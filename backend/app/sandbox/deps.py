"""依赖准备（DESIGN.md 第 4 节、D-012）：宿主机只下载预编译 wheel，容器内离线安装到任务虚拟环境。

宿主机用后端虚拟环境里的 pip 执行 `pip download --only-binary=:all:`，不运行任何构建脚本。
wheel 按目标平台缓存在 data/wheelhouse/<平台>/，整个 wheelhouse 只读挂到容器的 /wheels。
容器内用 --system-site-packages 建 /work/venv：拿不到 wheel 的包回退到镜像预装的版本，仍缺失的记入结果。
准备失败不影响任务继续，后续动态验证据结果决定是否跳过。
"""

from __future__ import annotations

import asyncio
import json
import re
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from app.core.config import get_settings
from app.sandbox.manager import SandboxError, SandboxManager

if TYPE_CHECKING:
    from app.pipeline.state import TaskContext

VENV = "/work/venv"
VENV_PYTHON = f"{VENV}/bin/python"
WHEELS_MOUNT = "/wheels"
DOWNLOAD_TIMEOUT_S = 300
INSTALL_TIMEOUT_S = 300
MIN_GLIBC_MINOR = 17  # manylinux2014 对应 glibc 2.17

_NAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")
_CLAUSE = r"\s*(?:===|==|!=|~=|<=|>=|<|>)\s*[A-Za-z0-9.*+!_-]+\s*"
_SPEC = re.compile(rf"^{_CLAUSE}(?:,{_CLAUSE})*$")
# 出现这些字样说明连不上索引，不再逐个重试
_NETWORK_ERROR = re.compile(
    r"NewConnectionError|ConnectTimeout|ReadTimeout|Max retries exceeded|ProxyError|SSLError|"
    r"Name or service not known|getaddrinfo failed|Temporary failure in name resolution"
)

_PROBE = (
    "import json,platform,sys;"
    "print(json.dumps({'machine':platform.machine(),'libc':platform.libc_ver(),"
    "'python':'%d.%d'%sys.version_info[:2]}))"
)
_CHECK = """
import json, sys
from importlib import metadata
found = {}
for name in sys.argv[1:]:
    try:
        dist = metadata.distribution(name)
    except metadata.PackageNotFoundError:
        found[name] = None
    else:
        found[name] = {"version": dist.version, "location": str(dist.locate_file(""))}
print(json.dumps(found))
"""


class DepsError(RuntimeError):
    pass


@dataclass(frozen=True)
class Target:
    """沙箱镜像的解释器与平台，决定下载哪些 wheel。"""

    machine: str
    glibc_minor: int
    python: str

    @property
    def abi(self) -> str:
        return "cp" + self.python.replace(".", "")

    @property
    def tag(self) -> str:
        return f"{self.abi}-manylinux_2_{self.glibc_minor}_{self.machine}"

    def platforms(self) -> list[str]:
        plats = [f"manylinux_2_{m}_{self.machine}" for m in range(self.glibc_minor, MIN_GLIBC_MINOR - 1, -1)]
        # pip 会把 manylinux2014 展开到 manylinux2010、manylinux1
        return [*plats, f"manylinux2014_{self.machine}"]


def wheelhouse_dir() -> Path:
    return get_settings().resolved_data_dir / "wheelhouse"


def requirement_specs(dependencies: list[dict[str, Any]]) -> tuple[list[str], list[str]]:
    """把侦察得到的 PyPI 运行依赖转成 pip 需求串；包名不合规的跳过，版本约束无法识别的去掉约束。"""
    reqs: dict[str, str] = {}
    notes: list[str] = []
    for dep in dependencies:
        if dep["ecosystem"] != "pypi" or dep.get("dev"):
            continue
        name, spec = dep["name"], (dep.get("spec") or "").strip()
        if not _NAME.match(name):
            notes.append(f"跳过无法识别的依赖名：{name[:60]}")
            continue
        if spec and not _SPEC.match(spec):
            notes.append(f"{name} 的版本约束 {spec[:40]} 无法识别，按最新版本准备")
            spec = ""
        reqs.setdefault(name, f"{name}{spec}")
    return list(reqs.values()), notes


def requirement_name(req: str) -> str:
    return re.split(r"[<>=!~\s]", req, maxsplit=1)[0]


def _last_error(output: str) -> str:
    lines = [x.strip() for x in output.splitlines() if x.strip()]
    errors = [x for x in lines if x.startswith("ERROR")]
    return (errors or lines or ["未知错误"])[-1][:300]


def _run(cmd: list[str], timeout: float, should_stop: Callable[[], bool]) -> tuple[int, str]:
    """运行宿主机命令，超时或任务被停止时结束进程。"""
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace"
    )
    deadline = time.monotonic() + timeout
    while True:
        try:
            output, _ = proc.communicate(timeout=1)
            return proc.returncode, output
        except subprocess.TimeoutExpired:
            if should_stop() or time.monotonic() > deadline:
                proc.kill()
                proc.communicate()
                return -1, "ERROR: 任务已停止" if should_stop() else f"ERROR: 超过 {timeout:.0f} 秒未完成"


def pip_download_cmd(reqs: list[str], dest: Path, target: Target, index_url: str) -> list[str]:
    cmd = [
        sys.executable, "-m", "pip", "download",
        "--only-binary=:all:", "--dest", str(dest), "--index-url", index_url,
        "--python-version", target.python, "--implementation", "cp", "--abi", target.abi,
        "--disable-pip-version-check", "--no-input", "--progress-bar", "off", "--timeout", "15", "--retries", "1",
    ]  # fmt: skip
    for plat in target.platforms():
        cmd += ["--platform", plat]
    return [*cmd, "--", *reqs]


def download_wheels(
    reqs: list[str], dest: Path, target: Target, index_url: str, should_stop: Callable[[], bool]
) -> tuple[list[str], dict[str, str]]:
    """先整批下载；失败时逐个下载找出拿不到 wheel 的包。返回（下载成功的需求，失败需求 → 原因）。"""
    dest.mkdir(parents=True, exist_ok=True)
    if not reqs:
        return [], {}
    code, output = _run(pip_download_cmd(reqs, dest, target, index_url), DOWNLOAD_TIMEOUT_S, should_stop)
    if code == 0:
        return list(reqs), {}
    if should_stop() or _NETWORK_ERROR.search(output):
        reason = "无法连接 PyPI 索引" if _NETWORK_ERROR.search(output) else _last_error(output)
        return [], dict.fromkeys(reqs, reason)
    ok: list[str] = []
    failed: dict[str, str] = {}
    for req in reqs:
        code, output = _run(pip_download_cmd([req], dest, target, index_url), DOWNLOAD_TIMEOUT_S, should_stop)
        if code == 0:
            ok.append(req)
        else:
            failed[req] = _last_error(output)
    return ok, failed


def probe_target(sandbox: SandboxManager, task_id: int) -> Target:
    result = sandbox.exec(task_id, ["python", "-c", _PROBE], timeout=30)
    if not result.ok:
        raise DepsError(f"读取沙箱解释器信息失败：{_last_error(result.stderr or result.stdout)}")
    info = json.loads(result.stdout)
    libc, version = info["libc"]
    if libc != "glibc":
        raise DepsError(f"沙箱镜像的 C 库是 {libc or '未知'}，只支持 glibc")
    return Target(machine=info["machine"], glibc_minor=int(version.split(".")[1]), python=info["python"])


def install_in_container(sandbox: SandboxManager, task_id: int, reqs: list[str], find_links: str) -> dict[str, str]:
    """建任务虚拟环境并离线安装，返回安装失败的需求 → 原因。"""
    venv = sandbox.exec(task_id, ["python", "-m", "venv", "--without-pip", "--system-site-packages", VENV], timeout=120)
    if not venv.ok:
        raise DepsError(f"创建虚拟环境失败：{_last_error(venv.stderr or venv.stdout)}")
    if not reqs:
        return {}
    # wheel 解包用的临时目录放在任务卷里，/tmp 是容量很小的 tmpfs
    sandbox.exec(task_id, ["mkdir", "-p", "/work/tmp"], timeout=10)
    env = {"TMPDIR": "/work/tmp"}
    base = [VENV_PYTHON, "-m", "pip", "install", "--no-index", "--find-links", find_links,
            "--disable-pip-version-check", "--no-input", "--progress-bar", "off"]  # fmt: skip
    batch = sandbox.exec(task_id, [*base, "--", *reqs], timeout=INSTALL_TIMEOUT_S, env=env)
    if batch.ok:
        return {}
    failed: dict[str, str] = {}
    for req in reqs:
        one = sandbox.exec(task_id, [*base, "--", req], timeout=INSTALL_TIMEOUT_S, env=env)
        if not one.ok:
            failed[req] = _last_error(one.stderr or one.stdout)
    return failed


def check_installed(sandbox: SandboxManager, task_id: int, names: list[str]) -> dict[str, dict[str, str] | None]:
    result = sandbox.exec(task_id, [VENV_PYTHON, "-c", _CHECK, *names], timeout=60)
    if not result.ok:
        raise DepsError(f"检查已安装依赖失败：{_last_error(result.stderr or result.stdout)}")
    return json.loads(result.stdout)


def summarize(
    reqs: list[str], download_failed: dict[str, str], install_failed: dict[str, str],
    installed: dict[str, dict[str, str] | None], target: Target,
) -> dict[str, Any]:  # fmt: skip
    from_wheels: list[dict[str, str]] = []
    preinstalled: list[dict[str, str]] = []
    missing: list[dict[str, str]] = []
    for req in reqs:
        name = requirement_name(req)
        info = installed.get(name)
        if info is None:
            reason = download_failed.get(req) or install_failed.get(req) or "安装后仍未找到"
            missing.append({"name": name, "requirement": req, "reason": reason})
        elif info["location"].startswith(VENV):
            from_wheels.append({"name": name, "version": info["version"]})
        else:
            # 下载或安装失败、退回预装版本的，版本未必满足工程要求
            fallback = req in download_failed or req in install_failed
            preinstalled.append({"name": name, "version": info["version"], "requirement": req, "fallback": fallback})
    return {
        "ok": not missing,
        "target": target.tag,
        "venv": VENV,
        "requirements": reqs,
        "installed": from_wheels,
        "preinstalled": preinstalled,
        "missing": missing,
    }


async def prepare_dependencies(ctx: TaskContext, dependencies: list[dict[str, Any]]) -> dict[str, Any]:
    """在侦察阶段末尾调用；结果写入任务的 deps_result 并返回。"""
    reqs, notes = requirement_specs(dependencies)
    for note in notes:
        await ctx.log(note, "warn")
    try:
        target = await asyncio.to_thread(probe_target, ctx.sandbox, ctx.task_id)
        download_failed: dict[str, str] = {}
        downloaded: list[str] = []
        if reqs:
            index_url = ctx.runtime.pypi_index_url
            await ctx.log(f"下载预编译 wheel：{len(reqs)} 项依赖，目标平台 {target.tag}，索引 {index_url}")
            downloaded, download_failed = await asyncio.to_thread(
                download_wheels, reqs, wheelhouse_dir() / target.tag, target, index_url, ctx.stop_event.is_set
            )
            ctx.check_stop()
            for req, reason in download_failed.items():
                await ctx.log(f"{req} 没有可用的预编译 wheel：{reason}", "warn")
        install_failed = await asyncio.to_thread(
            install_in_container, ctx.sandbox, ctx.task_id, downloaded, f"{WHEELS_MOUNT}/{target.tag}"
        )
        ctx.check_stop()
        names = [requirement_name(r) for r in reqs]
        installed = await asyncio.to_thread(check_installed, ctx.sandbox, ctx.task_id, names) if names else {}
    except (DepsError, SandboxError, OSError, ValueError, KeyError) as exc:
        result: dict[str, Any] = {"ok": False, "error": str(exc), "requirements": reqs}
        await ctx.update_task(deps_result=result)
        await ctx.log(f"依赖准备失败：{exc}，动态验证将跳过", "warn")
        return result

    result = summarize(reqs, download_failed, install_failed, installed, target)
    await ctx.update_task(deps_result=result)
    parts = [f"从 wheel 安装 {len(result['installed'])} 项", f"使用镜像预装 {len(result['preinstalled'])} 项"]
    if result["missing"]:
        parts.append(f"缺失 {len(result['missing'])} 项")
    await ctx.log(f"依赖准备完成：{'，'.join(parts)}；虚拟环境 {VENV}")
    for item in result["preinstalled"]:
        if item["fallback"]:
            await ctx.log(f"{item['requirement']} 改用镜像预装的 {item['version']}，版本可能与工程要求不一致", "warn")
    if result["missing"]:
        missing = "、".join(m["name"] for m in result["missing"])
        await ctx.log(f"缺失依赖：{missing}，动态验证将跳过", "warn")
    return result
