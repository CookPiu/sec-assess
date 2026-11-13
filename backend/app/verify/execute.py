"""动态验证执行（DESIGN.md 5.3）：启动工程副本、准备测试账号、逐条执行用例并保存证据。

工程进程退出或不再响应时重启副本后继续；某个用例导致进程退出时记为未命中。
停止信号在每个用例之间检查。
"""

from __future__ import annotations

import asyncio
import json
import shlex
from typing import Any

from app.core.db import session_factory
from app.models import Evidence, Finding
from app.models.enums import CATEGORY_LABELS, Severity, VerifyStatus
from app.pipeline.state import TaskContext
from app.project.pysource import ProjectIndex
from app.sandbox.deps import VENV_PYTHON
from app.sandbox.probe import replay_command, run_probe
from app.verify.accounts import (
    field_values,
    find_seed_accounts,
    registration_values,
)
from app.verify.cases import (
    AuthInfo,
    ProbeCase,
    build_cases,
    evaluate,
    hardcoded_secret_values,
    marker,
)

START_TIMEOUT_S = 20
MAX_LOGGED = 30
WORK_APP = "/work/app"
APP_LOG = "/work/app.log"
APP_PID = "/work/app.pid"
MISS = "响应中未出现命中特征"

KILL_SCRIPT = f"""
import os, signal
me = os.getpid()
for name in os.listdir("/proc"):
    if not name.isdigit():
        continue
    pid = int(name)
    if pid == me:
        continue
    try:
        cmd = open(f"/proc/{{pid}}/cmdline", "rb").read().replace(b"\\0", b" ").decode("utf-8", "replace")
    except OSError:
        continue
    if {VENV_PYTHON!r} in cmd and "/opt/probe/runner.py" not in cmd:
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
"""


def entry_command(facts: dict[str, Any]) -> tuple[str, int] | None:
    """按侦察得到的启动方式拼出启动命令，返回（shell 命令，端口）。"""
    entry = facts.get("entry") or {}
    kind = entry.get("kind")
    port = int(entry.get("port") or 5000)
    if kind == "run":
        source = shlex.quote(str(entry.get("file") or "app.py"))
        command = f"exec {shlex.quote(VENV_PYTHON)} {source}"
    elif kind in ("factory", "app"):
        spec = str(entry.get("app") or "").removesuffix("()")
        command = (
            f"exec {shlex.quote(VENV_PYTHON)} -m flask --app {shlex.quote(spec)} "
            f"run --host 127.0.0.1 --port {port}"
        )
    else:
        return None
    script = (
        f"rm -f {APP_LOG} {APP_PID}; echo $$ > {APP_PID}; "
        f"{command} > {APP_LOG} 2>&1"
    )
    return script, port


async def _read_log(ctx: TaskContext) -> str:
    result = await asyncio.to_thread(
        ctx.sandbox.exec, ctx.task_id, ["sh", "-c", f"tail -c 4000 {APP_LOG} 2>/dev/null"], timeout=10
    )
    return (result.stdout or result.stderr).strip()


async def _stop_app(ctx: TaskContext) -> None:
    try:
        await asyncio.to_thread(ctx.sandbox.exec, ctx.task_id, [VENV_PYTHON, "-c", KILL_SCRIPT], timeout=15)
    except Exception:
        pass


async def _start_app(ctx: TaskContext, facts: dict[str, Any]) -> tuple[bool, int]:
    built = entry_command(facts)
    if built is None:
        await ctx.log("启动方式无法确定，跳过动态验证", "warn")
        return False, 5000
    script, port = built
    await _stop_app(ctx)
    try:
        await asyncio.to_thread(ctx.sandbox.exec_detached, ctx.task_id, ["sh", "-c", script], workdir=WORK_APP)
    except Exception as exc:
        await ctx.log(f"工程启动失败：{exc}", "warn")
        return False, port
    await ctx.log(f"按 {facts['entry'].get('kind')} 方式启动工程副本，端口 {port}")
    deadline = asyncio.get_running_loop().time() + START_TIMEOUT_S
    while asyncio.get_running_loop().time() < deadline:
        ctx.check_stop()
        probe = await _probe(ctx, {"port": port, "method": "GET", "path": "/", "timeout_s": 2})
        if probe.ok:
            await ctx.log(f"工程已启动：GET / 返回 {probe.status}")
            return True, port
        if not probe.error or "连接失败" not in probe.error:
            await ctx.log(f"无法执行容器内探针：{probe.error}", "warn")
            return False, port
        await asyncio.sleep(0.5)
    output = await _read_log(ctx)
    await ctx.log(f"工程在 {START_TIMEOUT_S} 秒内未启动，跳过动态验证", "warn")
    if output:
        await ctx.log(f"启动输出：{output[-1500:]}", "warn")
    return False, port


async def _probe(ctx: TaskContext, case: dict[str, Any]):
    timeout = min(max(ctx.runtime.probe_timeout_s, 3), 60)
    return await asyncio.to_thread(run_probe, ctx.sandbox, ctx.task_id, case, timeout=timeout)


async def _ensure_alive(ctx: TaskContext, facts: dict[str, Any], port: int) -> bool:
    probe = await _probe(ctx, {"port": port, "method": "GET", "path": "/", "timeout_s": 2})
    if probe.ok:
        return True
    if not probe.error or "连接失败" not in probe.error:
        return False
    await ctx.log("工程进程已退出，重启副本后继续", "warn")
    started, _ = await _start_app(ctx, facts)
    return started


def _json_body(text: str) -> dict[str, Any] | None:
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return None
    return data if isinstance(data, dict) else None


def _find_value(data: Any, keys: set[str]) -> Any:
    if isinstance(data, dict):
        for key, value in data.items():
            if key.lower() in keys and isinstance(value, (str, int)):
                return value
        for value in data.values():
            found = _find_value(value, keys)
            if found is not None:
                return found
    elif isinstance(data, list):
        for value in data:
            found = _find_value(value, keys)
            if found is not None:
                return found
    return None


def _cookie_header(set_cookie: list[str]) -> str | None:
    pairs = [item.split(";", 1)[0].strip() for item in set_cookie if item.strip()]
    return "; ".join(pairs) if pairs else None


def _session_headers(result) -> dict[str, str] | None:
    headers: dict[str, str] = {}
    if result.set_cookie:
        cookie = _cookie_header(result.set_cookie)
        if cookie:
            headers["Cookie"] = cookie
    payload = _json_body(result.body)
    if payload is not None:
        token = _find_value(payload, {"token", "access_token", "jwt", "id_token"})
        if isinstance(token, str) and token:
            headers["Authorization"] = f"Bearer {token}"
    return headers or None


def _session_user_id(result) -> int | None:
    payload = _json_body(result.body)
    if payload is None:
        return None
    value = _find_value(payload, {"id", "user_id", "uid"})
    return int(value) if isinstance(value, int) or (isinstance(value, str) and value.isdigit()) else None


def _auth_body(content: str, data: dict[str, str]) -> dict[str, Any]:
    return {"kind": "json" if content == "json" else "form", "data": data}


async def _login(
    ctx: TaskContext, facts: dict[str, Any], port: int, username: str, password: str
) -> dict[str, Any] | None:
    spec = (facts.get("auth") or {}).get("login")
    if not spec:
        return None
    fields = spec.get("fields") or ["username", "password"]
    data = field_values(fields, username=username, password=password, marker="login")
    result = await _probe(
        ctx,
        {
            "port": port,
            "method": spec.get("method") or "POST",
            "path": spec["path"],
            "body": _auth_body(spec.get("content") or "form", data),
            "timeout_s": 8,
        },
    )
    if not result.ok or result.status is None or not 200 <= result.status < 300:
        return None
    headers = _session_headers(result)
    if headers is None:
        return None
    return {"headers": headers, "user_id": _session_user_id(result)}


async def _register(
    ctx: TaskContext, facts: dict[str, Any], port: int, marker: str
) -> dict[str, Any] | None:
    spec = (facts.get("auth") or {}).get("register")
    if not spec:
        return None
    username, password, data = registration_values(spec.get("fields") or [], marker)
    result = await _probe(
        ctx,
        {
            "port": port,
            "method": spec.get("method") or "POST",
            "path": spec["path"],
            "body": _auth_body(spec.get("content") or "form", data),
            "timeout_s": 8,
        },
    )
    if not result.ok or result.status is None or not 200 <= result.status < 300:
        return None
    session = await _login(ctx, facts, port, username, password)
    if session is None:
        return None
    session["id"] = session.get("user_id") or _session_user_id(result)
    session["marker"] = marker
    return session


async def _prepare_auth(
    ctx: TaskContext, facts: dict[str, Any], port: int, index: ProjectIndex
) -> AuthInfo:
    info = AuthInfo()
    seeds = find_seed_accounts(index)
    for account in seeds:
        session = await _login(ctx, facts, port, account.username, account.password)
        if session is not None:
            info.admin = session["headers"]
            await ctx.log(f"使用源码中的测试账号 {account.username} 登录成功")
            break
    if not seeds:
        await ctx.log("源码中未识别到测试账号，管理类接口无法验证", "warn")

    register = (facts.get("auth") or {}).get("register")
    if register:
        first = await _register(ctx, facts, port, marker="a" + marker().lower())
        second = await _register(ctx, facts, port, marker="b" + marker().lower())
        if first is not None and second is not None:
            info.user = first["headers"]
            info.peer_id = second.get("id")
            info.peer_marker = second["marker"]
            await ctx.log("已通过注册接口准备两个测试账号")
        else:
            await ctx.log("测试账号注册失败，越权与缺失鉴权候选保持疑似", "warn")
    return info


async def _save_evidence(
    case: ProbeCase, request: dict[str, Any], result, matched: str | None
) -> None:
    hit = matched is not None
    async with session_factory()() as session:
        finding = await session.get(Finding, case.finding_id)
        if finding is None:
            return
        if hit:
            finding.status = VerifyStatus.VERIFIED
        elif finding.severity in (Severity.CRITICAL, Severity.HIGH):
            finding.severity = Severity.MEDIUM
        session.add(
            Evidence(
                finding_id=case.finding_id,
                case={**request, "replay": replay_command(request)},
                request_raw=result.request_raw,
                response_raw=result.response_raw,
                matched=matched or (result.error or MISS),
                hit=hit,
            )
        )
        await session.commit()


async def run_verification(
    ctx: TaskContext,
    index: ProjectIndex,
    findings: list[dict[str, Any]],
    facts: dict[str, Any],
) -> None:
    copy = await asyncio.to_thread(ctx.sandbox.copy_source, ctx.task_id)
    if not copy.ok:
        await ctx.log(f"复制工程副本失败：{copy.stderr or copy.stdout}", "warn")
        return
    started, port = await _start_app(ctx, facts)
    if not started:
        return
    try:
        secrets = hardcoded_secret_values(index)
        auth = await _prepare_auth(ctx, facts, port, index)
        cases, skipped = build_cases(
            findings, _steps_of(findings), index, facts, auth, secrets
        )
        for finding, reason in skipped:
            await ctx.log(f"{finding['code']} 跳过动态验证：{reason}", "warn")
        if not cases:
            await ctx.log("没有可执行的无害验证用例，候选漏洞保持疑似", "warn")
            return

        hits = misses = 0
        for number, case in enumerate(cases, 1):
            ctx.check_stop()
            if not await _ensure_alive(ctx, facts, port):
                remaining = len(cases) - number + 1
                await ctx.log(f"工程无法恢复运行，其余 {remaining} 条用例未执行，保持疑似", "warn")
                break
            matched: str | None = None
            result = None
            chosen = case.requests[0]
            for request in case.requests:
                chosen = request
                result = await _probe(ctx, request)
                matched = evaluate(case.rules, result)
                if matched:
                    break
                if result.error and ("连接失败" in result.error or result.timed_out):
                    break
            if result is not None:
                await _save_evidence(case, chosen, result, matched)
            if matched:
                hits += 1
                if hits <= MAX_LOGGED:
                    await ctx.log(
                        f"{case.code} 验证通过：{CATEGORY_LABELS[case.category]}"
                        f"（{case.description}，命中 {matched}）"
                    )
            else:
                misses += 1
                reason = (result.error if result is not None and result.error else MISS)
                if misses <= MAX_LOGGED:
                    await ctx.log(f"{case.code} 未命中：{CATEGORY_LABELS[case.category]}（{reason}）", "warn")

        total = hits + misses
        await ctx.log(
            f"动态验证完成：执行 {total} 条用例，验证通过 {hits} 条，未命中 {misses} 条；"
            f"另有 {len(skipped)} 条候选用例无法执行，保持疑似"
        )
        if hits > MAX_LOGGED:
            await ctx.log(f"其余 {hits - MAX_LOGGED} 条命中记录见漏洞详情")
    finally:
        await _stop_app(ctx)


def _steps_of(findings: list[dict[str, Any]]) -> dict[int, list[dict[str, Any]]]:
    return {finding["id"]: finding.get("steps") or [] for finding in findings}
