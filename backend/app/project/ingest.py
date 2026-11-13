"""项目接入：公开 HTTPS Git 仓库浅克隆、zip 源码包安全解压（FR-001）。

两种来源都落到 data/projects/{project_id}/src。仓库与解压后都不超过 200 MB，zip 本身不超过 50 MB。
这里的函数都是同步的，异步代码通过 asyncio.to_thread 调用。
"""

from __future__ import annotations

import ipaddress
import os
import shutil
import stat
import subprocess
import tempfile
import time
import zipfile
from pathlib import Path, PurePosixPath
from typing import BinaryIO
from urllib.parse import urlsplit

MAX_ZIP_BYTES = 50 * 1024 * 1024
MAX_SOURCE_BYTES = 200 * 1024 * 1024
MAX_ZIP_ENTRIES = 20_000
CLONE_TIMEOUT_S = 180


class IngestError(ValueError):
    """来源不合法或超出限制，消息直接展示给用户。"""


def project_source_dir(data_dir: Path, project_id: int) -> Path:
    return data_dir / "projects" / str(project_id) / "src"


def dir_size(path: Path) -> int:
    total = 0
    for root, _dirs, files in os.walk(path):
        for name in files:
            try:
                total += os.lstat(os.path.join(root, name)).st_size
            except OSError:
                pass
    return total


def remove_tree(path: Path) -> None:
    """删除目录；Git 对象文件在 Windows 上是只读的，删除前先去掉只读属性。"""

    def _on_error(func, target, _exc) -> None:
        os.chmod(target, stat.S_IWRITE)
        func(target)

    if path.exists():
        shutil.rmtree(path, onexc=_on_error)


def repo_name_from_url(url: str) -> str:
    name = urlsplit(url).path.rstrip("/").rsplit("/", 1)[-1]
    return name.removesuffix(".git") or "repository"


# ---------- Git ----------


def validate_git_url(url: str) -> str:
    url = url.strip()
    parts = urlsplit(url)
    if parts.scheme != "https":
        raise IngestError("只接受 https:// 开头的公开 Git 地址")
    host = parts.hostname
    if not host:
        raise IngestError("Git 地址缺少主机名")
    if parts.username or parts.password:
        raise IngestError("Git 地址不能包含账号或令牌")
    if parts.query or parts.fragment:
        raise IngestError("Git 地址不能带查询参数")
    if host == "localhost" or host.endswith(".localhost"):
        raise IngestError("不接受本机地址")
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        addr = None
    if addr is not None and not addr.is_global:
        raise IngestError("不接受内网或本机 IP 地址")
    return url


def clone_repo(url: str, dest: Path, *, timeout: int = CLONE_TIMEOUT_S, max_bytes: int = MAX_SOURCE_BYTES) -> None:
    """浅克隆到 dest，禁用 hooks、子模块、LFS 与本机凭据，克隆后删除 .git 目录。

    先克隆到同级的临时目录，成功后再改名为 dest，中途失败或被打断时不会留下半个仓库。
    """
    url = validate_git_url(url)
    work = dest.with_name(dest.name + ".partial")
    remove_tree(work)
    dest.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as empty, tempfile.TemporaryFile() as err:
        cmd = [
            "git",
            "-c", "protocol.allow=never",
            "-c", "protocol.https.allow=always",
            "-c", f"core.hooksPath={empty}",
            "-c", "core.symlinks=false",
            "-c", "credential.helper=",
            "-c", "submodule.recurse=false",
            "-c", "filter.lfs.smudge=",
            "-c", "filter.lfs.process=",
            "-c", "filter.lfs.required=false",
            "clone", "--depth", "1", "--single-branch", "--no-tags",
            f"--template={empty}",
            "--", url, str(work),
        ]  # fmt: skip
        env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1", "GCM_INTERACTIVE": "never"}
        try:
            proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=err, env=env)
        except FileNotFoundError as exc:
            raise IngestError("本机未安装 git") from exc

        deadline = time.monotonic() + timeout
        try:
            while proc.poll() is None:
                if time.monotonic() > deadline:
                    raise IngestError(f"Git 克隆超时（{timeout} 秒）")
                if work.exists() and dir_size(work) > max_bytes:
                    raise IngestError(f"仓库超过 {max_bytes // 1024 // 1024} MB 上限")
                time.sleep(1)
            if proc.returncode != 0:
                err.seek(0)
                lines = err.read().decode("utf-8", errors="replace").strip().splitlines()
                raise IngestError(f"Git 克隆失败：{lines[-1] if lines else f'退出码 {proc.returncode}'}")
            remove_tree(work / ".git")
            if dir_size(work) > max_bytes:
                raise IngestError(f"仓库超过 {max_bytes // 1024 // 1024} MB 上限")
            remove_tree(dest)
            work.rename(dest)
        except BaseException:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
            remove_tree(work)
            raise


# ---------- zip ----------


def _safe_relpath(name: str) -> PurePosixPath | None:
    """把条目名规范成相对路径；绝对路径和 .. 直接拒绝，空路径返回 None。"""
    name = name.replace("\\", "/")
    if name.startswith("/") or (len(name) > 1 and name[1] == ":"):
        raise IngestError(f"压缩包含绝对路径条目：{name}")
    parts = [p for p in name.split("/") if p not in ("", ".")]
    if ".." in parts:
        raise IngestError(f"压缩包含路径穿越条目：{name}")
    return PurePosixPath(*parts) if parts else None


def extract_zip(
    source: Path | BinaryIO,
    dest: Path,
    *,
    max_zip_bytes: int = MAX_ZIP_BYTES,
    max_bytes: int = MAX_SOURCE_BYTES,
    max_entries: int = MAX_ZIP_ENTRIES,
) -> None:
    """校验后解压到 dest。全部文件在同一个顶层目录下时去掉这一层，忽略 __MACOSX。失败时 dest 不保留。"""
    if isinstance(source, Path):
        size = source.stat().st_size
    else:
        source.seek(0, os.SEEK_END)
        size = source.tell()
        source.seek(0)
    if size > max_zip_bytes:
        raise IngestError(f"压缩包超过 {max_zip_bytes // 1024 // 1024} MB 上限")
    try:
        zf = zipfile.ZipFile(source)
    except zipfile.BadZipFile as exc:
        raise IngestError("不是有效的 zip 文件") from exc

    with zf:
        infos = zf.infolist()
        if len(infos) > max_entries:
            raise IngestError(f"压缩包条目超过 {max_entries} 个")
        members: list[tuple[zipfile.ZipInfo, PurePosixPath]] = []
        declared = 0
        for info in infos:
            if stat.S_ISLNK(info.external_attr >> 16):
                raise IngestError(f"压缩包含符号链接：{info.filename}")
            rel = _safe_relpath(info.filename)
            if rel is None or info.is_dir() or rel.parts[0] == "__MACOSX":
                continue
            declared += info.file_size
            if declared > max_bytes:
                raise IngestError(f"解压后超过 {max_bytes // 1024 // 1024} MB 上限")
            members.append((info, rel))
        if not members:
            raise IngestError("压缩包里没有文件")

        tops = {rel.parts[0] for _, rel in members}
        strip = len(tops) == 1 and all(len(rel.parts) > 1 for _, rel in members)

        remove_tree(dest)
        dest.mkdir(parents=True)
        written = 0
        try:
            for info, rel in members:
                target = dest.joinpath(*(rel.parts[1:] if strip else rel.parts))
                target.parent.mkdir(parents=True, exist_ok=True)
                # 按实际写出的字节计数，不信任条目头里声明的大小
                with zf.open(info) as src, open(target, "wb") as out:
                    while chunk := src.read(1 << 20):
                        written += len(chunk)
                        if written > max_bytes:
                            raise IngestError(f"解压后超过 {max_bytes // 1024 // 1024} MB 上限")
                        out.write(chunk)
        except (OSError, zipfile.BadZipFile, NotImplementedError) as exc:
            remove_tree(dest)
            raise IngestError(f"解压失败：{exc}") from exc
        except BaseException:
            remove_tree(dest)
            raise
