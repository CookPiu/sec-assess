"""宿主机侧的探针调用（D-014）：把用例编码后交给容器内脚本，解析回传的报文与文件检查结果。

容器没有网络，宿主机不能直连容器端口，因此所有请求都由 `sandbox-images/probe/runner.py`
在容器内发往 127.0.0.1。
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.core.config import PROJECT_ROOT
from app.sandbox.deps import VENV_PYTHON
from app.sandbox.manager import SandboxManager

PROBE_DIR = PROJECT_ROOT / "sandbox-images" / "probe"
PROBE_RUNNER = "/opt/probe/runner.py"
PROBE_TIMEOUT_MARGIN_S = 5


@dataclass
class ProbeResult:
    ok: bool
    error: str | None = None
    status: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    set_cookie: list[str] = field(default_factory=list)
    body: str = ""
    request_raw: str = ""
    response_raw: str = ""
    files_exist: dict[str, bool] = field(default_factory=dict)
    found: list[str] = field(default_factory=list)
    timed_out: bool = False

    @property
    def connected(self) -> bool:
        """请求是否到达服务：连接失败与超时都不算。"""
        return self.ok or not (self.error or "").startswith("连接失败")


def encode_case(case: dict[str, Any]) -> str:
    return base64.b64encode(json.dumps(case, ensure_ascii=False).encode("utf-8")).decode("ascii")


def replay_command(case: dict[str, Any]) -> list[str]:
    return [VENV_PYTHON, PROBE_RUNNER, encode_case(case)]


def run_probe(
    sandbox: SandboxManager, task_id: int, case: dict[str, Any], *, timeout: int = 10
) -> ProbeResult:
    """在容器内执行一条用例。容器内脚本的 HTTP 超时由用例的 timeout_s 控制。"""
    result = sandbox.exec(
        task_id, replay_command(case), timeout=timeout + PROBE_TIMEOUT_MARGIN_S, workdir="/work"
    )
    if result.timed_out:
        return ProbeResult(ok=False, error="探针执行超时", timed_out=True)
    stdout = result.stdout.strip()
    if not stdout:
        reason = (result.stderr or result.stdout).strip()[:300] or "没有输出"
        return ProbeResult(ok=False, error=f"探针没有返回结果：{reason}")
    try:
        data = json.loads(stdout.splitlines()[-1])
    except (ValueError, IndexError):
        return ProbeResult(ok=False, error=f"探针输出无法解析：{stdout[:300]}")
    if not isinstance(data, dict):
        return ProbeResult(ok=False, error="探针输出格式不正确")
    return ProbeResult(
        ok=bool(data.get("ok")),
        error=data.get("error"),
        status=data.get("status"),
        headers=data.get("headers") or {},
        set_cookie=data.get("set_cookie") or [],
        body=data.get("body") or "",
        request_raw=data.get("request_raw") or "",
        response_raw=data.get("response_raw") or "",
        files_exist=data.get("files_exist") or {},
        found=data.get("found") or [],
    )


def probe_dir_or_none() -> Path | None:
    return PROBE_DIR if PROBE_DIR.is_dir() else None
