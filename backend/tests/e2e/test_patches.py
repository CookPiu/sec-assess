"""US5 端到端检查（T047、SC-003）：两个靶场在真实沙箱里由真实大模型跑完，每条 Verified 漏洞都有行号、
污点轨迹（越权与敏感信息类除外）、命中证据和补丁，补丁全部通过 `git apply --check`。

需要 Docker Desktop、已构建的沙箱镜像、外网，以及仓库根目录 .env 中可用的大模型配置。
"""

from __future__ import annotations

import os
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest
from dotenv import dotenv_values
from fastapi.testclient import TestClient

from app.core.config import PROJECT_ROOT, get_settings
from app.core.llm import get_llm
from app.models import Project, Task
from app.models.enums import Category
from app.pipeline.runner import runner
from app.sandbox.manager import sandbox_manager
from app.core.db import session_factory

from tests.e2e.test_pipeline import run_assessment

pytestmark = [pytest.mark.docker, pytest.mark.network, pytest.mark.llm]

LLM_KEYS = ("LLM_API_KEY", "LLM_MODEL", "LLM_BASE_URL")
# 越权与敏感信息类由规则直接匹配，没有污点轨迹
NO_TRACE = {
    Category.IDOR,
    Category.MISSING_AUTH,
    Category.HARDCODED_SECRET,
    Category.DEBUG_MODE,
    Category.CONFIG_EXPOSURE,
    Category.WEAK_PASSWORD_STORAGE,
}


@pytest.fixture
def sandbox(monkeypatch, client: TestClient):
    if not sandbox_manager.ping():
        pytest.skip("Docker 未启动")
    monkeypatch.setattr(runner, "manager", sandbox_manager)
    return sandbox_manager


@pytest.fixture
def real_llm(app_env) -> Iterator[None]:
    """测试默认不读 .env；这里只把大模型配置从 .env 放进环境变量，用完恢复。"""
    values = dotenv_values(PROJECT_ROOT / ".env")
    if not values.get("LLM_API_KEY") or not values.get("LLM_MODEL"):
        pytest.skip(".env 中没有大模型配置")
    saved = {key: os.environ.get(key) for key in LLM_KEYS}
    for key in LLM_KEYS:
        if values.get(key):
            os.environ[key] = values[key]
    get_settings.cache_clear()
    get_llm.cache_clear()
    try:
        yield
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        get_settings.cache_clear()
        get_llm.cache_clear()


def source_root(run_async, app_env: Path, task_id: int) -> Path:
    async def _root() -> str:
        async with session_factory()() as session:
            task = await session.get(Task, task_id)
            project = await session.get(Project, task.project_id)
            return project.source_dir

    return app_env / run_async(_root)


@pytest.mark.parametrize("name", ["shop-admin", "user-center"])
def test_every_verified_finding_has_applicable_patch(
    client: TestClient, login, run_async, app_env, sandbox, real_llm, name: str
) -> None:
    headers = login("engineer")
    task_id = run_assessment(client, headers, name)
    root = source_root(run_async, app_env, task_id)

    findings = client.get(f"/api/tasks/{task_id}/findings", headers=headers).json()
    verified = [f for f in findings if f["status"] == "verified"]
    assert verified, findings
    for finding in verified:
        label = f"{finding['code']} {finding['category']}"
        detail = client.get(f"/api/findings/{finding['id']}", headers=headers).json()
        assert detail["file"] and detail["line"] > 0, label
        if finding["category"] not in NO_TRACE:
            assert detail["steps"], label
        assert any(ev["hit"] for ev in detail["evidence"]), label

        resp = client.get(f"/api/findings/{finding['id']}/patch", headers=headers)
        assert resp.status_code == 200, (label, resp.text)
        patch = resp.json()
        assert patch["patched"] is not None and patch["added"] + patch["removed"] > 0, label
        check = subprocess.run(
            ["git", "apply", "--check", "-"], cwd=root, input=patch["diff"].encode("utf-8"), capture_output=True
        )
        assert check.returncode == 0, (label, check.stderr.decode("utf-8", errors="replace"))

    messages = [entry["message"] for entry in client.get(f"/api/tasks/{task_id}/logs", headers=headers).json()]
    assert f"补丁生成完成：{len(verified)} 条已验证漏洞中 {len(verified)} 条生成补丁" in messages
