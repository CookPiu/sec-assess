"""真实 Docker 下的流水线：容器随任务创建，完成或停止后容器与任务卷都被删除。"""

from __future__ import annotations

import asyncio

import pytest
from fastapi.testclient import TestClient

from app.models.enums import Stage
from app.pipeline import graph
from app.pipeline.runner import runner
from app.sandbox.manager import sandbox_manager

from tests.test_tasks_api import create_zip_task, finished, wait_for

pytestmark = pytest.mark.docker


@pytest.fixture
def real_sandbox(monkeypatch, client: TestClient):
    if not sandbox_manager.ping():
        pytest.skip("Docker 未启动")
    monkeypatch.setattr(runner, "manager", sandbox_manager)
    return sandbox_manager


def test_container_lifecycle_follows_task(client: TestClient, login, real_sandbox, monkeypatch) -> None:
    seen: dict[str, bool] = {}

    async def probe(ctx) -> None:
        seen["exists"] = await asyncio.to_thread(real_sandbox.exists, ctx.task_id)
        result = await asyncio.to_thread(real_sandbox.exec, ctx.task_id, ["ls", "/src"])
        seen["src_listed"] = "app.py" in result.stdout

    monkeypatch.setitem(graph.AGENTS, Stage.CODE_AUDIT, probe)
    headers = login("engineer")
    task = create_zip_task(client, headers).json()
    body = wait_for(client, headers, task["id"], finished, timeout=60)
    assert body["status"] == "completed", body
    assert seen == {"exists": True, "src_listed": True}
    assert not real_sandbox.exists(task["id"])


def test_stop_destroys_container(client: TestClient, login, real_sandbox, monkeypatch) -> None:
    async def slow(_ctx) -> None:
        await asyncio.sleep(60)

    monkeypatch.setitem(graph.AGENTS, Stage.CODE_AUDIT, slow)
    headers = login("engineer")
    task = create_zip_task(client, headers).json()
    wait_for(client, headers, task["id"], lambda b: b["current_stage"] == "code_audit", timeout=60)
    assert real_sandbox.exists(task["id"])

    resp = client.post(f"/api/tasks/{task['id']}/stop", headers=headers)
    assert resp.json()["status"] == "stopped"
    assert not real_sandbox.exists(task["id"])
