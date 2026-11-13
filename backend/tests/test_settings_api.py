"""沙箱与环境配置接口：查看、修改、校验与审计，以及修改后对新任务的效果（US6 验收 1、2）。"""

from __future__ import annotations

import asyncio

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete

import app.pipeline.runner as runner_module
from app.core.db import session_factory
from app.models import Setting
from app.models.enums import Stage
from app.pipeline import graph
from app.pipeline.runner import runner
from tests.test_tasks_api import FakeSandbox, create_zip_task, finished, stop_leftover_tasks, wait_for

IMAGE = {"tag": "sec-assess/python-flask:test", "size_mb": 512.0, "created": "2026-11-01T00:00:00Z"}


class ImageSandbox(FakeSandbox):
    def list_images(self, prefix: str = "sec-assess/") -> list[dict[str, object]]:
        return [IMAGE]


@pytest.fixture
def sandbox(monkeypatch, client: TestClient, run_async):
    fake = ImageSandbox()
    monkeypatch.setattr(runner, "manager", fake)
    yield fake
    stop_leftover_tasks(run_async)

    async def _reset() -> None:
        async with session_factory()() as session:
            await session.execute(delete(Setting))
            await session.commit()

    run_async(_reset)


def put(client: TestClient, headers, changes: dict):
    return client.put("/api/settings", headers=headers, json=changes)


def setting_audits(client: TestClient, headers) -> dict:
    return client.get("/api/audit-logs", headers=headers, params={"action": "setting_update"}).json()


def test_get_settings(client: TestClient, login, sandbox: ImageSandbox) -> None:
    headers = login("admin")
    body = client.get("/api/settings", headers=headers).json()
    assert body["values"] == body["defaults"]
    assert body["values"]["network_policy"] == "none"
    assert body["images"] == [IMAGE]
    assert body["docker_available"] is True
    assert body["llm_key_configured"] is False
    assert body["updated_at"] is None and body["updated_by"] is None

    sandbox.docker_ok = False
    body = client.get("/api/settings", headers=headers).json()
    assert body["images"] == [] and body["docker_available"] is False


def test_update_settings_writes_audit_log(client: TestClient, login, sandbox: ImageSandbox) -> None:
    headers = login("admin")
    before = setting_audits(client, headers)["total"]

    resp = put(client, headers, {"cpus": 2, "memory_mb": 2048, "llm_enabled": False, "pids": 256})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert (body["values"]["cpus"], body["values"]["memory_mb"], body["values"]["llm_enabled"]) == (2.0, 2048, False)
    assert body["updated_by"] == "admin" and body["updated_at"] is not None

    audits = setting_audits(client, headers)
    assert audits["total"] == before + 1
    latest = audits["items"][0]
    assert latest["username"] == "admin"
    assert latest["target_id"] == "cpus,llm_enabled,memory_mb"
    # 值没变的项（pids）不记入变更
    assert latest["detail"] == {"changes": {"cpus": [1.0, 2.0], "memory_mb": [1024, 2048], "llm_enabled": [True, False]}}

    # 提交相同的值不产生新记录
    assert put(client, headers, {"cpus": 2.0}).status_code == 200
    assert setting_audits(client, headers)["total"] == before + 1
    assert client.get("/api/settings", headers=headers).json()["values"]["cpus"] == 2.0


@pytest.mark.parametrize(
    ("changes", "detail"),
    [
        ({"network_policy": "bridge"}, "不能修改的配置项：网络隔离策略"),
        ({"debug": True}, "不能修改的配置项：debug"),
        ({"cpus": 0}, "CPU 核数必须大于 0"),
        ({"memory_mb": 100}, "内存上限不能小于 256"),
        ({"task_timeout_min": 500}, "单任务超时不能大于 240"),
        ({"probe_timeout_s": 1}, "单探针超时不能小于 3"),
        ({"pypi_index_url": "ftp://mirror.local/simple"}, "PyPI 地址必须是 http:// 或 https:// 开头的地址"),
        ({"sandbox_image": ""}, "沙箱镜像不能为空"),
        ({"llm_concurrency": "many"}, "大模型并发数的取值不合法"),
    ],
)
def test_update_settings_validation(client: TestClient, login, sandbox: ImageSandbox, changes, detail) -> None:
    headers = login("admin")
    resp = put(client, headers, changes)
    assert resp.status_code == 422
    assert resp.json()["detail"] == detail
    body = client.get("/api/settings", headers=headers).json()
    assert body["values"] == body["defaults"]


def test_sandbox_image_must_exist(client: TestClient, login, sandbox: ImageSandbox) -> None:
    headers = login("admin")
    assert put(client, headers, {"sandbox_image": IMAGE["tag"]}).json()["values"]["sandbox_image"] == IMAGE["tag"]

    sandbox.image_ok = False
    resp = put(client, headers, {"sandbox_image": "sec-assess/missing:1"})
    assert resp.status_code == 400 and resp.json()["detail"] == "本机没有镜像 sec-assess/missing:1"

    sandbox.docker_ok = False
    resp = put(client, headers, {"sandbox_image": "sec-assess/missing:1"})
    assert resp.status_code == 400 and resp.json()["detail"] == "Docker 未启动，无法确认沙箱镜像是否存在"
    assert client.get("/api/settings", headers=headers).json()["values"]["sandbox_image"] == IMAGE["tag"]


def test_lowered_timeout_fails_new_task(client: TestClient, login, sandbox: ImageSandbox, monkeypatch) -> None:
    """验收 1：调低单任务超时后，新任务超时即销毁容器并标记失败。"""

    async def slow(_ctx) -> None:
        await asyncio.sleep(30)

    monkeypatch.setitem(graph.AGENTS, Stage.CODE_AUDIT, slow)
    monkeypatch.setattr(runner_module, "SECONDS_PER_MINUTE", 2)
    assert put(client, login("admin"), {"task_timeout_min": 1}).status_code == 200

    headers = login("engineer")
    task = create_zip_task(client, headers).json()
    body = wait_for(client, headers, task["id"], finished)
    assert body["status"] == "failed"
    assert body["error"] == "超过任务总时长上限（1 分钟）"
    assert body["quota"]["task_timeout_min"] == 1
    assert task["id"] in sandbox.destroyed


def test_raising_concurrency_starts_queued_task(client: TestClient, login, sandbox: ImageSandbox, monkeypatch) -> None:
    """验收 2：达到并发上限时新任务排队，调大上限后立即开始。"""

    async def slow(_ctx) -> None:
        await asyncio.sleep(30)

    monkeypatch.setitem(graph.AGENTS, Stage.CODE_AUDIT, slow)
    headers = login("engineer")
    first = create_zip_task(client, headers).json()
    wait_for(client, headers, first["id"], lambda b: b["current_stage"] == "code_audit")
    second = create_zip_task(client, headers).json()
    assert client.get(f"/api/tasks/{second['id']}", headers=headers).json()["status"] == "created"

    assert put(client, login("admin"), {"max_concurrent": 2}).status_code == 200
    body = wait_for(client, headers, second["id"], lambda b: b["status"] == "running")
    assert body["quota"]["max_concurrent"] == 2
