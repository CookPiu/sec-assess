"""任务接口与流水线调度：用假沙箱替代 Docker，覆盖新建、排队、停止、收尾与权限。"""

from __future__ import annotations

import asyncio
import io
import time
import zipfile

import pytest
from docker.errors import NotFound
from fastapi.testclient import TestClient
from sqlalchemy import select, update

from app.models import Project, Task
from app.models.enums import Stage, TaskStatus
from app.pipeline import graph
from app.pipeline.runner import runner

FLASK_APP = b"""from flask import Flask

app = Flask(__name__)


@app.get("/")
def index():
    return "ok"


if __name__ == "__main__":
    app.run(port=5000)
"""


class FakeSandbox:
    def __init__(self, *, docker_ok: bool = True, image_ok: bool = True) -> None:
        self.docker_ok = docker_ok
        self.image_ok = image_ok
        self.created: list[int] = []
        self.destroyed: list[int] = []

    @property
    def client(self):  # 资源采样线程拿不到容器，直接结束
        raise NotFound("fake sandbox")

    def ping(self) -> bool:
        return self.docker_ok

    def image_exists(self, image: str) -> bool:
        return self.image_ok

    def create(self, task_id, src_dir, image, quota, **_kw) -> str:
        assert src_dir.is_dir()
        self.created.append(task_id)
        return f"fake-{task_id}"

    def destroy(self, task_id: int) -> None:
        self.destroyed.append(task_id)

    def cleanup_leftovers(self) -> int:
        return 0


def flask_zip(top: str = "demo") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(f"{top}/app.py", FLASK_APP)
        zf.writestr(f"{top}/requirements.txt", "flask==3.0.3\n")
    return buf.getvalue()


def create_zip_task(client: TestClient, headers: dict[str, str], name: str = "demo.zip", data: bytes | None = None):
    return client.post(
        "/api/tasks",
        headers=headers,
        files={"file": (name, data if data is not None else flask_zip(), "application/zip")},
    )


def wait_for(client: TestClient, headers, task_id: int, predicate, timeout: float = 20) -> dict:
    deadline = time.monotonic() + timeout
    while True:
        body = client.get(f"/api/tasks/{task_id}", headers=headers).json()
        if predicate(body):
            return body
        assert time.monotonic() < deadline, f"等待超时，当前状态：{body}"
        time.sleep(0.05)


def finished(body: dict) -> bool:
    return body["status"] in ("completed", "failed", "stopped")


@pytest.fixture
def fake(monkeypatch, client: TestClient, run_async):
    sandbox = FakeSandbox()
    monkeypatch.setattr(runner, "manager", sandbox)
    yield sandbox
    # 停掉本测试遗留的任务，避免占住并发名额
    for task_id in list(runner._running):
        run_async(runner.stop, task_id)

    async def _clear_queue() -> None:
        from app.core.db import session_factory

        async with session_factory()() as session:
            await session.execute(
                update(Task).where(Task.status == TaskStatus.CREATED).values(status=TaskStatus.STOPPED)
            )
            await session.commit()

    run_async(_clear_queue)


def test_zip_task_runs_all_stages(client: TestClient, login, fake: FakeSandbox, run_async) -> None:
    headers = login("engineer")
    resp = create_zip_task(client, headers, name="shop-demo.zip")
    assert resp.status_code == 201, resp.text
    task = resp.json()
    assert task["project_name"] == "shop-demo"

    body = wait_for(client, headers, task["id"], finished)
    assert body["status"] == "completed", body
    assert body["error"] is None
    assert body["quota"]["max_concurrent"] == 1
    assert fake.created == [task["id"]] and task["id"] in fake.destroyed

    logs = client.get(f"/api/tasks/{task['id']}/logs", headers=headers).json()
    messages = [x["message"] for x in logs]
    for label in ("环境侦察", "源码审计", "动态验证", "攻击路径推演", "补丁与报告"):
        assert f"阶段开始：{label}" in messages
        assert any(m.startswith(f"阶段结束：{label}") for m in messages)
    assert any("Flask 3.0.3" in m for m in messages)
    assert messages[-1] == "全部阶段完成"
    after = client.get(f"/api/tasks/{task['id']}/logs", headers=headers, params={"after": logs[-2]["id"]}).json()
    assert [x["id"] for x in after] == [logs[-1]["id"]]

    project = client.get(f"/api/projects/{body['project_id']}", headers=headers).json()
    assert project["tech_stack"]["primary_language"] == "Python"
    assert project["tech_stack"]["frameworks"][0]["name"] == "Flask"
    assert project["loc"] == 7
    assert project["last_assessed_at"] is not None
    assert project["latest_task"]["id"] == task["id"]
    listed = client.get("/api/projects", headers=headers).json()
    assert any(p["id"] == body["project_id"] and p["latest_task"]["status"] == "completed" for p in listed)

    # 对已有项目重新评估
    again = client.post("/api/tasks", headers=headers, data={"project_id": str(body["project_id"])})
    assert again.status_code == 201, again.text
    assert wait_for(client, headers, again.json()["id"], finished)["status"] == "completed"


def test_stop_running_and_queued_tasks(client: TestClient, login, fake: FakeSandbox, monkeypatch) -> None:
    async def slow(_ctx) -> None:
        await asyncio.sleep(30)

    monkeypatch.setitem(graph.AGENTS, Stage.CODE_AUDIT, slow)
    headers = login("engineer")
    first = create_zip_task(client, headers).json()
    second = create_zip_task(client, headers).json()
    wait_for(client, headers, first["id"], lambda b: b["current_stage"] == "code_audit")
    # 并发上限为 1，第二个任务排队
    assert client.get(f"/api/tasks/{second['id']}", headers=headers).json()["status"] == "created"

    stopped = client.post(f"/api/tasks/{second['id']}/stop", headers=headers)
    assert stopped.status_code == 200 and stopped.json()["status"] == "stopped"

    stopped = client.post(f"/api/tasks/{first['id']}/stop", headers=headers)
    assert stopped.status_code == 200
    assert stopped.json()["status"] == "stopped"
    assert stopped.json()["current_stage"] == "code_audit"
    assert first["id"] in fake.destroyed
    messages = [x["message"] for x in client.get(f"/api/tasks/{first['id']}/logs", headers=headers).json()]
    assert "阶段开始：环境侦察" in messages and messages[-1].startswith("任务已被停止")

    again = client.post(f"/api/tasks/{first['id']}/stop", headers=headers)
    assert again.status_code == 409

    audit = client.get("/api/audit-logs", headers=login("admin"), params={"action": "task_stop"}).json()
    assert {int(x["target_id"]) for x in audit["items"]} >= {first["id"], second["id"]}


def test_stage_failure_marks_task_failed(client: TestClient, login, fake: FakeSandbox, monkeypatch) -> None:
    async def broken(_ctx) -> None:
        raise RuntimeError("boom")

    monkeypatch.setitem(graph.AGENTS, Stage.POC_VERIFY, broken)
    headers = login("engineer")
    task = create_zip_task(client, headers).json()
    body = wait_for(client, headers, task["id"], finished)
    assert body["status"] == "failed"
    assert body["current_stage"] == "poc_verify"
    assert "boom" in body["error"]
    assert task["id"] in fake.destroyed


def test_create_task_validation(client: TestClient, login, fake: FakeSandbox, run_async) -> None:
    headers = login("engineer")

    async def project_count() -> int:
        from app.core.db import session_factory

        async with session_factory()() as session:
            return len((await session.execute(select(Project))).scalars().all())

    before = run_async(project_count)
    assert client.post("/api/tasks", headers=headers, data={}).status_code == 400
    both = client.post(
        "/api/tasks",
        headers=headers,
        data={"git_url": "https://github.com/a/b.git"},
        files={"file": ("a.zip", flask_zip(), "application/zip")},
    )
    assert both.status_code == 400
    bad_url = client.post("/api/tasks", headers=headers, data={"git_url": "http://github.com/a/b.git"})
    assert bad_url.status_code == 400 and "https" in bad_url.json()["detail"]
    not_zip = create_zip_task(client, headers, name="a.tar.gz")
    assert not_zip.status_code == 400
    evil = io.BytesIO()
    with zipfile.ZipFile(evil, "w") as zf:
        zf.writestr("../evil.py", "x")
    traversal = create_zip_task(client, headers, data=evil.getvalue())
    assert traversal.status_code == 400 and "路径穿越" in traversal.json()["detail"]
    assert client.post("/api/tasks", headers=headers, data={"project_id": "99999"}).status_code == 404
    assert run_async(project_count) == before

    fake.docker_ok = False
    assert create_zip_task(client, headers).status_code == 503
    fake.docker_ok, fake.image_ok = True, False
    resp = create_zip_task(client, headers)
    assert resp.status_code == 503 and "镜像" in resp.json()["detail"]


def test_git_task_records_project(client: TestClient, login, fake: FakeSandbox, monkeypatch) -> None:
    from app.pipeline.agents import recon

    def fake_clone(url, dest) -> None:
        dest.mkdir(parents=True)
        (dest / "app.py").write_bytes(FLASK_APP)

    monkeypatch.setattr(recon, "clone_repo", fake_clone)
    headers = login("engineer")
    resp = client.post("/api/tasks", headers=headers, data={"git_url": "https://github.com/acme/user-center.git"})
    assert resp.status_code == 201, resp.text
    body = wait_for(client, headers, resp.json()["id"], finished)
    assert body["status"] == "completed", body
    project = client.get(f"/api/projects/{body['project_id']}", headers=headers).json()
    assert project["name"] == "user-center" and project["source_type"] == "git"
    assert project["tech_stack"]["frameworks"][0]["name"] == "Flask"


def test_git_clone_failure_marks_task_failed(client: TestClient, login, fake: FakeSandbox, monkeypatch) -> None:
    from app.pipeline.agents import recon
    from app.project.ingest import IngestError

    def failing_clone(url, dest) -> None:
        raise IngestError("Git 克隆失败：repository not found")

    monkeypatch.setattr(recon, "clone_repo", failing_clone)
    headers = login("engineer")
    resp = client.post("/api/tasks", headers=headers, data={"git_url": "https://github.com/acme/missing.git"})
    body = wait_for(client, headers, resp.json()["id"], finished)
    assert body["status"] == "failed"
    assert body["error"] == "Git 克隆失败：repository not found"
    assert fake.created == []


def test_task_permissions(client: TestClient, login, fake: FakeSandbox) -> None:
    for role in ("developer", "admin"):
        headers = login(role)
        assert create_zip_task(client, headers).status_code == 403
        assert client.post("/api/tasks/1/stop", headers=headers).status_code == 403
    assert client.get("/api/projects").status_code == 401
    assert client.get("/api/tasks/1").status_code == 401
    assert client.get("/api/projects", headers=login("developer")).status_code == 200
