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

from app.models import Finding, Project, TaintStep, Task
from app.models.enums import Stage, TaskStatus
from app.pipeline import graph
from app.pipeline.runner import runner
from app.sandbox.manager import ExecResult

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

    def exec(self, task_id: int, cmd, **_kw) -> ExecResult:  # 依赖准备读不到解释器信息，记为准备失败
        return ExecResult(exit_code=1, stdout="", stderr="fake sandbox")

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
    stop_leftover_tasks(run_async)


def stop_leftover_tasks(run_async) -> None:
    """停掉本测试遗留的任务，避免占住并发名额。"""
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

    audit = client.get("/api/audit-logs", headers=login("admin"), params={"action": "task_create"}).json()
    entry = next(x for x in audit["items"] if x["target_id"] == str(task["id"]))
    assert entry["username"] == "engineer" and entry["target_type"] == "task"
    assert entry["detail"]["project_name"] == "shop-demo" and entry["detail"]["source_type"] == "zip"

    logs = client.get(f"/api/tasks/{task['id']}/logs", headers=headers).json()
    messages = [x["message"] for x in logs]
    for label in ("环境侦察", "源码审计", "动态验证", "攻击路径推演", "补丁与报告"):
        assert f"阶段开始：{label}" in messages
        assert any(m.startswith(f"阶段结束：{label}") for m in messages)
    assert any("Flask 3.0.3" in m for m in messages)
    assert any(
        row["stage"] == "poc_verify" and row["level"] == "warn" and row["message"] == "跳过动态验证：工程依赖未准备就绪"
        for row in logs
    )
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


VULN_APP = b"""import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.get("/search")
def search():
    q = request.args.get("q", "")
    sql = f"SELECT name FROM item WHERE name = '{q}'"
    return str(sqlite3.connect("shop.db").execute(sql).fetchall())


if __name__ == "__main__":
    app.run(port=8000, debug=True)
"""


def test_code_audit_stores_findings_and_recon_facts(client: TestClient, login, fake: FakeSandbox, run_async) -> None:
    headers = login("engineer")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("vuln/app.py", VULN_APP)
    resp = create_zip_task(client, headers, name="vuln.zip", data=buf.getvalue())
    assert resp.status_code == 201, resp.text
    task_id = resp.json()["id"]
    body = wait_for(client, headers, task_id, finished)
    assert body["status"] == "completed", body

    async def load():
        from app.core.db import session_factory

        async with session_factory()() as session:
            task = await session.get(Task, task_id)
            findings = (await session.execute(select(Finding).where(Finding.task_id == task_id))).scalars().all()
            steps = (
                await session.execute(
                    select(TaintStep).where(TaintStep.finding_id.in_([f.id for f in findings])).order_by(TaintStep.seq)
                )
            ).scalars().all()
            return task.recon, findings, steps

    recon_result, findings, steps = run_async(load)
    facts = recon_result["facts"]
    assert facts["entry"]["port"] == 8000 and facts["entry"]["debug"] is True
    assert [r["path"] for r in facts["routes"]] == ["/search"]

    by_cat = {f.category: f for f in findings}
    assert set(by_cat) == {"sql_injection", "debug_mode"}
    sql = by_cat["sql_injection"]
    assert sql.code == f"SA-{task_id}-001"
    assert sql.status == "unverified" and sql.judged_by == "default" and "未经模型研判" in sql.reason
    assert sql.route == {"path": "/search", "methods": ["GET"], "access": "anonymous"}
    sql_steps = [s for s in steps if s.finding_id == sql.id]
    assert sql_steps[0].note.startswith("读取用户输入") and sql_steps[-1].line == sql.line

    logs = [x["message"] for x in client.get(f"/api/tasks/{task_id}/logs", headers=headers).json()]
    assert any(m.startswith("启动方式：app.py 第 16 行调用 app.run") for m in logs)
    assert any(m.startswith(f"SA-{task_id}-001 ") for m in logs)
    assert any(m.startswith("研判完成：") for m in logs)


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
    async def broken(ctx) -> None:
        from app.core.db import session_factory

        async with session_factory()() as session:
            session.add(
                Finding(
                    task_id=ctx.task_id, code=f"SA-{ctx.task_id}-001", category="hardcoded_secret", title="密钥",
                    severity="critical", cvss_score=9.1, file="app.py", line=1, status="unverified",
                )
            )
            await session.commit()
        raise RuntimeError("boom")

    monkeypatch.setitem(graph.AGENTS, Stage.POC_VERIFY, broken)
    headers = login("engineer")
    task = create_zip_task(client, headers).json()
    body = wait_for(client, headers, task["id"], finished)
    assert body["status"] == "failed"
    assert body["current_stage"] == "poc_verify"
    assert "boom" in body["error"]
    assert task["id"] in fake.destroyed
    # 没走完动态验证，收尾时疑似漏洞封顶为中危（D-029）
    findings = client.get(f"/api/tasks/{task['id']}/findings", headers=headers).json()
    assert [(f["status"], f["severity"], f["cvss_score"]) for f in findings] == [("unverified", "medium", 9.1)]


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
