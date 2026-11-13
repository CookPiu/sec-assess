"""动态验证执行流程：注册测试账号、执行用例、命中改判与证据落库。用假探针代替容器。"""

from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy import select

from app.core.db import session_factory
from app.core.runtime import RuntimeConfig
from app.models import Evidence, Finding, Project, StageLog, Task
from app.models.enums import Category, Severity, TaskStatus, VerifyStatus
from app.pipeline.state import TaskContext
from app.project.flask_facts import collect_flask_facts
from app.project.pysource import ProjectIndex
from app.sandbox.manager import ExecResult
from app.sandbox.probe import ProbeResult
from app.verify import execute

TARGETS = Path(__file__).resolve().parents[2] / "targets"


class FakeSandbox:
    def __init__(self) -> None:
        self.detached: list[list[str]] = []

    def copy_source(self, _task_id: int) -> ExecResult:
        return ExecResult(0, "", "")

    def exec(self, _task_id: int, _cmd, **_kw) -> ExecResult:
        return ExecResult(0, "", "")

    def exec_detached(self, _task_id: int, cmd, **_kw) -> None:
        self.detached.append(cmd)


class FakeProbe:
    """模拟 user-center：注册返回 id，登录返回 JWT，资料接口返回账号数据。"""

    def __init__(self) -> None:
        self.users: dict[str, int] = {}
        self.next_id = 1
        self.cases: list[dict] = []

    def result(self, status: int, body: str) -> ProbeResult:
        return ProbeResult(
            ok=True,
            status=status,
            body=body,
            request_raw=f"request {status}",
            response_raw=f"response {body}",
        )

    def __call__(self, _sandbox, _task_id, case, *, timeout: int = 10) -> ProbeResult:
        del timeout
        self.cases.append(case)
        path = case["path"]
        data = (case.get("body") or {}).get("data") or {}
        if path == "/":
            return self.result(200, "ok")
        if path == "/api/register":
            user_id = self.next_id
            self.next_id += 1
            self.users[data["username"]] = user_id
            return self.result(201, json.dumps({"id": user_id, "username": data["username"]}))
        if path == "/api/login":
            user_id = self.users.get(data.get("username"))
            if user_id is None:
                return self.result(401, '{"error": "bad"}')
            return self.result(200, json.dumps({"token": f"t{user_id}", "user_id": user_id}))
        if path == "/api/users/export":
            return self.result(200, json.dumps([{"username": name} for name in self.users]))
        if path.startswith("/api/users/"):
            user_id = int(path.rsplit("/", 1)[1])
            name = next((n for n, i in self.users.items() if i == user_id), "")
            return self.result(200, json.dumps({"id": user_id, "username": name, "phone": name}))
        return self.result(200, "nothing")


def _facts() -> dict:
    index = ProjectIndex(TARGETS / "user-center")
    return collect_flask_facts(index)


def test_verification_updates_status_and_saves_evidence(
    client, run_async, monkeypatch
) -> None:
    facts = _facts()

    async def setup() -> tuple[int, int, list[int]]:
        async with session_factory()() as session:
            project = Project(name="user-center", source_type="zip", source_dir="fake")
            session.add(project)
            await session.flush()
            task = Task(
                project_id=project.id,
                status=TaskStatus.RUNNING,
                recon={"facts": facts},
                deps_result={"ok": True, "missing": []},
            )
            session.add(task)
            await session.flush()
            rows = [
                Finding(
                    task_id=task.id,
                    code=f"VT-{task.id}-001",
                    category=Category.IDOR,
                    title="越权",
                    severity=Severity.HIGH,
                    file="app.py",
                    line=66,
                    route={"path": "/api/users/<int:user_id>", "methods": ["GET"], "access": "user"},
                    status=VerifyStatus.UNVERIFIED,
                ),
                Finding(
                    task_id=task.id,
                    code=f"VT-{task.id}-002",
                    category=Category.MISSING_AUTH,
                    title="缺失鉴权",
                    severity=Severity.HIGH,
                    file="app.py",
                    line=84,
                    route={"path": "/api/users/export", "methods": ["GET"], "access": "anonymous"},
                    status=VerifyStatus.UNVERIFIED,
                ),
                Finding(
                    task_id=task.id,
                    code=f"VT-{task.id}-003",
                    category=Category.MISSING_AUTH,
                    title="未命中的候选",
                    severity=Severity.CRITICAL,
                    file="app.py",
                    line=90,
                    route={"path": "/api/nothing", "methods": ["GET"], "access": "anonymous"},
                    status=VerifyStatus.UNVERIFIED,
                ),
            ]
            session.add_all(rows)
            await session.commit()
            return project.id, task.id, [row.id for row in rows]

    project_id, task_id, finding_ids = run_async(setup)
    findings = [
        {
            "id": finding_id,
            "code": f"VT-{task_id}-{number:03d}",
            "category": category,
            "severity": severity,
            "file": "app.py",
            "line": 66,
            "route": route,
            "steps": [],
            "model_false_positive": False,
        }
        for number, (finding_id, category, severity, route) in enumerate(
            [
                (finding_ids[0], Category.IDOR, Severity.HIGH, {"path": "/api/users/<int:user_id>", "methods": ["GET"], "access": "user"}),
                (finding_ids[1], Category.MISSING_AUTH, Severity.HIGH, {"path": "/api/users/export", "methods": ["GET"], "access": "anonymous"}),
                (finding_ids[2], Category.MISSING_AUTH, Severity.CRITICAL, {"path": "/api/nothing", "methods": ["GET"], "access": "anonymous"}),
            ],
            1,
        )
    ]

    probe = FakeProbe()
    monkeypatch.setattr(execute, "run_probe", probe)
    sandbox = FakeSandbox()
    index = ProjectIndex(TARGETS / "user-center")
    ctx = TaskContext(
        task_id=task_id,
        project_id=project_id,
        source_type="zip",
        source_url=None,
        source_dir=TARGETS / "user-center",
        runtime=RuntimeConfig(),
        sandbox=sandbox,
    )
    run_async(execute.run_verification, ctx, index, findings, facts)

    async def load():
        async with session_factory()() as session:
            rows = (
                await session.execute(select(Finding).where(Finding.task_id == task_id).order_by(Finding.id))
            ).scalars().all()
            evidence = (
                await session.execute(
                    select(Evidence).where(Evidence.finding_id.in_(finding_ids)).order_by(Evidence.id)
                )
            ).scalars().all()
            logs = (
                await session.execute(select(StageLog).where(StageLog.task_id == task_id))
            ).scalars().all()
        return rows, evidence, logs

    rows, evidence, logs = run_async(load)
    statuses = {row.id: row.status for row in rows}
    assert statuses[finding_ids[0]] == VerifyStatus.VERIFIED
    assert statuses[finding_ids[1]] == VerifyStatus.VERIFIED
    assert statuses[finding_ids[2]] == VerifyStatus.UNVERIFIED
    severities = {row.id: row.severity for row in rows}
    assert severities[finding_ids[2]] == Severity.MEDIUM  # 未命中降为中危

    assert len(evidence) == 3
    assert [item.hit for item in evidence] == [True, True, False]
    assert all(item.request_raw and item.response_raw for item in evidence)
    assert all(item.case.get("replay") for item in evidence)
    idor_evidence = next(item for item in evidence if item.finding_id == finding_ids[0])
    assert idor_evidence.case["path"] == "/api/users/2"

    messages = [item.message for item in logs]
    assert any("准备两个测试账号" in message for message in messages)
    assert any("验证通过" in message for message in messages)
    assert any("未命中" in message for message in messages)
    assert len(sandbox.detached) == 1  # 一次启动，工程进程未退出
    idor_case = next(case for case in probe.cases if case["path"] == "/api/users/2")
    assert idor_case["headers"] == {"Authorization": "Bearer t1"}
