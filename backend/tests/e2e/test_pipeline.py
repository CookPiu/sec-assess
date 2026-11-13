"""US1 端到端验收：两个靶场在真实沙箱里跑到 completed，检出结果与 DESIGN.md 第 8 节一致（T031）。

需要 Docker Desktop、已构建的沙箱镜像和访问 PyPI 的网络（user-center 的 PyJWT 不在镜像里）。
"""

from __future__ import annotations

import asyncio
import io
import time
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.db import session_factory
from app.models import Evidence, Finding, StageLog, Task
from app.models.enums import Category, Stage, VerifyStatus
from app.pipeline import graph
from app.pipeline.runner import runner
from app.sandbox.manager import sandbox_manager

from tests.test_tasks_api import create_zip_task, finished, wait_for

TARGETS = Path(__file__).resolve().parents[3] / "targets"
pytestmark = [pytest.mark.docker, pytest.mark.network]

SHOP_VERIFIED = {
    Category.SQL_INJECTION,
    Category.CONFIG_EXPOSURE,
    Category.DEBUG_MODE,
    Category.COMMAND_INJECTION,
    Category.TEMPLATE_INJECTION,
    Category.DESERIALIZATION,
    Category.PATH_TRAVERSAL,
}
SHOP_UNVERIFIED = {Category.HARDCODED_SECRET, Category.WEAK_PASSWORD_STORAGE}
CENTER_VERIFIED = {Category.IDOR, Category.MISSING_AUTH}


@pytest.fixture
def real_sandbox(monkeypatch, client: TestClient):
    if not sandbox_manager.ping():
        pytest.skip("Docker 未启动")
    monkeypatch.setattr(runner, "manager", sandbox_manager)
    return sandbox_manager


def target_zip(name: str) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for path in sorted((TARGETS / name).rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".db":
                archive.write(path, f"{name}/{path.relative_to(TARGETS / name).as_posix()}")
    return buffer.getvalue()


def run_assessment(client: TestClient, headers: dict[str, str], name: str) -> int:
    source = target_zip(name)
    resp = create_zip_task(client, headers, name=f"{name}.zip", data=source)
    assert resp.status_code == 201, resp.text
    task_id = resp.json()["id"]
    body = wait_for(client, headers, task_id, finished, timeout=15 * 60)
    assert body["status"] == "completed", body
    return task_id


def load_results(fn, task_id: int):
    async def _load():
        async with session_factory()() as session:
            task = await session.get(Task, task_id)
            findings = (
                await session.execute(select(Finding).where(Finding.task_id == task_id).order_by(Finding.id))
            ).scalars().all()
            evidence = (
                await session.execute(
                    select(Evidence).where(Evidence.finding_id.in_([item.id for item in findings]))
                )
            ).scalars().all()
        return task, findings, evidence

    return fn(_load)


def assert_evidence_matches_verdicts(findings, evidence) -> None:
    verified_ids = {item.id for item in findings if item.status == VerifyStatus.VERIFIED}
    hit_ids = {item.finding_id for item in evidence if item.hit}
    assert hit_ids == verified_ids
    for item in evidence:
        assert item.request_raw and item.response_raw and item.matched
        assert item.case.get("replay")


def test_shop_admin_assessment(client: TestClient, login, run_async, real_sandbox) -> None:
    """S1–S9：注入、配置暴露、调试模式与管理类漏洞命中；硬编码密钥与弱密码存储保持疑似。"""
    headers = login("engineer")
    task_id = run_assessment(client, headers, "shop-admin")
    task, findings, evidence = load_results(run_async, task_id)
    assert task.deps_result["ok"] is True

    by_category = {finding.category: finding for finding in findings}
    assert set(by_category) == SHOP_VERIFIED | SHOP_UNVERIFIED, "检出结果与 DESIGN.md 第 8 节不一致"
    for category in SHOP_VERIFIED:
        assert by_category[category].status == VerifyStatus.VERIFIED, (
            category,
            by_category[category].reason,
        )
    for category in SHOP_UNVERIFIED:
        assert by_category[category].status == VerifyStatus.UNVERIFIED

    assert_evidence_matches_verdicts(findings, evidence)
    messages = [entry["message"] for entry in client.get(f"/api/tasks/{task_id}/logs", headers=headers).json()]
    assert any("验证通过" in message for message in messages)
    assert any("动态验证完成" in message for message in messages)


def test_user_center_assessment(client: TestClient, login, run_async, real_sandbox) -> None:
    """U1–U3：越权与缺失鉴权命中；硬编码 JWT 密钥保持疑似；诱饵接口不产生检出。"""
    headers = login("engineer")
    task_id = run_assessment(client, headers, "user-center")
    task, findings, evidence = load_results(run_async, task_id)
    assert task.deps_result["ok"] is True
    assert {"name": "pyjwt", "version": "2.9.0"} in task.deps_result["installed"]

    by_category = {finding.category: finding for finding in findings}
    assert set(by_category) == CENTER_VERIFIED | {Category.HARDCODED_SECRET}, "检出结果与 DESIGN.md 第 8 节不一致"
    for category in CENTER_VERIFIED:
        assert by_category[category].status == VerifyStatus.VERIFIED, (
            category,
            by_category[category].reason,
        )
    assert by_category[Category.HARDCODED_SECRET].status == VerifyStatus.UNVERIFIED

    assert_evidence_matches_verdicts(findings, evidence)


def test_stop_keeps_findings_and_removes_container(
    client: TestClient, login, run_async, real_sandbox, monkeypatch
) -> None:
    """SC-006：动态验证结束后停在阶段内再停止，容器 5 秒内消失，已产出的漏洞与证据仍可读。"""
    original = graph.AGENTS[Stage.POC_VERIFY]

    async def hold_after_verify(ctx) -> None:
        await original(ctx)
        await asyncio.sleep(60)

    monkeypatch.setitem(graph.AGENTS, Stage.POC_VERIFY, hold_after_verify)
    headers = login("engineer")
    task = create_zip_task(client, headers, name="shop-admin.zip", data=target_zip("shop-admin")).json()

    def verified_done(body: dict) -> bool:
        if body["status"] != "running":
            return True
        messages = [entry["message"] for entry in client.get(f"/api/tasks/{task['id']}/logs", headers=headers).json()]
        return any("动态验证完成" in message for message in messages)

    body = wait_for(client, headers, task["id"], verified_done, timeout=15 * 60)
    assert body["status"] == "running", body

    async def counts():
        async with session_factory()() as session:
            findings = (
                await session.execute(select(Finding).where(Finding.task_id == task["id"]))
            ).scalars().all()
            evidence = (
                await session.execute(
                    select(Evidence).where(Evidence.finding_id.in_([item.id for item in findings]))
                )
            ).scalars().all()
            logs = (
                await session.execute(select(StageLog).where(StageLog.task_id == task["id"]))
            ).scalars().all()
        return findings, evidence, logs

    findings_before, evidence_before, logs_before = run_async(counts)
    assert findings_before and evidence_before and logs_before

    stopped = client.post(f"/api/tasks/{task['id']}/stop", headers=headers)
    assert stopped.status_code == 200 and stopped.json()["status"] == "stopped"

    deadline = time.monotonic() + 5
    while sandbox_manager.exists(task["id"]):
        assert time.monotonic() < deadline, "停止 5 秒后容器仍存在"
        time.sleep(0.2)

    findings_after, evidence_after, logs_after = run_async(counts)
    assert [item.id for item in findings_after] == [item.id for item in findings_before]
    assert [item.id for item in evidence_after] == [item.id for item in evidence_before]
    assert {item.id for item in logs_after} >= {item.id for item in logs_before}
    assert client.get(f"/api/tasks/{task['id']}", headers=headers).json()["status"] == "stopped"
