"""推演 Agent 与攻击路径接口（T036）：落库、模板与模型两种文字来源、重复执行、接口输出。"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.core.db import session_factory
from app.core.runtime import RuntimeConfig
from app.models import AttackPath, ChainEdge, ChainNode, Evidence, Finding, Project, StageLog, Task
from app.models.enums import Severity, SourceType, TaskStatus, VerifyStatus
from app.pipeline.agents import chain
from app.pipeline.state import TaskContext
from app.project.flask_facts import collect_flask_facts
from app.project.pysource import ProjectIndex

TARGETS = Path(__file__).resolve().parents[2] / "targets"

# (编号后缀, 类别, 路由路径, 访问前提, 状态)
SHOP = [
    (1, "template_injection", "/admin/mail/preview", "admin", VerifyStatus.VERIFIED),
    (2, "sql_injection", "/orders/search", "anonymous", VerifyStatus.VERIFIED),
    (3, "config_exposure", "/debug/config", "anonymous", VerifyStatus.VERIFIED),
    (4, "command_injection", "/admin/logistics/ping", "admin", VerifyStatus.VERIFIED),
    (5, "deserialization", "/admin/backup/import", "admin", VerifyStatus.VERIFIED),
    (6, "path_traversal", "/admin/products/<int:product_id>/image", "admin", VerifyStatus.VERIFIED),
    (7, "hardcoded_secret", None, None, VerifyStatus.UNVERIFIED),
    (8, "debug_mode", None, None, VerifyStatus.VERIFIED),
]


@pytest.fixture(scope="module")
def shop_facts() -> dict[str, Any]:
    return collect_flask_facts(ProjectIndex(TARGETS / "shop-admin"))


def seed(run_async, facts: dict[str, Any], items=SHOP) -> int:
    async def _seed() -> int:
        async with session_factory()() as session:
            project = Project(name="chain", source_type=SourceType.ZIP, source_dir="projects/chain/src")
            session.add(project)
            await session.flush()
            task = Task(project_id=project.id, status=TaskStatus.RUNNING, recon={"facts": facts})
            session.add(task)
            await session.flush()
            for seq, category, path, access, status in items:
                finding = Finding(
                    task_id=task.id,
                    code=f"SA-{task.id}-{seq:03d}",
                    category=category,
                    title=f"{category} {path or ''}".strip(),
                    severity=Severity.HIGH,
                    file="shop/admin.py",
                    line=seq,
                    route={"path": path, "methods": ["POST" if access == "admin" else "GET"], "access": access}
                    if path
                    else None,
                    status=status,
                )
                session.add(finding)
                await session.flush()
                if category == "path_traversal":
                    session.add_all(
                        [
                            Evidence(finding_id=finding.id, case={}, matched="响应中未出现命中特征", hit=False),
                            Evidence(finding_id=finding.id, case={}, matched="文件出现在 /work/app/static/a.txt", hit=True),
                        ]
                    )
            await session.commit()
            return task.id

    return run_async(_seed)


def make_ctx(task_id: int, *, llm_enabled: bool = False) -> TaskContext:
    return TaskContext(
        task_id=task_id,
        project_id=0,
        source_type="zip",
        source_url=None,
        source_dir=TARGETS / "shop-admin",
        runtime=RuntimeConfig(llm_enabled=llm_enabled),
        sandbox=None,  # 推演阶段不使用沙箱
    )


async def counts(task_id: int) -> tuple[int, int, int]:
    async with session_factory()() as session:
        result = []
        for model in (ChainNode, ChainEdge, AttackPath):
            result.append(await session.scalar(select(func.count()).select_from(model).where(model.task_id == task_id)))
        return tuple(result)


async def logs(task_id: int) -> list[str]:
    async with session_factory()() as session:
        rows = await session.execute(select(StageLog.message).where(StageLog.task_id == task_id).order_by(StageLog.id))
        return list(rows.scalars())


def test_agent_saves_graph_with_template_text(client: TestClient, login, run_async, shop_facts) -> None:
    task_id = seed(run_async, shop_facts)
    run_async(chain.run, make_ctx(task_id))
    # 起点、管理员身份、执行代码 3 个节点 + 6 个漏洞节点；边：2 入口 + 2 推导 + 4 后台入口 + 4 执行代码
    assert run_async(counts, task_id) == (9, 12, 8)
    run_async(chain.run, make_ctx(task_id))  # 重复执行不产生重复数据
    assert run_async(counts, task_id) == (9, 12, 8)

    messages = run_async(logs, task_id)
    assert f"SA-{task_id}-008 未进入攻击路径图：该类别没有登记可获得的能力" in messages
    assert "能力推导完成：7 条已验证漏洞中 6 条进入攻击路径图，边 12 条，多步攻击路径 8 条" in messages
    assert "大模型未启用，阶段说明与业务危害按路径步骤生成" in messages

    body = client.get(f"/api/tasks/{task_id}/chain", headers=login("developer")).json()
    nodes = {n["id"]: n for n in body["nodes"]}
    kinds = sorted(n["kind"] for n in body["nodes"])
    assert kinds == ["capability", "finding", "finding", "finding", "finding", "finding", "finding", "goal", "start"]
    sqli = next(n for n in body["nodes"] if n["label"] == f"SA-{task_id}-002 SQL 注入")
    assert sqli["severity"] == "high" and sqli["route"]["path"] == "/orders/search"
    assert all(nodes[e["src"]] and nodes[e["dst"]] for e in body["edges"])

    paths = body["paths"]
    assert len(paths) == 8 and all(p["target"] == "执行代码" and p["written_by"] == "template" for p in paths)
    labels = [[nodes[i]["label"] for i in p["node_ids"]] for p in paths]
    expected = ["匿名攻击者", f"SA-{task_id}-002 SQL 注入", "管理员身份", f"SA-{task_id}-005 不安全的反序列化", "执行代码"]
    path = paths[labels.index(expected)]
    assert [s["node_id"] for s in path["steps"]] == path["node_ids"]
    assert path["summary"].startswith(f"1. 匿名访问 GET /orders/search，利用 SA-{task_id}-002 SQL 注入；2. 读出用户表")
    assert f"以管理员身份访问 POST /admin/backup/import，利用 SA-{task_id}-005 不安全的反序列化；4. 执行代码。" in path["summary"]
    assert path["impact"].startswith("攻击者可在应用服务器上")
    upload = next(p for p in paths if any("文件上传" in nodes[i]["label"] for i in p["node_ids"]))
    assert "/work/app/static/a.txt" in upload["steps"][-1]["via"]


class FakeLLM:
    configured = True

    def __init__(self) -> None:
        self.prompts: list[str] = []

    async def chat_json(self, system: str, user: str, *, enabled: bool = True) -> dict[str, Any] | None:
        self.prompts.append(user)
        if "SA-" in user and "配置暴露" in user:
            return {"summary": "", "impact": "缺字段"}  # 不合法，回退模板
        return {"summary": "模型写的阶段说明", "impact": "模型写的业务危害"}


def test_agent_uses_model_text_and_falls_back(client: TestClient, login, run_async, shop_facts, monkeypatch) -> None:
    fake = FakeLLM()
    monkeypatch.setattr(chain, "get_llm", lambda: fake)
    task_id = seed(run_async, shop_facts)
    run_async(chain.run, make_ctx(task_id, llm_enabled=True))
    assert len(fake.prompts) == 8
    assert all("攻陷目标：执行代码" in p and "[start] 匿名攻击者" in p for p in fake.prompts)

    paths = client.get(f"/api/tasks/{task_id}/chain", headers=login("engineer")).json()["paths"]
    by_model = [p for p in paths if p["written_by"] == "model"]
    assert len(by_model) == 4 and all(p["summary"] == "模型写的阶段说明" for p in by_model)
    assert all(p["summary"].startswith("1. 匿名访问 GET /debug/config") for p in paths if p["written_by"] == "template")
    assert "4 条路径的模型输出不可用，改用按步骤生成的说明" in run_async(logs, task_id)


def test_agent_without_multi_step_path(client: TestClient, login, run_async, shop_facts) -> None:
    only_admin = [(1, "command_injection", "/admin/logistics/ping", "admin", VerifyStatus.VERIFIED)]
    task_id = seed(run_async, shop_facts, only_admin)
    run_async(chain.run, make_ctx(task_id))
    assert run_async(counts, task_id) == (0, 0, 0)
    assert "已验证漏洞之间没有能力衔接，不生成多步攻击路径" in run_async(logs, task_id)
    assert client.get(f"/api/tasks/{task_id}/chain", headers=login("admin")).json() == {
        "nodes": [],
        "edges": [],
        "paths": [],
    }

    none_verified = [(1, "hardcoded_secret", None, None, VerifyStatus.UNVERIFIED)]
    empty = seed(run_async, shop_facts, none_verified)
    run_async(chain.run, make_ctx(empty))
    assert run_async(logs, empty) == ["没有已验证漏洞，不生成攻击路径"]


def test_chain_api_errors(client: TestClient, login) -> None:
    assert client.get("/api/tasks/99999/chain", headers=login("engineer")).status_code == 404
    assert client.get("/api/tasks/1/chain").status_code == 401
