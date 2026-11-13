"""攻击路径组装（T035）：以两个靶场的侦察事实为输入，覆盖推导规则、剪枝、成环防护与多步路径筛选。"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from app.chain.assemble import ADMIN, GOAL_DATA, GOAL_RCE, START, USER, ChainFinding, build_chain
from app.models.enums import ChainNodeKind
from app.project.flask_facts import collect_flask_facts
from app.project.pysource import ProjectIndex

TARGETS = Path(__file__).resolve().parents[2] / "targets"


@pytest.fixture(scope="module")
def shop_facts() -> dict[str, Any]:
    return collect_flask_facts(ProjectIndex(TARGETS / "shop-admin"))


@pytest.fixture(scope="module")
def center_facts() -> dict[str, Any]:
    return collect_flask_facts(ProjectIndex(TARGETS / "user-center"))


def access_of(facts: dict[str, Any], path: str) -> str:
    [route] = [r for r in facts["routes"] if r["path"] == path]
    return route["access"]


def shop_findings(facts: dict[str, Any]) -> list[ChainFinding]:
    """DESIGN.md 第 8 节中电商靶场预期为 Verified 的漏洞，访问前提取自侦察事实。"""
    items = [
        (1, "S8", "template_injection", "/admin/mail/preview"),
        (2, "S1", "sql_injection", "/orders/search"),
        (3, "S2", "config_exposure", "/debug/config"),
        (4, "S6", "command_injection", "/admin/logistics/ping"),
        (5, "S7", "deserialization", "/admin/backup/import"),
        (6, "S9", "path_traversal", "/admin/products/<int:product_id>/image"),
    ]
    found = [
        ChainFinding(
            id=i,
            code=code,
            category=category,
            title=code,
            access=access_of(facts, path),
            matched="文件出现在 /work/app/static/x.txt" if category == "path_traversal" else None,
        )
        for i, code, category, path in items
    ]
    found.append(ChainFinding(id=7, code="S3", category="debug_mode", title="S3", access=None))
    return found


def labels(graph, path) -> list[str]:
    return [graph.nodes[key].label for key in path.nodes]


def test_shop_admin_chains_through_admin_identity(shop_facts) -> None:
    assert access_of(shop_facts, "/orders/search") == "anonymous"
    assert access_of(shop_facts, "/admin/backup/import") == "admin"
    graph = build_chain(shop_findings(shop_facts), shop_facts)

    assert graph.nodes[START].kind == ChainNodeKind.START
    assert graph.nodes[ADMIN].label == "管理员身份"
    assert USER not in graph.nodes  # 电商靶场没有开放注册接口
    assert GOAL_DATA not in graph.nodes and graph.nodes[GOAL_RCE].label == "执行代码"
    findings = {n.finding_id for n in graph.nodes.values() if n.kind == ChainNodeKind.FINDING}
    assert findings == {1, 2, 3, 4, 5, 6}
    assert [(f.code, why) for f, why in graph.skipped] == [("S3", "该类别没有登记可获得的能力")]

    edges = {(e.src, e.dst): e.reason for e in graph.edges}
    assert edges[(START, "finding:2")] == "无需登录即可访问"
    assert "无盐哈希（hashlib.md5）" in edges[("finding:2", ADMIN)]
    assert "伪造 Flask 签名会话" in edges[("finding:3", ADMIN)]
    assert edges[(ADMIN, "finding:5")] == "管理员身份满足后台访问要求"
    assert "/work/app/static/x.txt" in edges[("finding:6", GOAL_RCE)]

    # US3 验收 1：匿名 SQL 注入 → 取得管理员身份 → 后台功能执行代码，三步及以上
    readable = [labels(graph, p) for p in graph.paths]
    assert ["匿名攻击者", "S1 SQL 注入", "管理员身份", "S7 不安全的反序列化", "执行代码"] in readable
    assert ["匿名攻击者", "S2 配置暴露", "管理员身份", "S9 文件上传 / 路径穿越", "执行代码"] in readable
    assert len(graph.paths) == 8  # 2 个匿名入口 × 4 个后台执行代码漏洞
    assert all(graph.finding_count(p) == 2 and p.target == "执行代码" for p in graph.paths)

    first = graph.paths[0]
    assert first.steps[0] == {"node": START, "label": "匿名攻击者", "kind": "start", "via": ""}
    assert first.steps[2]["via"] == edges[(first.nodes[1], ADMIN)]


def test_user_center_has_no_multi_step_path(center_facts) -> None:
    findings = [
        ChainFinding(1, "U2", "missing_auth", "U2", access_of(center_facts, "/api/users/export")),
        ChainFinding(2, "U1", "idor", "U1", access_of(center_facts, "/api/users/<int:user_id>")),
    ]
    graph = build_chain(findings, center_facts)
    edges = {(e.src, e.dst): e.reason for e in graph.edges}
    assert edges[(START, USER)].startswith("开放注册接口 POST /api/register")
    assert edges[(USER, "finding:2")] == "普通用户身份满足登录要求"
    assert edges[(START, "finding:1")] == "无需登录即可访问"
    assert set(edges) == {(START, USER), (USER, "finding:2"), (START, "finding:1"), ("finding:1", GOAL_DATA), ("finding:2", GOAL_DATA)}
    assert graph.paths == []  # 每条路径只经过一个漏洞节点，不算多步


def test_no_derivation_without_weak_password_or_cookie_session(shop_facts) -> None:
    facts = {**shop_facts, "password_storage": {"kind": "salted_hash"}, "session": {"flask_session": False}}
    graph = build_chain(shop_findings(shop_facts), facts)
    assert graph.nodes == {} and graph.edges == [] and graph.paths == []
    reasons = {f.code: why for f, why in graph.skipped}
    assert reasons["S1"] == "获得的能力无法衔接到执行代码或读他人数据"
    assert reasons["S7"] == "前置条件无法满足"


def test_identity_never_derived_from_equal_or_higher_entry() -> None:
    facts = {"password_storage": {"kind": "plaintext"}, "session": {"flask_session": True}, "auth": {}}
    findings = [
        ChainFinding(1, "A", "config_exposure", "A", "anonymous"),
        # 管理员才能触发的 SQL 注入不能再推出管理员身份，否则成环
        ChainFinding(2, "B", "sql_injection", "B", "admin"),
        # 没有注册接口时，需登录的漏洞由管理员身份进入
        ChainFinding(3, "C", "idor", "C", "user"),
        ChainFinding(4, "D", "command_injection", "D", "admin"),
    ]
    graph = build_chain(findings, facts)
    pairs = {(e.src, e.dst) for e in graph.edges}
    assert ("finding:2", ADMIN) not in pairs
    assert "finding:2" not in graph.nodes  # 推不出新能力，剪掉
    assert (ADMIN, "finding:3") in pairs and ("finding:3", GOAL_DATA) in pairs
    readable = sorted(labels(graph, p) for p in graph.paths)
    assert readable == [
        ["匿名攻击者", "A 配置暴露", "管理员身份", "C 越权访问", "读他人数据"],
        ["匿名攻击者", "A 配置暴露", "管理员身份", "D 命令注入", "执行代码"],
    ]
    assert graph.paths[0].target == "执行代码"  # 执行代码排在前面


def test_user_entry_preferred_and_admin_reached_through_user() -> None:
    facts = {
        "password_storage": {"kind": "unsalted_hash", "detail": "hashlib.sha1"},
        "session": {},
        "auth": {"register": {"method": "POST", "path": "/signup"}},
    }
    findings = [
        ChainFinding(1, "Q", "sql_injection", "Q", "user"),
        ChainFinding(2, "R", "template_injection", "R", "admin"),
        ChainFinding(3, "I", "idor", "I", "user"),
    ]
    graph = build_chain(findings, facts)
    pairs = {(e.src, e.dst) for e in graph.edges}
    assert (USER, "finding:1") in pairs and (ADMIN, "finding:1") not in pairs
    assert (USER, "finding:3") in pairs and (ADMIN, "finding:3") not in pairs
    assert [labels(graph, p) for p in graph.paths] == [
        ["匿名攻击者", "普通用户身份", "Q SQL 注入", "管理员身份", "R 模板注入", "执行代码"]
    ]
