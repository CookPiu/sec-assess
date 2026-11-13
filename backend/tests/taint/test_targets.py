"""以两个靶场为基准（DESIGN.md 第 8 节、D-018）：漏洞清单逐条检出，诱饵写法不产生候选。"""

from pathlib import Path

import pytest

from app.pipeline.agents.audit import collect_candidates
from app.project.flask_facts import collect_flask_facts
from app.project.pysource import ProjectIndex

TARGETS = Path(__file__).resolve().parents[3] / "targets"

EXPECTED = {
    "shop-admin": {
        ("sql_injection", "shop/public.py", "shop.public.search_orders"),  # S1
        ("config_exposure", "shop/public.py", "shop.public.debug_config"),  # S2
        ("debug_mode", "app.py", "app"),  # S3
        ("hardcoded_secret", "config.py", "config"),  # S4
        ("weak_password_storage", "db.py", "db"),  # S5
        ("command_injection", "shop/admin.py", "shop.admin.logistics_ping"),  # S6
        ("deserialization", "shop/admin.py", "shop.admin.import_backup"),  # S7
        ("template_injection", "shop/admin.py", "shop.admin.mail_preview"),  # S8
        ("path_traversal", "shop/admin.py", "shop.admin.upload_image"),  # S9
    },
    "user-center": {
        ("idor", "app.py", "app.user_profile"),  # U1
        ("missing_auth", "app.py", "app.export_users"),  # U2
        ("hardcoded_secret", "auth.py", "auth"),  # U3
    },
}


def analyze(name: str):
    index = ProjectIndex(TARGETS / name)
    facts = collect_flask_facts(index)
    candidates, _ = collect_candidates(index, facts)
    return facts, candidates


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_target_findings_match_design_list(name: str) -> None:
    _, candidates = analyze(name)
    assert {(c.category, c.file, c.function) for c in candidates} == EXPECTED[name]


def test_shop_admin_facts_and_routes() -> None:
    facts, candidates = analyze("shop-admin")
    assert facts["entry"] == {"kind": "run", "module": "app", "file": "app.py", "line": facts["entry"]["line"],
                              "app": "app:app", "port": 5000, "debug": True}  # fmt: skip
    assert facts["auth"]["login"]["fields"] == ["username", "password"]
    assert facts["password_storage"]["kind"] == "unsalted_hash" and facts["session"]["flask_session"]
    access = {r["path"]: r["access"] for r in facts["routes"]}
    assert access["/orders/search"] == "anonymous" and access["/admin/backup/import"] == "admin"
    by_route = {c.route["path"]: c for c in candidates if c.route}
    # S1 是匿名可达的注入，后台漏洞都要求管理员身份，供攻击路径推演使用
    assert by_route["/orders/search"].route["access"] == "anonymous"
    assert {by_route[p].route["access"] for p in by_route if p.startswith("/admin/")} == {"admin"}


def test_user_center_facts() -> None:
    facts, _ = analyze("user-center")
    assert set(facts["auth"]["register"]["fields"]) >= {"username", "password"}
    assert facts["auth"]["login"]["content"] == "json"
    assert facts["password_storage"]["kind"] == "salted_hash" and facts["session"]["jwt"]
    assert {r["path"]: r["access"] for r in facts["routes"]}["/api/orders/<int:order_id>"] == "user"
