"""验证用例模板：参数定位、列数推断、种子账号、用例生成与命中判定。"""

from __future__ import annotations

import re
from types import SimpleNamespace
from pathlib import Path

from app.models.enums import Category
from app.project.flask_facts import collect_flask_facts
from app.project.pysource import ProjectIndex
from app.pipeline.agents.audit import collect_candidates
from app.verify.accounts import find_seed_accounts
from app.verify.cases import (
    AuthInfo,
    build_cases,
    evaluate,
    hardcoded_secret_values,
)
from app.verify.params import extract_params, select_columns

TARGETS = Path(__file__).resolve().parents[2] / "targets"


def target(name: str) -> tuple[ProjectIndex, dict]:
    index = ProjectIndex(TARGETS / name)
    return index, collect_flask_facts(index)


def findings_and_steps(name: str) -> tuple[list[dict], ProjectIndex, dict]:
    index, facts = target(name)
    candidates, _ = collect_candidates(index, facts)
    findings = [
        {
            "id": number,
            "code": f"T-{number}",
            "category": cand.category,
            "severity": "high",
            "file": cand.file,
            "line": cand.line,
            "route": cand.route,
            "steps": [
                {"file": s.file, "line": s.line, "snippet": s.snippet, "note": s.note} for s in cand.steps
            ],
        }
        for number, cand in enumerate(candidates)
    ]
    return findings, index, facts


def build(name: str, auth: AuthInfo) -> tuple[list, list[tuple[dict, str]], ProjectIndex, dict]:
    findings, index, facts = findings_and_steps(name)
    cases, skipped = build_cases(
        findings,
        {item["id"]: item["steps"] for item in findings},
        index,
        facts,
        auth,
        hardcoded_secret_values(index),
    )
    return cases, skipped, index, facts


def test_extract_params_from_taint_steps() -> None:
    params = extract_params(
        'host = request.form.get("host", "")\nbackup = request.files["backup"]\n'
        'q = request.args.get("q", "")\ndata = request.get_json()\nname = data.get("name")',
        "/users/<int:user_id>",
    )
    assert params.form == ["host"]
    assert params.files == ["backup"]
    assert params.query == ["q"]
    assert params.json == ["name"]
    assert params.path == ["user_id"]


def test_select_columns_handles_nested_expressions() -> None:
    assert select_columns('sql = f"SELECT id, customer, product_id, amount, status FROM orders"') == 5
    assert select_columns('SELECT coalesce(a, b), c FROM t') == 2
    assert select_columns("DELETE FROM t") is None


def test_seed_accounts_are_recognised() -> None:
    index, _ = target("shop-admin")
    accounts = find_seed_accounts(index)
    assert accounts[0].username == "admin" and accounts[0].admin is True
    assert {a.username: a.admin for a in accounts}["operator"] is False

    index, _ = target("user-center")
    assert {a.username for a in find_seed_accounts(index)} == {"alice", "bob"}


def test_shop_admin_cases_cover_expected_categories() -> None:
    auth = AuthInfo(admin={"Cookie": "session=admin"}, user=None)
    cases, skipped, _index, _facts = build("shop-admin", auth)
    by_category = {case.category: case for case in cases}
    assert set(by_category) == {
        Category.SQL_INJECTION,
        Category.CONFIG_EXPOSURE,
        Category.DEBUG_MODE,
        Category.COMMAND_INJECTION,
        Category.TEMPLATE_INJECTION,
        Category.DESERIALIZATION,
        Category.PATH_TRAVERSAL,
    }
    assert {finding["category"] for finding, _reason in skipped} == {
        Category.HARDCODED_SECRET,
        Category.WEAK_PASSWORD_STORAGE,
    }
    sql = by_category[Category.SQL_INJECTION].requests[0]
    assert sql["query"]["keyword"].count(",") == 4  # 按原查询的 5 列凑 UNION
    assert by_category[Category.PATH_TRAVERSAL].requests[0]["path"] == "/admin/products/1/image"
    assert by_category[Category.COMMAND_INJECTION].requests[0]["headers"] == {"Cookie": "session=admin"}


def test_shop_admin_admin_cases_are_skipped_without_login() -> None:
    cases, skipped, _index, _facts = build("shop-admin", AuthInfo())
    assert {case.category for case in cases} == {
        Category.SQL_INJECTION,
        Category.CONFIG_EXPOSURE,
        Category.DEBUG_MODE,
    }
    admin_skips = [finding for finding, reason in skipped if reason == "未获得管理员登录态"]
    assert {finding["category"] for finding in admin_skips} == {
        Category.COMMAND_INJECTION,
        Category.TEMPLATE_INJECTION,
        Category.DESERIALIZATION,
        Category.PATH_TRAVERSAL,
    }


def test_user_center_cases_and_hit_rules() -> None:
    auth = AuthInfo(user={"Authorization": "Bearer a"}, peer_id=7, peer_marker="b123")
    cases, skipped, _index, _facts = build("user-center", auth)
    by_category = {case.category: case for case in cases}
    idor = by_category[Category.IDOR].requests[0]
    assert idor["path"] == "/api/users/7"
    assert idor["headers"] == {"Authorization": "Bearer a"}
    assert [f["category"] for f, _reason in skipped] == [Category.HARDCODED_SECRET]


def test_evaluate_hit_rules() -> None:
    hit = SimpleNamespace(
        body='{"version":"3.40.1"}',
        files_exist={"/tmp/A": True},
        found=["/work/app/static/upload.txt", "/work/app/static/uploads/upload.txt"],
    )
    assert evaluate([{"kind": "contains", "value": "3.40.1"}], hit) == "3.40.1"
    assert evaluate([{"kind": "regex", "pattern": r"3\.\d+\.\d+"}], hit) == "3.40.1"
    assert evaluate([{"kind": "file", "path": "/tmp/A"}], hit) is not None
    matched = evaluate([{"kind": "found_outside", "dirs": ["uploads"]}], hit)
    assert matched is not None and "upload.txt" in matched
    assert evaluate([{"kind": "contains", "value": "nope"}], hit) is None


def test_hardcoded_secret_values() -> None:
    index, _ = target("shop-admin")
    values = hardcoded_secret_values(index)
    assert ("SECRET_KEY", "shop-admin-dev-secret-2024") in values
    index, _ = target("user-center")
    assert any(value == "user-center-signing-key-2024" for _name, value in hardcoded_secret_values(index))


def test_real_marker_hits_expected_text() -> None:
    auth = AuthInfo(admin={"Cookie": "session=admin"})
    cases, _skipped, _index, _facts = build("shop-admin", auth)
    sql = next(case for case in cases if case.category == Category.SQL_INJECTION)
    payload = sql.requests[0]["query"]["keyword"]
    token = re.search(r"'([0-9A-F]{10})'\|\|sqlite_version", payload).group(1)
    result = SimpleNamespace(body=f"{token}3.40.1", files_exist={}, found=[])
    assert evaluate(sql.rules, result) is not None
    assert evaluate(sql.rules, SimpleNamespace(body="3.40.1", files_exist={}, found=[])) is None
