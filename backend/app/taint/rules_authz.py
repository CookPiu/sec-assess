"""鉴权类规则（FR-007、DESIGN.md 5.2 第 2 条）。

- 越权（IDOR）：需要登录的路由带资源 ID 参数，处理函数用它查询数据，却没有按当前用户过滤或比对。
- 缺失鉴权：匿名可访问的路由查询并返回用户类数据，且不是注册、登录这类公开接口。
管理员才能访问的路由不在这两条规则的范围内。
"""

from __future__ import annotations

import ast
import re
from typing import Any

from app.models.enums import Category
from app.project.flask_facts import ACCESS_LABELS
from app.project.pysource import FunctionInfo, ProjectIndex, call_name, dotted
from app.taint.model import Candidate, Step

ID_PARAM = re.compile(r"^(?:id|uid|pk)$|_id$|Id$")
QUERY_CALLS = {"get", "get_or_404", "filter_by", "filter", "first", "first_or_404", "one", "execute", "where", "query"}
# 处理函数里出现这些写法，视为按当前用户做了过滤或比对
OWNER_CHECK = re.compile(
    r"current_user|g\.user|session\s*\[|session\.get|get_jwt_identity|request\.user|owner_id|\bidentity\b"
)
USER_DATA = re.compile(r"\b(?:User|Users|Account|Member|Customer|Profile)\b|\b(?:users|accounts|members|customers|profiles)\b")
PUBLIC_ROUTE = re.compile(r"login|logout|register|signup|sign_up|signin|health|static|captcha", re.IGNORECASE)


def _route_info(route: dict[str, Any]) -> dict[str, Any]:
    return {"path": route["path"], "methods": route["methods"], "access": route["access"]}


def _query_using(fn: ast.AST, name: str) -> ast.Call | None:
    """找到把 name 作为参数（含关键字参数和比较表达式）的数据查询调用。"""
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        if call_name(node) not in QUERY_CALLS and "query" not in dotted(node.func):
            continue
        for arg in [*node.args, *(kw.value for kw in node.keywords)]:
            if any(isinstance(n, ast.Name) and n.id == name for n in ast.walk(arg)):
                return node
    return None


def _owner_checked(index: ProjectIndex, fn: FunctionInfo) -> bool:
    """处理函数或它直接调用的工程内函数（如 get_post(id) 里比对作者）出现当前用户比对，视为做了归属校验。"""
    if OWNER_CHECK.search(index.function_source(fn)):
        return True
    for node in ast.walk(fn.node):
        if isinstance(node, ast.Call):
            target = index.resolve_call(fn.module, node.func)
            if target is not None and target is not fn and OWNER_CHECK.search(index.function_source(target)):
                return True
    return False


def find_authz_candidates(index: ProjectIndex, routes: list[dict[str, Any]]) -> list[Candidate]:
    found: list[Candidate] = []
    for route in routes:
        if route["access"] == "admin":
            continue
        fn = index.functions.get((route["module"], route["handler"]))
        if fn is None or fn.node.lineno != route["line"]:
            continue
        method_path = f"{' / '.join(route['methods'])} {route['path']}"
        route_step = Step(fn.file, fn.node.lineno, index.snippet(fn.file, fn.node.lineno),
                          f"路由 {method_path}，访问前提：{ACCESS_LABELS[route['access']]}")  # fmt: skip

        idor = False
        # 越权指登录用户访问他人的资源；匿名路由走下面的缺失鉴权检查
        for param in route["params"] if route["access"] == "user" else []:
            if not ID_PARAM.search(param) or param not in fn.params:
                continue
            query = _query_using(fn.node, param)
            if query is None or _owner_checked(index, fn):
                continue
            idor = True
            found.append(
                Candidate(
                    Category.IDOR, fn.file, query.lineno, fn.qualname,
                    f"按 URL 参数 {param} 查询资源，未比对当前用户",
                    [route_step, Step(fn.file, query.lineno, index.snippet(fn.file, query.lineno),
                                      f"直接用 {param} 查询，没有按当前用户过滤")],  # fmt: skip
                    route=_route_info(route),
                    functions=[fn.qualname],
                )
            )
            break

        if idor or route["access"] != "anonymous" or PUBLIC_ROUTE.search(route["path"] + " " + route["handler"]):
            continue
        query = next(
            (n for n in ast.walk(fn.node) if isinstance(n, ast.Call) and USER_DATA.search(ast.unparse(n))
             and (call_name(n) in QUERY_CALLS or "query" in dotted(n.func) or "select" in ast.unparse(n).lower())),
            None,
        )  # fmt: skip
        if query is None:
            continue
        found.append(
            Candidate(
                Category.MISSING_AUTH, fn.file, query.lineno, fn.qualname,
                "匿名可访问的接口查询并返回用户数据",
                [route_step, Step(fn.file, query.lineno, index.snippet(fn.file, query.lineno), "查询用户数据，无登录校验")],
                route=_route_info(route),
                functions=[fn.qualname],
            )
        )
    return found
