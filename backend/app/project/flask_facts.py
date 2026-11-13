"""侦察：Flask 路由表与后续阶段要用的事实（DESIGN.md 5.1、FR-002）。

- 路由：URL、方法、处理函数、装饰器、URL 参数，以及访问前提（匿名 / 普通用户 / 管理员）。
- 启动方式：app.run 所在模块与端口，或 create_app 工厂。
- 注册与登录接口读取的字段名，供验证阶段自动注册测试账号。
- 密码存储方式（明文 / 无盐哈希 / 加盐哈希）与会话方式。
"""

from __future__ import annotations

import ast
import re
from dataclasses import asdict, dataclass, field
from typing import Any

from app.project.pysource import ProjectIndex, call_name, const_str, dotted, is_true, keyword

ROUTE_METHODS = {"route", "get", "post", "put", "delete", "patch"}
USER_DECORATORS = {
    "login_required", "fresh_login_required", "jwt_required", "token_required",
    "auth_required", "require_login", "authenticated",
}  # fmt: skip
ADMIN_DECORATORS = {
    "admin_required", "roles_required", "role_required", "superuser_required",
    "permission_required", "requires_admin", "admin_only",
}  # fmt: skip
ACCESS_LEVELS = ("anonymous", "user", "admin")
ACCESS_LABELS = {"anonymous": "匿名", "user": "普通用户", "admin": "管理员"}

# 拦截分支的判断条件里出现这些词，分别视为管理员校验和登录校验
_ADMIN_CHECK = re.compile(r"admin|superuser", re.IGNORECASE)
_USER_CHECK = re.compile(r"session|current_user|token|auth|login|user_id|g\.user|jwt", re.IGNORECASE)
# 分支体里出现这些写法视为拒绝访问
_DENY = re.compile(r"abort\(\s*40[13]|\b40[13]\b|redirect\(|Unauthorized|Forbidden|raise\s")
_URL_PARAM = re.compile(r"<(?:[a-zA-Z_]+:)?([a-zA-Z_][a-zA-Z0-9_]*)>")
_PASSWORD_NAME = re.compile(r"passw(?:or)?d|pwd|\bpw\b", re.IGNORECASE)
_REGISTER = re.compile(r"register|signup|sign_up", re.IGNORECASE)
_LOGIN = re.compile(r"login|signin|sign_in", re.IGNORECASE)
UNSALTED_HASHES = {"md5", "sha1", "sha224", "sha256", "sha384", "sha512"}
SALTED_HASH_CALLS = {"generate_password_hash", "hashpw", "pbkdf2_hmac", "scrypt", "PasswordHasher", "CryptContext"}
REQUEST_CONTAINERS = {"request.form", "request.json", "request.values", "request.args", "request.get_json()"}


def access_rank(level: str) -> int:
    return ACCESS_LEVELS.index(level)


def guard_level(fn: ast.AST, text: str) -> str:
    """找函数里“条件不满足就拒绝”的分支：if 条件涉及管理员判断为 admin，涉及登录态为 user；
    try 里解码令牌、except 里拒绝的写法也算登录校验。"""
    level = "anonymous"
    for node in ast.walk(fn):
        if isinstance(node, ast.If):
            test = ast.get_source_segment(text, node.test) or ""
            body = "\n".join(ast.get_source_segment(text, s) or "" for s in node.body)
            if not _DENY.search(body):
                continue
            if _ADMIN_CHECK.search(test):
                return "admin"
            if _USER_CHECK.search(test):
                level = "user"
        elif isinstance(node, ast.Try):
            body = "\n".join(ast.get_source_segment(text, s) or "" for s in node.body)
            handlers = "\n".join(ast.get_source_segment(text, h) or "" for h in node.handlers)
            if _USER_CHECK.search(body) and _DENY.search(handlers):
                level = "user"
    return level


@dataclass
class Route:
    path: str
    methods: list[str]
    module: str
    handler: str
    file: str
    line: int
    decorators: list[str]
    params: list[str]
    access: str = "anonymous"
    # 路由所属对象（Flask 应用或蓝图），用于 before_request 判断
    owner: tuple[str, str] | None = field(default=None, repr=False)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data.pop("owner")
        return data


class FlaskFacts:
    def __init__(self, index: ProjectIndex) -> None:
        self.index = index
        self.apps: dict[tuple[str, str], int] = {}  # (模块, 变量名) → 行号
        self.blueprints: dict[tuple[str, str], str] = {}  # (模块, 变量名) → url_prefix
        self.routes: list[Route] = []

    # ---------- 路由 ----------

    def _owner_key(self, module: str, var: str) -> tuple[str, str]:
        target, attr = self.index.resolve_symbol(module, var)
        return (target, attr) if attr else (module, var)

    def _collect_objects(self) -> None:
        for mod in self.index.modules.values():
            for node in ast.walk(mod.tree):
                if not (isinstance(node, ast.Assign) and isinstance(node.value, ast.Call)):
                    continue
                ctor = call_name(node.value)
                for target in node.targets:
                    if not isinstance(target, ast.Name):
                        continue
                    if ctor == "Flask":
                        self.apps[(mod.name, target.id)] = node.lineno
                    elif ctor == "Blueprint":
                        self.blueprints[(mod.name, target.id)] = const_str(keyword(node.value, "url_prefix")) or ""

    def _registered_prefixes(self) -> dict[tuple[str, str], str]:
        prefixes: dict[tuple[str, str], str] = {}
        for mod in self.index.modules.values():
            for node in ast.walk(mod.tree):
                if not (isinstance(node, ast.Call) and call_name(node) == "register_blueprint" and node.args):
                    continue
                prefix = const_str(keyword(node, "url_prefix"))
                if prefix is None:
                    continue
                arg = node.args[0]
                if isinstance(arg, ast.Name):
                    prefixes[self._owner_key(mod.name, arg.id)] = prefix
                elif isinstance(arg, ast.Attribute) and isinstance(arg.value, ast.Name):
                    target, attr = self.index.resolve_symbol(mod.name, arg.value.id)
                    if attr is None:
                        prefixes[(target, arg.attr)] = prefix
        return prefixes

    def _decorator_level(self, module: str, dec: ast.expr) -> tuple[str, str]:
        """返回（装饰器名，访问前提）。工程内自定义的装饰器按其源码判断。"""
        func = dec.func if isinstance(dec, ast.Call) else dec
        name = dotted(func).split(".")[-1]
        if name in ADMIN_DECORATORS:
            return name, "admin"
        if name in USER_DECORATORS:
            return name, "user"
        fn = self.index.resolve_call(module, func)
        if fn is not None:
            return name, guard_level(fn.node, self.index.modules[fn.module].text)
        return name, "anonymous"

    def _before_request_levels(self) -> dict[tuple[str, str] | None, str]:
        """蓝图或应用上 before_request 钩子的拦截级别；键为 None 表示作用于全部路由的应用级钩子。"""
        levels: dict[tuple[str, str] | None, str] = {}
        for mod in self.index.modules.values():
            for node in ast.walk(mod.tree):
                if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                    continue
                for dec in node.decorator_list:
                    if not (isinstance(dec, ast.Attribute) and dec.attr == "before_request"):
                        continue
                    if not isinstance(dec.value, ast.Name):
                        continue
                    key = self._owner_key(mod.name, dec.value.id)
                    level = guard_level(node, mod.text)
                    scope = None if key in self.apps else key
                    if access_rank(level) > access_rank(levels.get(scope, "anonymous")):
                        levels[scope] = level
        return levels

    def _add_route(self, mod_name: str, file: str, fn: ast.FunctionDef | ast.AsyncFunctionDef, path: str,
                   methods: list[str], owner: tuple[str, str]) -> None:  # fmt: skip
        decorators: list[str] = []
        level = "anonymous"
        for dec in fn.decorator_list:
            name, dec_level = self._decorator_level(mod_name, dec)
            decorators.append(name)
            if access_rank(dec_level) > access_rank(level):
                level = dec_level
        body_level = guard_level(fn, self.index.modules[mod_name].text)
        if access_rank(body_level) > access_rank(level):
            level = body_level
        self.routes.append(
            Route(path, methods, mod_name, fn.name, file, fn.lineno, decorators, _URL_PARAM.findall(path), level, owner)
        )

    def _collect_routes(self) -> None:
        prefixes = self._registered_prefixes()
        for mod in self.index.modules.values():
            functions = {
                n.name: n for n in ast.walk(mod.tree) if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)
            }
            for node in ast.walk(mod.tree):
                if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                    for dec in node.decorator_list:
                        if not (isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute)):
                            continue
                        if dec.func.attr not in ROUTE_METHODS or not isinstance(dec.func.value, ast.Name):
                            continue
                        rule = const_str(dec.args[0]) if dec.args else const_str(keyword(dec, "rule"))
                        if rule is None:
                            continue
                        owner = self._owner_key(mod.name, dec.func.value.id)
                        if owner not in self.apps and owner not in self.blueprints:
                            continue
                        if dec.func.attr == "route":
                            methods = _str_list(keyword(dec, "methods")) or ["GET"]
                        else:
                            methods = [dec.func.attr.upper()]
                        prefix = prefixes.get(owner, self.blueprints.get(owner, ""))
                        self._add_route(mod.name, mod.file, node, _join(prefix, rule), methods, owner)
                elif isinstance(node, ast.Call) and call_name(node) == "add_url_rule" and node.args:
                    view = keyword(node, "view_func")
                    rule = const_str(node.args[0])
                    if rule is None or not isinstance(view, ast.Name) or view.id not in functions:
                        continue
                    if not (isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name)):
                        continue
                    owner = self._owner_key(mod.name, node.func.value.id)
                    prefix = prefixes.get(owner, self.blueprints.get(owner, ""))
                    methods = _str_list(keyword(node, "methods")) or ["GET"]
                    self._add_route(mod.name, mod.file, functions[view.id], _join(prefix, rule), methods, owner)

        hooks = self._before_request_levels()
        for route in self.routes:
            for scope in (None, route.owner):
                level = hooks.get(scope)
                if level and access_rank(level) > access_rank(route.access):
                    route.access = level
        self.routes.sort(key=lambda r: (r.path, r.file, r.line))

    # ---------- 启动方式 ----------

    def _entry(self) -> dict[str, Any] | None:
        for mod in self.index.modules.values():
            for node in ast.walk(mod.tree):
                if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
                    continue
                if node.func.attr != "run" or not isinstance(node.func.value, ast.Name):
                    continue
                key = self._owner_key(mod.name, node.func.value.id)
                if key not in self.apps:
                    continue
                port_node = keyword(node, "port")
                port = port_node.value if isinstance(port_node, ast.Constant) and isinstance(port_node.value, int) else 5000
                debug = keyword(node, "debug")
                return {
                    "kind": "run",
                    "module": mod.name,
                    "file": mod.file,
                    "line": node.lineno,
                    "app": f"{key[0]}:{key[1]}",
                    "port": port,
                    "debug": is_true(debug),
                }
        for (module, name), fn in self.index.functions.items():
            if name in ("create_app", "make_app") and "Flask(" in self.index.function_source(fn):
                return {"kind": "factory", "module": module, "file": fn.file, "line": fn.node.lineno,
                        "app": f"{module}:{name}()", "port": 5000, "debug": False}  # fmt: skip
        if self.apps:
            (module, var), line = next(iter(self.apps.items()))
            mod = self.index.modules[module]
            return {"kind": "app", "module": module, "file": mod.file, "line": line, "app": f"{module}:{var}",
                    "port": 5000, "debug": False}  # fmt: skip
        return None

    # ---------- 注册与登录 ----------

    def _request_fields(self, route: Route) -> tuple[list[str], str]:
        mod = self.index.modules[route.module]
        fn = next(
            n for n in ast.walk(mod.tree)
            if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef) and n.name == route.handler and n.lineno == route.line
        )  # fmt: skip
        aliases = set(REQUEST_CONTAINERS)
        for node in ast.walk(fn):
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                value = node.value.values[0] if isinstance(node.value, ast.BoolOp) else node.value
                if dotted(value) in REQUEST_CONTAINERS:
                    aliases.add(node.targets[0].id)
        fields: list[str] = []
        for node in ast.walk(fn):
            container, key = None, None
            if isinstance(node, ast.Subscript):
                container, key = dotted(node.value), const_str(node.slice)
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "get":
                container, key = dotted(node.func.value), const_str(node.args[0]) if node.args else None
            if container in aliases and key and key not in fields:
                fields.append(key)
        source = ast.unparse(fn)
        uses_json = "request.json" in source or "get_json" in source
        return fields, "json" if uses_json else "form"

    def _auth_endpoints(self) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for kind, pattern in (("register", _REGISTER), ("login", _LOGIN)):
            for route in self.routes:
                if "POST" not in route.methods or not (pattern.search(route.path) or pattern.search(route.handler)):
                    continue
                fields, content = self._request_fields(route)
                if fields:
                    result[kind] = {"path": route.path, "method": "POST", "fields": fields, "content": content}
                    break
        return result

    # ---------- 密码与会话 ----------

    def _password_storage(self) -> dict[str, Any]:
        evidence: list[dict[str, Any]] = []
        password_columns: list[dict[str, Any]] = []
        for mod in self.index.modules.values():
            for node in ast.walk(mod.tree):
                if isinstance(node, ast.Call):
                    name = call_name(node)
                    line = mod.lines[node.lineno - 1] if node.lineno <= len(mod.lines) else ""
                    base = dotted(node.func)
                    if base.startswith("hashlib.") and name in UNSALTED_HASHES and _PASSWORD_NAME.search(line):
                        kind = "salted_hash" if "salt" in line.lower() else "unsalted_hash"
                        evidence.append({"kind": kind, "file": mod.file, "line": node.lineno, "detail": f"hashlib.{name}"})
                    elif name in SALTED_HASH_CALLS:
                        evidence.append({"kind": "salted_hash", "file": mod.file, "line": node.lineno, "detail": name})
                elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Call) and call_name(node.value) == "Column":
                    for target in node.targets:
                        if isinstance(target, ast.Name) and target.id.lower() in ("password", "passwd", "pwd"):
                            password_columns.append({"file": mod.file, "line": node.lineno})
        weak = [e for e in evidence if e["kind"] == "unsalted_hash"]
        if weak:
            return {**weak[0], "evidence": evidence}
        if evidence:
            return {**evidence[0], "evidence": evidence}
        if password_columns:
            return {"kind": "plaintext", **password_columns[0], "detail": "密码字段未发现任何哈希处理", "evidence": []}
        return {"kind": "unknown", "evidence": []}

    def _session(self) -> dict[str, bool]:
        """flask_session 为真表示登录态保存在 Flask 签名 Cookie 里（含 Flask-Login），拿到 SECRET_KEY 即可伪造。"""
        imported = [pair for mod in self.index.modules.values() for pair in mod.imports.values()]
        flask_login = any(target.startswith("flask_login") for target, _ in imported)
        flask_session = any(target == "flask" and attr == "session" for target, attr in imported)
        uses_jwt = any(target == "jwt" for target, _ in imported)
        return {"flask_session": flask_session or flask_login, "flask_login": flask_login, "jwt": uses_jwt}

    def collect(self) -> dict[str, Any]:
        self._collect_objects()
        self._collect_routes()
        return {
            "is_flask": bool(self.apps),
            "entry": self._entry(),
            "routes": [r.to_dict() for r in self.routes],
            "auth": self._auth_endpoints(),
            "password_storage": self._password_storage(),
            "session": self._session(),
            "parse_errors": self.index.errors,
        }


def _str_list(node: ast.AST | None) -> list[str]:
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return [v.upper() for v in (const_str(e) for e in node.elts) if v]
    return []


def _join(prefix: str, rule: str) -> str:
    if not prefix:
        return rule
    return prefix.rstrip("/") + "/" + rule.lstrip("/") if rule != "/" else prefix.rstrip("/") or "/"


def collect_flask_facts(index: ProjectIndex) -> dict[str, Any]:
    return FlaskFacts(index).collect()
