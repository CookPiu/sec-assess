"""敏感信息规则（FR-007、DESIGN.md 5.2 第 3 条）：硬编码密钥、调试模式、配置暴露、弱密码存储。"""

from __future__ import annotations

import ast
import re
from typing import Any

from app.models.enums import Category
from app.project.flask_facts import access_rank
from app.project.pysource import ModuleInfo, ProjectIndex, call_name, const_str, dotted, is_true, keyword
from app.taint.model import Candidate, Step

SECRET_NAME = re.compile(r"secret|passw(?:or)?d|token|api_?key|private_?key|signing_?key", re.IGNORECASE)
MIN_SECRET_LEN = 8
CONFIG_OBJECTS = ("app.config", "current_app.config", "config")


def _step(index: ProjectIndex, file: str, line: int, note: str) -> Step:
    return Step(file, line, index.snippet(file, line), note)


def _target_name(target: ast.expr) -> str | None:
    if isinstance(target, ast.Name):
        return target.id
    if isinstance(target, ast.Attribute):
        return target.attr
    if isinstance(target, ast.Subscript):
        return const_str(target.slice)
    return None


def _hardcoded_secrets(index: ProjectIndex, mod: ModuleInfo) -> list[Candidate]:
    found: list[Candidate] = []

    def add(line: int, name: str) -> None:
        found.append(
            Candidate(
                Category.HARDCODED_SECRET, mod.file, line, mod.name, f"{name} 以明文写在源码中",
                [_step(index, mod.file, line, f"{name} 赋值为字符串常量")],
            )
        )

    for node in ast.walk(mod.tree):
        if isinstance(node, ast.Assign):
            value = const_str(node.value)
            if value is None or len(value) < MIN_SECRET_LEN:
                continue
            for target in node.targets:
                name = _target_name(target)
                if name and SECRET_NAME.search(name):
                    add(node.lineno, name)
        elif isinstance(node, ast.Call):
            name = dotted(node.func)
            if name in ("jwt.encode", "jwt.decode") and len(node.args) > 1:
                value = const_str(node.args[1])
                if value and len(value) >= MIN_SECRET_LEN:
                    add(node.lineno, f"{name} 的签名密钥")
            elif call_name(node) == "update" and name.endswith("config.update"):
                for kw in node.keywords:
                    value = const_str(kw.value)
                    if kw.arg and SECRET_NAME.search(kw.arg) and value and len(value) >= MIN_SECRET_LEN:
                        add(node.lineno, kw.arg)
    return found


def _debug_mode(index: ProjectIndex, mod: ModuleInfo, facts: dict[str, Any]) -> list[Candidate]:
    found: list[Candidate] = []
    entry = facts.get("entry") or {}
    if entry.get("debug") and entry.get("file") == mod.file:
        found.append(
            Candidate(
                Category.DEBUG_MODE, mod.file, entry["line"], mod.name, "以 debug=True 启动，异常时暴露 Werkzeug 调试页",
                [_step(index, mod.file, entry["line"], "app.run(debug=True)")],
            )
        )
    for node in ast.walk(mod.tree):
        if isinstance(node, ast.Assign) and is_true(node.value):
            for target in node.targets:
                name = _target_name(target)
                if name in ("DEBUG", "debug"):
                    found.append(
                        Candidate(
                            Category.DEBUG_MODE, mod.file, node.lineno, mod.name, "配置中开启了调试模式",
                            [_step(index, mod.file, node.lineno, f"{name} = True")],
                        )
                    )
    return found


def _config_exposure(index: ProjectIndex, routes: list[dict[str, Any]]) -> list[Candidate]:
    """路由处理函数把整个配置对象或密钥类配置项返回给调用方。"""
    found: list[Candidate] = []
    for route in routes:
        fn = index.functions.get((route["module"], route["handler"]))
        if fn is None or fn.node.lineno != route["line"]:
            continue
        for node in ast.walk(fn.node):
            if not isinstance(node, ast.Return) or node.value is None:
                continue
            hit = None
            for sub in ast.walk(node.value):
                text = dotted(sub)
                if isinstance(sub, ast.Attribute | ast.Name) and text in CONFIG_OBJECTS:
                    hit = text
                elif isinstance(sub, ast.Subscript) and dotted(sub.value) in CONFIG_OBJECTS:
                    key = const_str(sub.slice)
                    if key and SECRET_NAME.search(key):
                        hit = f"{dotted(sub.value)}['{key}']"
                if hit:
                    break
            if hit:
                found.append(
                    Candidate(
                        Category.CONFIG_EXPOSURE, fn.file, node.lineno, fn.qualname,
                        f"接口返回了 {hit}，可能泄露应用密钥",
                        [
                            _step(index, fn.file, fn.node.lineno, f"路由 {' / '.join(route['methods'])} {route['path']}"),
                            _step(index, fn.file, node.lineno, f"响应中包含 {hit}"),
                        ],
                        route={"path": route["path"], "methods": route["methods"], "access": route["access"]},
                        functions=[fn.qualname],
                    )
                )
                break
    # 管理员才能访问的配置接口不算暴露
    return [c for c in found if c.route and access_rank(c.route["access"]) < access_rank("admin")]


def _weak_password(index: ProjectIndex, facts: dict[str, Any]) -> list[Candidate]:
    storage = facts.get("password_storage") or {}
    kind = storage.get("kind")
    if kind not in ("unsalted_hash", "plaintext") or not storage.get("file"):
        return []
    file, line = storage["file"], storage["line"]
    message = "密码使用无盐哈希存储" if kind == "unsalted_hash" else "密码以明文存储"
    note = f"使用 {storage.get('detail')} 计算密码哈希" if kind == "unsalted_hash" else "密码字段未做哈希"
    module = index.module_by_file(file)
    return [
        Candidate(Category.WEAK_PASSWORD_STORAGE, file, line, module.name if module else file, message,
                  [_step(index, file, line, note)])  # fmt: skip
    ]


def find_secret_candidates(index: ProjectIndex, facts: dict[str, Any]) -> list[Candidate]:
    found: list[Candidate] = []
    for mod in index.modules.values():
        found += _hardcoded_secrets(index, mod)
        found += _debug_mode(index, mod, facts)
    found += _config_exposure(index, facts.get("routes") or [])
    found += _weak_password(index, facts)
    unique: dict[tuple[str, str, int], Candidate] = {}
    for cand in found:
        unique.setdefault(cand.key, cand)
    return list(unique.values())
