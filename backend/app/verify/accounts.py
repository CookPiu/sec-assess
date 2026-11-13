"""测试账号：从源码种子数据里识别登录账号，并为自动注册生成字段值（DESIGN.md 5.3）。

管理类路由需要管理员登录态。工程通常会在源码里写入种子账号（如 SEED_USERS），
验证阶段把这些字符串常量识别出来用于登录；识别不到或登录失败时相关候选保持疑似。
普通用户在工程提供注册接口时现注册，不依赖种子账号。
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass

from app.project.pysource import ProjectIndex

_SEED_NAME = re.compile(r"user|account|admin|login|seed|member", re.IGNORECASE)
_USER_FIELD = re.compile(r"user|login|name|account", re.IGNORECASE)
_PASSWORD_FIELD = re.compile(r"pass|pwd", re.IGNORECASE)
_EMAIL_FIELD = re.compile(r"mail", re.IGNORECASE)
_PHONE_FIELD = re.compile(r"phone|mobile", re.IGNORECASE)
_ADDRESS_FIELD = re.compile(r"address|addr|city", re.IGNORECASE)
MIN_PASSWORD_LEN = 6
MAX_ACCOUNTS = 20


@dataclass(frozen=True)
class SeedAccount:
    username: str
    password: str
    admin: bool


def _text(node: ast.AST | None) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _row_account(item: ast.AST) -> SeedAccount | None:
    if isinstance(item, ast.Tuple | ast.List):
        values = list(item.elts)
        strings = [v.value.strip() for v in values if _text(v) is not None]
        if len(strings) < 2:
            return None
        username, password = strings[0], strings[1]
        admin = "admin" in username.lower() or any(
            isinstance(v, ast.Constant) and (v.value is True or v.value == 1) for v in values[2:]
        )
    elif isinstance(item, ast.Dict):
        fields = {
            key.value: value
            for key, value in zip(item.keys, item.values)
            if _text(key) is not None
        }
        username = next((_text(v) or "" for k, v in fields.items() if _USER_FIELD.search(str(k))), "").strip()
        password = next((_text(v) or "" for k, v in fields.items() if _PASSWORD_FIELD.search(str(k))), "").strip()
        admin = any(
            isinstance(k, str) and k.lower() in ("admin", "is_admin")
            and isinstance(v, ast.Constant) and (v.value is True or v.value == 1)
            for k, v in fields.items()
        ) or "admin" in username.lower()
    else:
        return None
    if not username or len(username) > 64 or len(password) < MIN_PASSWORD_LEN or len(password) > 128:
        return None
    if any(c in username + password for c in "\n\r\t"):
        return None
    return SeedAccount(username, password, admin)


def find_seed_accounts(index: ProjectIndex) -> list[SeedAccount]:
    """模块级列表里的账号行，形如 SEED_USERS = [("admin", "admin123", 1), ...]。"""
    accounts: dict[str, SeedAccount] = {}
    for module in index.modules.values():
        for node in ast.walk(module.tree):
            targets: list[ast.expr] = []
            value = None
            if isinstance(node, ast.Assign):
                targets, value = node.targets, node.value
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                targets, value = [node.target], node.value
            if value is None or not any(
                isinstance(t, ast.Name) and _SEED_NAME.search(t.id) for t in targets
            ):
                continue
            if not isinstance(value, ast.List | ast.Tuple):
                continue
            for item in value.elts:
                account = _row_account(item)
                if account is not None:
                    accounts.setdefault(account.username, account)
    ordered = sorted(accounts.values(), key=lambda a: (not a.admin, a.username))
    return ordered[:MAX_ACCOUNTS]


def field_values(fields: list[str], *, username: str, password: str, marker: str) -> dict[str, str]:
    """按字段名填值；未知字段用随机标记，保证必填项不为空。"""
    values: dict[str, str] = {}
    for field in fields:
        if _PASSWORD_FIELD.search(field):
            values[field] = password
        elif _EMAIL_FIELD.search(field):
            values[field] = f"{marker.lower()}@example.test"
        elif _PHONE_FIELD.search(field):
            values[field] = marker
        elif _ADDRESS_FIELD.search(field):
            values[field] = marker
        elif _USER_FIELD.search(field):
            values[field] = username
        else:
            values[field] = marker
    return values


def registration_values(fields: list[str], marker: str) -> tuple[str, str, dict[str, str]]:
    """给注册接口生成一组带标记的账号，返回（用户名，密码，字段值）。响应里出现标记即证明是这组账号的数据。"""
    username = f"u{marker.lower()}"
    password = f"Pw-{marker}-9"
    return username, password, field_values(fields, username=username, password=password, marker=marker)
