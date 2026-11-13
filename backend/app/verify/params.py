"""从污点轨迹与处理函数源码里提取请求参数和 SQL 投影列数，供用例模板定位入口。"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

CONTAINERS = ("query", "form", "json", "files")
_PATH_PARAM = re.compile(r"<(?:[a-zA-Z_]+:)?([a-zA-Z_][a-zA-Z0-9_]*)>")
_DIRECT = re.compile(
    r"(?P<container>request\.(?:args|form|values|files)|request\.json|request\.get_json\(\))"
    r"\s*(?:\.\s*get\(\s*|\[\s*)['\"](?P<name>[^'\"]+)['\"]"
)
_ALIAS_DEF = re.compile(r"(?P<alias>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*request\.get_json\(\)")
_ALIAS_USE = re.compile(r"(?P<alias>[A-Za-z_][A-Za-z0-9_]*)\s*(?:\.\s*get\(\s*|\[\s*)['\"](?P<name>[^'\"]+)['\"]")
_SELECT = re.compile(r"\bselect\s+(?P<columns>.+?)\s+from\s", re.IGNORECASE | re.DOTALL)


@dataclass
class Params:
    query: list[str] = field(default_factory=list)
    form: list[str] = field(default_factory=list)
    json: list[str] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    path: list[str] = field(default_factory=list)

    def add(self, container: str, name: str) -> None:
        values: list[str] = getattr(self, _container_attr(container))
        if name and name not in values:
            values.append(name)

    def empty(self) -> bool:
        return not (self.query or self.form or self.json or self.files or self.path)


def _container_attr(raw: str) -> str:
    if raw in ("query", "form", "json", "files"):
        return raw
    if "get_json" in raw or raw.endswith("request.json"):
        return "json"
    if "files" in raw:
        return "files"
    if "form" in raw:
        return "form"
    if "values" in raw:
        return "query"
    if "args" in raw:
        return "query"
    return "query"


def extract_params(text: str, route_path: str = "") -> Params:
    """扫描源码片段：request.args/form/json/files 的直接取值、JSON 别名取值，以及路径参数。"""
    found = Params()
    aliases = set(_ALIAS_DEF.findall(text))
    for match in _DIRECT.finditer(text):
        found.add(_container_attr(match.group("container")), match.group("name"))
    for match in _ALIAS_USE.finditer(text):
        if match.group("alias") not in aliases:
            continue
        # 别名只用于 JSON 数据；同一段代码里也可能有别的别名取值，已由直接匹配覆盖
        found.add("json", match.group("name"))
    if route_path:
        for name in _PATH_PARAM.findall(route_path):
            if name not in found.path:
                found.path.append(name)
    return found


def select_columns(text: str) -> int | None:
    """从 SELECT 语句推断投影列数，用于 UNION 注入凑齐列数；嵌套结构按顶层逗号计数。"""
    match = _SELECT.search(text)
    if match is None:
        return None
    columns = re.sub(r"^\s*distinct\s+", "", match.group("columns"), flags=re.IGNORECASE)
    depth = 0
    count = 1
    for char in columns:
        if char in "([":
            depth += 1
        elif char in ")]":
            depth = max(depth - 1, 0)
        elif char == "," and depth == 0:
            count += 1
    return count if 1 <= count <= 32 else None
