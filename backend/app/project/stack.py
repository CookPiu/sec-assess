"""侦察：解析依赖清单、识别语言与框架、统计代码行数（FR-002）。

只读取文件内容，不执行工程里的任何代码。
"""

from __future__ import annotations

import json
import os
import re
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

SKIP_DIRS = {
    ".git", ".hg", ".svn", ".idea", ".vscode", "__pycache__", ".mypy_cache", ".pytest_cache",
    "node_modules", ".venv", "venv", "env", "site-packages", "dist", "build", "target",
}  # fmt: skip
LANG_BY_EXT = {
    ".py": "Python",
    ".js": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript", ".jsx": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript",
    ".vue": "Vue",
    ".java": "Java", ".kt": "Kotlin",
    ".go": "Go", ".php": "PHP", ".rb": "Ruby",
    ".html": "HTML", ".htm": "HTML", ".jinja": "HTML", ".jinja2": "HTML", ".j2": "HTML",
    ".css": "CSS",
}  # fmt: skip
# 只用于判断主语言时忽略的标记语言
MARKUP_LANGS = {"HTML", "CSS"}
MAX_FILE_BYTES = 2 * 1024 * 1024  # 超过的文件多为压缩产物，不计行数
MAX_MANIFEST_DEPTH = 3

FRAMEWORKS: dict[tuple[str, str], str] = {
    ("pypi", "flask"): "Flask",
    ("pypi", "django"): "Django",
    ("pypi", "fastapi"): "FastAPI",
    ("pypi", "tornado"): "Tornado",
    ("npm", "express"): "Express",
    ("npm", "koa"): "Koa",
    ("npm", "@nestjs/core"): "NestJS",
    ("npm", "next"): "Next.js",
    ("npm", "vue"): "Vue",
    ("npm", "react"): "React",
}

_REQ_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$")
# 没有依赖清单时，从 import 语句补充识别 Python 框架
_PY_IMPORT_RE = re.compile(r"^\s*(?:from|import)\s+(flask|django|fastapi|tornado)\b", re.MULTILINE)


def normalize_pypi(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_requirement(line: str) -> tuple[str, str] | None:
    """解析一行 PEP 508 依赖，返回（规范化包名，版本约束）；选项行、URL 与空行返回 None。"""
    line = line.split(" #", 1)[0].strip()
    if not line or line.startswith(("#", "-")) or "://" in line:
        return None
    match = _REQ_RE.match(line)
    if match is None:
        return None
    spec = match.group(3).split(";", 1)[0].strip()
    return normalize_pypi(match.group(1)), spec


def _pinned(spec: str) -> str | None:
    match = re.fullmatch(r"(?:==|===)\s*([\w.+!-]+)", spec.strip())
    return match.group(1) if match else None


def _dep(ecosystem: str, name: str, spec: str, source: str, *, dev: bool = False) -> dict[str, Any]:
    return {"ecosystem": ecosystem, "name": name, "spec": spec, "source": source, "dev": dev}


def parse_requirements_txt(text: str, source: str) -> list[dict[str, Any]]:
    deps = []
    for line in text.splitlines():
        parsed = parse_requirement(line)
        if parsed:
            deps.append(_dep("pypi", parsed[0], parsed[1], source))
    return deps


def parse_pyproject(text: str, source: str) -> list[dict[str, Any]]:
    data = tomllib.loads(text)
    deps = []
    for item in (data.get("project") or {}).get("dependencies") or []:
        parsed = parse_requirement(str(item))
        if parsed:
            deps.append(_dep("pypi", parsed[0], parsed[1], source))
    poetry = ((data.get("tool") or {}).get("poetry") or {}).get("dependencies") or {}
    for name, value in poetry.items():
        if name.lower() == "python":
            continue
        spec = value if isinstance(value, str) else str((value or {}).get("version", ""))
        deps.append(_dep("pypi", normalize_pypi(name), spec, source))
    return deps


def parse_package_json(text: str, source: str) -> list[dict[str, Any]]:
    data = json.loads(text)
    deps = []
    for key, dev in (("dependencies", False), ("devDependencies", True)):
        for name, spec in (data.get(key) or {}).items():
            deps.append(_dep("npm", name, str(spec), source, dev=dev))
    return deps


def parse_pom(text: str, source: str) -> list[dict[str, Any]]:
    root = ET.fromstring(text)
    for el in root.iter():
        el.tag = el.tag.rsplit("}", 1)[-1]  # 去掉 Maven 命名空间

    def coord(el: ET.Element) -> tuple[str, str]:
        name = f"{el.findtext('groupId', '').strip()}:{el.findtext('artifactId', '').strip()}"
        return name, el.findtext("version", "").strip()

    deps = []
    parent = root.find("parent")
    if parent is not None:
        name, version = coord(parent)
        deps.append(_dep("maven", name, version, source))
    for dep in root.findall("./dependencies/dependency"):
        name, version = coord(dep)
        deps.append(_dep("maven", name, version, source, dev=dep.findtext("scope", "") == "test"))
    return deps


def _manifest_parser(name: str):
    if name == "pyproject.toml":
        return parse_pyproject
    if name == "package.json":
        return parse_package_json
    if name == "pom.xml":
        return parse_pom
    if name.startswith("requirements") and name.endswith(".txt"):
        return parse_requirements_txt
    return None


def _framework_of(dep: dict[str, Any]) -> str | None:
    name = FRAMEWORKS.get((dep["ecosystem"], dep["name"]))
    if name is None and dep["ecosystem"] == "maven" and dep["name"].split(":")[-1].startswith("spring-boot"):
        name = "Spring Boot"
    return name


def _read_source(path: Path) -> str:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def analyze_stack(root: Path) -> dict[str, Any]:
    """遍历源码目录，返回语言分布、主语言、框架、依赖清单与代码行数（非空行）。"""
    languages: dict[str, dict[str, int]] = {}
    manifests: list[str] = []
    dependencies: list[dict[str, Any]] = []
    errors: list[str] = []
    imported: set[str] = set()

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not d.startswith("."))
        rel_dir = Path(dirpath).relative_to(root)
        depth = len(rel_dir.parts)
        for filename in sorted(filenames):
            path = Path(dirpath) / filename
            if path.is_symlink():
                continue
            rel = (rel_dir / filename).as_posix()
            lang = LANG_BY_EXT.get(path.suffix.lower())
            if lang:
                text = _read_source(path)
                stats = languages.setdefault(lang, {"files": 0, "loc": 0})
                stats["files"] += 1
                stats["loc"] += sum(1 for line in text.splitlines() if line.strip())
                if lang == "Python":
                    imported.update(_PY_IMPORT_RE.findall(text))
            parser = _manifest_parser(filename) if depth < MAX_MANIFEST_DEPTH else None
            if parser is None:
                continue
            try:
                dependencies.extend(parser(path.read_text(encoding="utf-8", errors="replace"), rel))
                manifests.append(rel)
            except (ValueError, ET.ParseError, OSError) as exc:
                errors.append(f"{rel}：{exc}")

    lang_list = sorted(
        ({"name": name, **stats} for name, stats in languages.items()), key=lambda x: (-x["loc"], x["name"])
    )
    code_langs = [x for x in lang_list if x["name"] not in MARKUP_LANGS]
    frameworks: dict[str, dict[str, Any]] = {}
    for dep in dependencies:
        fw = _framework_of(dep)
        if fw and fw not in frameworks:
            version = _pinned(dep["spec"]) if dep["ecosystem"] == "pypi" else (dep["spec"].lstrip("^~=") or None)
            frameworks[fw] = {"name": fw, "version": version, "ecosystem": dep["ecosystem"]}
    for module in sorted(imported):
        fw = FRAMEWORKS[("pypi", module)]
        frameworks.setdefault(fw, {"name": fw, "version": None, "ecosystem": "pypi"})

    return {
        "primary_language": code_langs[0]["name"] if code_langs else None,
        "languages": lang_list,
        "frameworks": list(frameworks.values()),
        "manifests": manifests,
        "dependencies": dependencies,
        "loc": sum(x["loc"] for x in lang_list),
        "errors": errors,
    }
