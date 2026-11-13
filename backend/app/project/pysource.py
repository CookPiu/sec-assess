"""Python 源码索引：解析全部 .py 文件，记录模块、导入别名和模块级函数，供侦察、污点引擎和规则共用。

只做语法解析，不导入、不执行工程代码。
"""

from __future__ import annotations

import ast
import os
from dataclasses import dataclass, field
from pathlib import Path

from app.project.stack import SKIP_DIRS

MAX_PY_BYTES = 1024 * 1024


@dataclass
class FunctionInfo:
    module: str
    name: str
    node: ast.FunctionDef | ast.AsyncFunctionDef
    file: str

    @property
    def qualname(self) -> str:
        return f"{self.module}.{self.name}"

    @property
    def params(self) -> list[str]:
        args = self.node.args
        return [a.arg for a in (*args.posonlyargs, *args.args, *args.kwonlyargs)]


@dataclass
class ModuleInfo:
    name: str
    file: str  # 相对源码根目录的路径，用 / 分隔
    tree: ast.Module
    text: str
    is_package: bool
    # 别名 → (模块, 名称)；import x 形式的名称为 None
    imports: dict[str, tuple[str, str | None]] = field(default_factory=dict)
    lines: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.lines = self.text.splitlines()


def dotted(node: ast.AST) -> str:
    """把 a.b.c 形式的表达式还原成字符串；调用取被调对象，其他情况返回空串。"""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted(node.value)
        return f"{base}.{node.attr}" if base else ""
    if isinstance(node, ast.Call):
        base = dotted(node.func)
        return f"{base}()" if base else ""
    return ""


def call_name(node: ast.Call) -> str:
    """被调函数的最后一段名称，如 db.session.execute(...) 得到 execute。"""
    func = node.func
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return ""


def keyword(node: ast.Call, name: str) -> ast.expr | None:
    for kw in node.keywords:
        if kw.arg == name:
            return kw.value
    return None


def const_str(node: ast.AST | None) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def is_true(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


# 测试代码不属于攻击面，其中的路由、密钥和 app.run 会干扰侦察与审计
TEST_DIRS = {"tests", "test", "testing"}


def is_test_file(filename: str) -> bool:
    return filename == "conftest.py" or filename.startswith("test_") or filename.endswith("_test.py")


class ProjectIndex:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.modules: dict[str, ModuleInfo] = {}
        self.functions: dict[tuple[str, str], FunctionInfo] = {}
        self.errors: list[str] = []
        self._by_file: dict[str, ModuleInfo] = {}
        self._load()

    def _load(self) -> None:
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = sorted(
                d for d in dirnames if d not in SKIP_DIRS and d not in TEST_DIRS and not d.startswith(".")
            )
            for filename in sorted(filenames):
                if not filename.endswith(".py") or is_test_file(filename):
                    continue
                path = Path(dirpath) / filename
                rel = path.relative_to(self.root).as_posix()
                if path.is_symlink() or path.stat().st_size > MAX_PY_BYTES:
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
                try:
                    tree = ast.parse(text, filename=rel)
                except SyntaxError as exc:
                    self.errors.append(f"{rel}:{exc.lineno}：{exc.msg}")
                    continue
                parts = rel[:-3].split("/")
                is_package = parts[-1] == "__init__"
                if is_package:
                    parts = parts[:-1]
                name = ".".join(parts) or "__init__"
                module = ModuleInfo(name, rel, tree, text, is_package)
                self.modules[name] = module
                self._by_file[rel] = module
        for module in self.modules.values():
            self._collect(module)

    def _collect(self, module: ModuleInfo) -> None:
        package = module.name if module.is_package else module.name.rpartition(".")[0]
        for node in ast.walk(module.tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.asname:
                        module.imports[alias.asname] = (alias.name, None)
                    else:
                        top = alias.name.split(".")[0]
                        module.imports[top] = (top, None)
            elif isinstance(node, ast.ImportFrom):
                base = node.module or ""
                if node.level:
                    pkg_parts = package.split(".") if package else []
                    keep = len(pkg_parts) - (node.level - 1)
                    prefix = ".".join(pkg_parts[: max(keep, 0)])
                    base = ".".join(p for p in (prefix, base) if p)
                for alias in node.names:
                    module.imports[alias.asname or alias.name] = (base, alias.name)
        for node in module.tree.body:
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                self.functions[(module.name, node.name)] = FunctionInfo(module.name, node.name, node, module.file)

    def snippet(self, file: str, line: int) -> str:
        module = self.module_by_file(file)
        if module is None or not 0 < line <= len(module.lines):
            return ""
        return module.lines[line - 1].strip()

    def module_by_file(self, file: str) -> ModuleInfo | None:
        return self._by_file.get(file)

    def function_source(self, fn: FunctionInfo) -> str:
        module = self.modules[fn.module]
        start = min([fn.node.lineno, *(d.lineno for d in fn.node.decorator_list)])
        end = fn.node.end_lineno or fn.node.lineno
        return "\n".join(module.lines[start - 1 : end])

    def resolve_symbol(self, module: str, name: str) -> tuple[str, str | None]:
        """把模块内的名称解析成（定义所在模块，名称）。未导入的名称视为本模块定义。"""
        info = self.modules.get(module)
        if info is not None and name in info.imports:
            target, attr = info.imports[name]
            if attr is None:
                return target, None
            if f"{target}.{attr}" in self.modules:  # from pkg import submodule
                return f"{target}.{attr}", None
            return target, attr
        return module, name

    def resolve_call(self, module: str, func: ast.expr) -> FunctionInfo | None:
        """解析 foo(...)、mod.foo(...) 形式的调用；方法调用和动态调用不追踪（D-018）。"""
        if isinstance(func, ast.Name):
            target, attr = self.resolve_symbol(module, func.id)
            return self.functions.get((target, attr)) if attr else None
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            target, attr = self.resolve_symbol(module, func.value.id)
            if attr is None:
                return self.functions.get((target, func.attr))
        return None
