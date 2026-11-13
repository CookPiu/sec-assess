"""补丁生成（DESIGN.md 5.5、D-009）：定位漏洞所在的函数或模块级语句，交给大模型输出修复后的完整代码段，
程序校验后替换原文，用 difflib 生成 unified diff。

补丁基于工程源码目录里的原文件生成，在工程根目录执行 `git apply` 即可应用。模型输出未通过校验时
带着原因重试一次，仍不通过则该漏洞不生成补丁。
"""

from __future__ import annotations

import ast
import asyncio
import re
import textwrap
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from app.core.llm import InputTooLarge, LLMClient
from app.models.enums import CATEGORY_LABELS
from app.patch.diff import split_lines, unified_diff
from app.project.flask_facts import ACCESS_LABELS
from app.report.render import REMEDIATION

MAX_FILE_BYTES = 1024 * 1024
MAX_SEGMENT_CHARS = 4_000
MAX_PROMPT_CHARS = 12_000
MAX_STEPS = 10
MAX_SIGNATURES = 30
MAX_HELPER_CHARS = 3_000
MAX_IMPORTS = 5
MAX_SUMMARY_CHARS = 80
ATTEMPTS = 2
# 补丁要输出整段函数，耗时比研判长，单次请求超时单独放宽
REQUEST_TIMEOUT_SECONDS = 60

SYSTEM_PROMPT = """你是 Python 安全工程师，为已经过动态验证的漏洞编写最小修复。
输入给出漏洞信息、污点轨迹、所在文件现有的导入语句和函数定义行、工程自带装饰器的源码，以及需要修改的代码段。
要求：
- 只修改这段代码，输出修复后的完整代码段，程序会用它原样替换输入的代码段；
- 函数名和参数保持不变，可以增删装饰器，保留与漏洞无关的业务逻辑；
- 优先采用参数化查询、白名单校验、安全 API 等根治写法，不靠过滤关键字；
- 只使用 Python 标准库、Flask 及其依赖（Werkzeug、Jinja2 等）和文件中已经导入的模块；
- 需要新增的 import 写进 imports，代码段里不要写 import 语句。
只输出一个 JSON 对象：
{"code": "修复后的完整代码段",
 "imports": ["需要新增的 import 语句，没有则为空数组"],
 "summary": "中文，50 字以内，说明修复方式"}"""

_FENCE = re.compile(r"^\s*```[a-zA-Z]*\n(.*?)\n?```\s*$", re.DOTALL)
_INDENT = re.compile(r"[ \t]*")


class PatchRejected(ValueError):
    """无法为该漏洞生成补丁，或模型输出未通过校验。"""


@dataclass(frozen=True)
class PatchTarget:
    finding_id: int
    code: str
    category: str
    title: str
    file: str
    line: int
    route: dict[str, Any] | None = None
    reason: str | None = None
    # (文件, 行号, 代码片段, 说明)
    steps: list[tuple[str, int, str, str]] = field(default_factory=list)


@dataclass(frozen=True)
class PatchResult:
    target: PatchTarget
    diff: str | None = None
    summary: str = ""
    error: str | None = None


@dataclass(frozen=True)
class Segment:
    """要替换的代码段，行号从 1 开始、首尾都包含；name 为函数名，模块级语句为 None。"""

    start: int
    end: int
    indent: str
    name: str | None


@dataclass
class SourceFile:
    path: str
    text: str
    tree: ast.Module
    lines: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.lines = split_lines(self.text)

    @property
    def newline(self) -> str:
        return "\r\n" if "\r\n" in self.text else "\n"


def read_source(root: Path, rel: str) -> SourceFile:
    """读取工程根目录内的 Python 文件；路径越界、过大、非 UTF-8 或有语法错误时拒绝。"""
    pure = PurePosixPath(rel)
    base = root.resolve()
    target = (base / pure).resolve()
    if pure.is_absolute() or ".." in pure.parts or not target.is_relative_to(base) or not target.is_file():
        raise PatchRejected(f"找不到源码文件 {rel}")
    if target.stat().st_size > MAX_FILE_BYTES:
        raise PatchRejected(f"{rel} 超过 1 MB")
    try:
        text = target.read_bytes().decode("utf-8")
    except UnicodeDecodeError:
        raise PatchRejected(f"{rel} 不是 UTF-8 编码") from None
    try:
        tree = ast.parse(text, filename=rel)
    except SyntaxError:
        raise PatchRejected(f"{rel} 有语法错误") from None
    return SourceFile(rel, text, tree)


def _span(node: ast.stmt) -> tuple[int, int]:
    decorators = getattr(node, "decorator_list", [])
    start = min([node.lineno, *(d.lineno for d in decorators)])
    return start, node.end_lineno or node.lineno


def _indent_of(source: SourceFile, line: int) -> str:
    return _INDENT.match(source.lines[line - 1]).group()


def locate_segment(source: SourceFile, line: int) -> Segment:
    """取包含该行的最内层函数（含装饰器）；不在函数里时取模块或类中包含该行的那条语句。"""
    best: tuple[int, int, str] | None = None
    for node in ast.walk(source.tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            start, end = _span(node)
            if start <= line <= end and (best is None or end - start < best[1] - best[0]):
                best = (start, end, node.name)
    if best is not None:
        start, end, name = best
        return Segment(start, end, _indent_of(source, start), name)
    body: list[ast.stmt] = source.tree.body
    while True:
        for stmt in body:
            start, end = _span(stmt)
            if start <= line <= end:
                if isinstance(stmt, ast.ClassDef) and stmt.body and line > stmt.lineno:
                    body = stmt.body
                    break
                return Segment(start, end, _indent_of(source, start), None)
        else:
            raise PatchRejected(f"{source.path}:{line} 不在任何语句内，无法确定修复范围")


def segment_code(source: SourceFile, seg: Segment) -> str:
    text = "".join(source.lines[seg.start - 1 : seg.end])
    return textwrap.dedent(text.replace("\r\n", "\n")).rstrip("\n")


def _import_nodes(source: SourceFile) -> list[ast.Import | ast.ImportFrom]:
    return [n for n in source.tree.body if isinstance(n, ast.Import | ast.ImportFrom)]


def _signatures(source: SourceFile, seg: Segment) -> list[str]:
    """同文件其他顶层函数的装饰器与定义行，让模型知道可用的鉴权装饰器等写法。"""
    result: list[str] = []
    for node in source.tree.body:
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        start, _ = _span(node)
        if start == seg.start:
            continue
        result += [source.lines[i - 1].rstrip() for i in range(start, node.lineno + 1)]
    return result[:MAX_SIGNATURES]


def _decorator_names(source: SourceFile) -> list[str]:
    names: list[str] = []
    for node in source.tree.body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            for deco in node.decorator_list:
                target = deco.func if isinstance(deco, ast.Call) else deco
                if isinstance(target, ast.Name) and target.id not in names:
                    names.append(target.id)
    return names


def _module_file(root: Path, source: SourceFile, node: ast.ImportFrom) -> str | None:
    """把 from x.y import z 解析成工程内的文件路径；不在工程内时返回 None。"""
    base: list[str] = []
    if node.level:
        package = list(PurePosixPath(source.path).parent.parts)
        base = package[: len(package) - (node.level - 1)]
    if node.module:
        base += node.module.split(".")
    if not base:
        return None
    for candidate in ("/".join(base) + ".py", "/".join([*base, "__init__.py"])):
        if (root / candidate).is_file():
            return candidate
    return None


def helper_sources(root: Path, source: SourceFile) -> list[tuple[str, str]]:
    """文件中用到的工程自带装饰器（如登录校验）的源码，让模型知道当前用户存在哪里、怎样拒绝访问。"""
    imported: dict[str, tuple[ast.ImportFrom, str]] = {}
    for node in _import_nodes(source):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                imported[alias.asname or alias.name] = (node, alias.name)
    result: list[tuple[str, str]] = []
    for name in _decorator_names(source):
        if name in imported:
            node, real = imported[name]
            rel = _module_file(root, source, node)
            if rel is None:
                continue
            try:
                module = read_source(root, rel)
            except PatchRejected:
                continue
        else:
            module, real = source, name
        for fn in module.tree.body:
            if isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef) and fn.name == real:
                start, end = _span(fn)
                code = "".join(module.lines[start - 1 : end]).replace("\r\n", "\n").rstrip("\n")
                result.append((f"{module.path} 中的 {real}", code))
                break
    return result


def route_text(route: dict[str, Any] | None) -> str:
    if not route:
        return ""
    access = ACCESS_LABELS.get(route.get("access", ""), route.get("access", ""))
    return f"{' / '.join(route.get('methods') or [])} {route.get('path', '')}，访问前提：{access}"


def build_prompt(
    target: PatchTarget, source: SourceFile, seg: Segment, helpers: list[tuple[str, str]] | None = None
) -> str:
    label = CATEGORY_LABELS.get(target.category, target.category)
    head = [f"漏洞：{target.code} {label}（{target.category}）", f"标题：{target.title}", f"位置：{target.file}:{target.line}"]
    if target.route:
        head.append(f"入口路由：{route_text(target.route)}")
    if target.reason:
        head.append(f"研判理由：{target.reason}")
    if target.category in REMEDIATION:
        head.append(f"参考修复方向：{REMEDIATION[target.category]}")
    where = f"{target.file} 第 {seg.start}–{seg.end} 行" + (f"，函数 {seg.name}" if seg.name else "，模块级语句")
    tail = f"\n\n需要修改的代码段（{where}）：\n{segment_code(source, seg)}"

    blocks = []
    if target.steps:
        blocks.append(
            "污点轨迹：\n"
            + "\n".join(
                f"{i}. {f}:{n}  {snippet}  # {note}" for i, (f, n, snippet, note) in enumerate(target.steps[:MAX_STEPS], 1)
            )
        )
    imports = [ast.unparse(n) for n in _import_nodes(source)]
    blocks.append("文件现有的导入语句：\n" + ("\n".join(imports) if imports else "（无）"))
    signatures = _signatures(source, seg)
    if signatures:
        blocks.append("同文件中的其他函数（装饰器与定义行）：\n" + "\n".join(signatures))
    helper_text = "".join(f"\n--- {label} ---\n{code}" for label, code in helpers or [])
    if helper_text and len(helper_text) <= MAX_HELPER_CHARS:
        blocks.append("工程自带装饰器的源码：" + helper_text)

    text = "\n".join(head)
    for block in blocks:
        if len(text) + len(block) + len(tail) + 2 > MAX_PROMPT_CHARS:
            break
        text += "\n\n" + block
    return text + tail


def _strip_fence(code: str) -> str:
    match = _FENCE.match(code)
    return match.group(1) if match else code


def _new_imports(reply: Any, source: SourceFile) -> list[str]:
    if reply is None:
        return []
    if not isinstance(reply, list) or len(reply) > MAX_IMPORTS:
        raise PatchRejected("imports 必须是不超过 5 条的数组")
    existing = {ast.unparse(n) for n in _import_nodes(source)}
    result: list[str] = []
    for item in reply:
        if not isinstance(item, str) or not item.strip():
            raise PatchRejected("imports 里有空的或不是字符串的项")
        try:
            body = ast.parse(item.strip()).body
        except SyntaxError:
            raise PatchRejected(f"导入语句有语法错误：{item.strip()}") from None
        if len(body) != 1 or not isinstance(body[0], ast.Import | ast.ImportFrom):
            raise PatchRejected(f"不是单条导入语句：{item.strip()}")
        if isinstance(body[0], ast.ImportFrom) and body[0].module == "__future__":
            raise PatchRejected("不能新增 from __future__ 导入")
        normalized = ast.unparse(body[0])
        if normalized not in existing and normalized not in result:
            result.append(normalized)
    return result


def _import_anchor(source: SourceFile, seg: Segment) -> int:
    """新增导入插在文件开头导入块的末尾（0 起的行下标），不晚于代码段开头。"""
    body = source.tree.body
    anchor: int | None = None
    for i, node in enumerate(body):
        is_docstring = i == 0 and isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)
        if is_docstring or isinstance(node, ast.Import | ast.ImportFrom):
            anchor = node.end_lineno or node.lineno
            continue
        if anchor is None:
            anchor = _span(node)[0] - 1
        break
    if anchor is None:
        anchor = len(source.lines)
    return min(anchor, seg.start - 1)


def apply_fix(reply: dict[str, Any], source: SourceFile, seg: Segment) -> tuple[str, str]:
    """校验模型输出并返回（修复后的整个文件、修复说明）；不通过时抛出 PatchRejected。"""
    code = reply.get("code")
    if not isinstance(code, str) or not code.strip():
        raise PatchRejected("没有给出修复后的代码")
    code = textwrap.dedent(_strip_fence(code).replace("\r\n", "\n")).strip("\n")
    try:
        module = ast.parse(code)
    except SyntaxError as exc:
        raise PatchRejected(f"修复后的代码有语法错误（第 {exc.lineno} 行：{exc.msg}）") from None
    if seg.name is not None:
        defs = module.body
        if len(defs) != 1 or not isinstance(defs[0], ast.FunctionDef | ast.AsyncFunctionDef) or defs[0].name != seg.name:
            raise PatchRejected(f"修复后的代码必须是函数 {seg.name} 的一个完整定义")
    imports = _new_imports(reply.get("imports"), source)

    nl = source.newline
    new_seg = [f"{seg.indent}{line}{nl}" if line.strip() else nl for line in code.split("\n")]
    lines = source.lines
    if seg.end == len(lines) and not lines[-1].endswith("\n"):
        new_seg[-1] = new_seg[-1].removesuffix(nl)
    added = [f"{line}{nl}" for line in imports]
    anchor = _import_anchor(source, seg)
    if anchor > 0 and added and not lines[anchor - 1].endswith("\n"):
        raise PatchRejected("无法在导入块后插入新的导入语句")
    new_lines = lines[:anchor] + added + lines[anchor : seg.start - 1] + new_seg + lines[seg.end :]
    new_text = "".join(new_lines)
    if new_text == source.text:
        raise PatchRejected("修复后的代码与原代码相同")
    try:
        ast.parse(new_text)
    except SyntaxError as exc:
        raise PatchRejected(f"替换后文件有语法错误（第 {exc.lineno} 行：{exc.msg}）") from None
    summary = str(reply.get("summary") or "").strip().rstrip("。.")[:MAX_SUMMARY_CHARS] or "模型未给出修复说明"
    return new_text, summary


async def generate_patch(llm: LLMClient, root: Path, target: PatchTarget) -> PatchResult:
    try:
        source = await asyncio.to_thread(read_source, root, target.file)
        seg = locate_segment(source, target.line)
        if len(segment_code(source, seg)) > MAX_SEGMENT_CHARS:
            raise PatchRejected(f"所在代码段超过 {MAX_SEGMENT_CHARS} 字符，不交给大模型")
        helpers = await asyncio.to_thread(helper_sources, root, source)
        prompt = build_prompt(target, source, seg, helpers)
    except PatchRejected as exc:
        return PatchResult(target, error=str(exc))

    feedback = ""
    error = "模型调用失败或输出不是 JSON"
    for _ in range(ATTEMPTS):
        try:
            reply = await llm.chat_json(SYSTEM_PROMPT, prompt + feedback, timeout=REQUEST_TIMEOUT_SECONDS)
        except InputTooLarge:
            return PatchResult(target, error="发给模型的内容超出长度上限")
        if reply is None:
            error = "模型调用失败或输出不是 JSON"
            continue
        try:
            new_text, summary = apply_fix(reply, source, seg)
        except PatchRejected as exc:
            error = f"模型输出未通过校验：{exc}"
            feedback = f"\n\n上一次输出未通过校验：{exc}。请按要求重新输出。"
            continue
        return PatchResult(target, unified_diff(target.file, source.text, new_text), summary)
    return PatchResult(target, error=error)


async def generate_patches(
    llm: LLMClient, root: Path, targets: list[PatchTarget], *, concurrency: int
) -> list[PatchResult]:
    semaphore = asyncio.Semaphore(concurrency)

    async def one(target: PatchTarget) -> PatchResult:
        async with semaphore:
            return await generate_patch(llm, root, target)

    # 任务被停止（取消）时，TaskGroup 会一并取消尚未完成的请求
    async with asyncio.TaskGroup() as group:
        jobs = [group.create_task(one(t)) for t in targets]
    return [job.result() for job in jobs]
