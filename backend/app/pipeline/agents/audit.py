"""源码审计（DESIGN.md 5.2）：污点引擎与规则产出候选，大模型逐条研判，结果写入 finding 与 taint_step。

发给模型的只有候选涉及的函数源码和轨迹片段（D-011）。模型未配置、在配置页被关闭、调用失败或
输出不合法时，按漏洞类别的默认向量计分，理由标注“未经模型研判”。
"""

from __future__ import annotations

import asyncio
from collections import Counter
from dataclasses import dataclass
from typing import Any

from app.core import cvss
from app.core.db import session_factory
from app.core.llm import InputTooLarge, LLMClient, get_llm
from app.models import Finding, TaintStep
from app.models.enums import CATEGORY_LABELS, SEVERITY_LABELS, Category, JudgedBy, Severity, VerifyStatus
from app.pipeline.state import TaskContext
from app.project.flask_facts import ACCESS_LABELS, collect_flask_facts
from app.project.pysource import FunctionInfo, ProjectIndex
from app.taint.engine import find_taint_candidates
from app.taint.model import Candidate
from app.taint.rules_authz import find_authz_candidates
from app.taint.rules_secrets import find_secret_candidates

MAX_FUNCTION_CHARS = 4_000
MAX_PROMPT_CHARS = 12_000
CONTEXT_LINES = 6
MAX_REASON_CHARS = 500
MAX_LOGGED = 30
NO_MODEL = "未经模型研判，按漏洞类别的默认向量计分"

SYSTEM_PROMPT = f"""你是代码安全审计员，复核静态分析器给出的候选漏洞。
输入包含候选类别、说明、污点轨迹和相关源码。请判断它是否误报，并给出 CVSS 3.1 基础向量。
只输出一个 JSON 对象：
{{"false_positive": true 或 false,
  "category": 取值之一 {", ".join(c.value for c in Category)},
  "cvss_vector": "CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_",
  "reason": "中文，150 字以内，说明数据从哪里来、为什么能或不能被利用"}}
只依据给出的代码判断；代码里有有效的净化、白名单校验、参数化查询或权限检查时判为误报。
PR 指标按路由的访问前提填写：匿名为 N，普通用户为 L，管理员为 H。"""


@dataclass(frozen=True)
class Judgement:
    category: Category
    vector: str
    score: float
    severity: Severity
    false_positive: bool
    judged_by: JudgedBy
    reason: str


def collect_candidates(index: ProjectIndex, facts: dict[str, Any]) -> tuple[list[Candidate], dict[str, int]]:
    routes = facts.get("routes") or []
    taint = find_taint_candidates(index, routes)
    authz = find_authz_candidates(index, routes)
    secrets = find_secret_candidates(index, facts)
    merged: dict[tuple[str, str, int], Candidate] = {}
    for cand in [*taint, *authz, *secrets]:
        merged.setdefault(cand.key, cand)
    ordered = sorted(merged.values(), key=lambda c: (c.file, c.line, c.category))
    return ordered, {"taint": len(taint), "authz": len(authz), "secrets": len(secrets)}


def route_text(route: dict[str, Any]) -> str:
    return f"{' / '.join(route['methods'])} {route['path']}"


def title_of(cand: Candidate, category: Category) -> str:
    detail = route_text(cand.route) if cand.route else cand.message
    return f"{CATEGORY_LABELS[category]}：{detail}"[:200]


def build_prompt(index: ProjectIndex, cand: Candidate, functions: dict[str, FunctionInfo]) -> str:
    parts = [
        f"候选类别：{CATEGORY_LABELS[Category(cand.category)]}（{cand.category}）",
        f"说明：{cand.message}",
        f"位置：{cand.file}:{cand.line}",
    ]
    if cand.route:
        parts.append(f"路由：{route_text(cand.route)}，访问前提：{ACCESS_LABELS[cand.route['access']]}")
    parts.append("轨迹：")
    parts += [f"{i}. {s.file}:{s.line}  {s.snippet}  # {s.note}" for i, s in enumerate(cand.steps, 1)]

    sources: list[tuple[str, str]] = []
    for name in cand.functions:
        fn = functions.get(name)
        if fn is not None:
            sources.append((f"{fn.file} 中的 {fn.qualname}", index.function_source(fn)[:MAX_FUNCTION_CHARS]))
    if not sources:
        # 模块级问题（硬编码密钥、调试开关）没有所在函数，只给上下文几行
        module = index.module_by_file(cand.file)
        if module is not None:
            start = max(cand.line - 1 - CONTEXT_LINES, 0)
            code = "\n".join(module.lines[start : cand.line + CONTEXT_LINES])
            sources.append((f"{cand.file} 第 {start + 1} 行起", code))

    text = "\n".join(parts)
    for label, code in sources:
        block = f"\n\n--- {label} ---\n{code}"
        if len(text) + len(block) > MAX_PROMPT_CHARS:
            text += "\n\n（其余代码超出长度，已省略）"
            break
        text += block
    return text


def default_judgement(cand: Candidate, note: str = NO_MODEL) -> Judgement:
    category = Category(cand.category)
    vector = cvss.default_vector(category)
    value, severity = cvss.score(vector)
    return Judgement(category, vector, value, severity, False, JudgedBy.DEFAULT, f"{cand.message}。{note}")


def parse_judgement(reply: dict[str, Any], cand: Candidate) -> Judgement | None:
    false_positive = reply.get("false_positive")
    if not isinstance(false_positive, bool):
        return None
    try:
        category = Category(reply.get("category") or cand.category)
    except ValueError:
        category = Category(cand.category)
    reason = str(reply.get("reason") or "").strip()[:MAX_REASON_CHARS] or "模型未给出理由"
    vector = str(reply.get("cvss_vector") or "").strip()
    try:
        value, severity = cvss.score(vector)
    except cvss.CvssError:
        vector = cvss.default_vector(category)
        value, severity = cvss.score(vector)
        reason += "（模型给出的 CVSS 向量无效，改按类别默认向量计分）"
    return Judgement(category, vector, value, severity, false_positive, JudgedBy.MODEL, reason)


async def judge_all(
    index: ProjectIndex, candidates: list[Candidate], llm: LLMClient, *, enabled: bool, concurrency: int
) -> list[Judgement]:
    if not (enabled and llm.configured):
        return [default_judgement(c) for c in candidates]
    functions = {fn.qualname: fn for fn in index.functions.values()}
    semaphore = asyncio.Semaphore(concurrency)

    async def judge(cand: Candidate) -> Judgement:
        async with semaphore:
            try:
                reply = await llm.chat_json(SYSTEM_PROMPT, build_prompt(index, cand, functions))
            except InputTooLarge:
                reply = None
        parsed = parse_judgement(reply, cand) if reply else None
        return parsed or default_judgement(cand, f"模型调用失败或输出不合法，{NO_MODEL}")

    # TaskGroup 在任务被停止（取消）时会一并取消尚未完成的研判请求
    async with asyncio.TaskGroup() as group:
        jobs = [group.create_task(judge(c)) for c in candidates]
    return [job.result() for job in jobs]


async def save_findings(
    task_id: int, candidates: list[Candidate], judgements: list[Judgement]
) -> list[tuple[Finding, Judgement]]:
    """按分数从高到低编号，模型判定误报的排在最后。"""
    pairs = sorted(
        zip(candidates, judgements, strict=True),
        key=lambda p: (p[1].false_positive, -p[1].score, p[0].file, p[0].line),
    )
    saved: list[tuple[Finding, Judgement]] = []
    async with session_factory()() as session:
        for seq, (cand, judgement) in enumerate(pairs, 1):
            finding = Finding(
                task_id=task_id,
                code=f"SA-{task_id}-{seq:03d}",
                category=judgement.category,
                title=title_of(cand, judgement.category),
                severity=judgement.severity,
                cvss_vector=judgement.vector,
                cvss_score=judgement.score,
                file=cand.file,
                line=cand.line,
                route=cand.route,
                status=VerifyStatus.UNVERIFIED,
                model_false_positive=judgement.false_positive,
                judged_by=judgement.judged_by,
                reason=judgement.reason,
            )
            session.add(finding)
            await session.flush()
            session.add_all(
                TaintStep(finding_id=finding.id, seq=i, file=s.file, line=s.line, snippet=s.snippet, note=s.note[:200])
                for i, s in enumerate(cand.steps, 1)
            )
            saved.append((finding, judgement))
        await session.commit()
    return saved


async def run(ctx: TaskContext) -> None:
    index = await asyncio.to_thread(ProjectIndex, ctx.source_dir)
    if not index.modules:
        await ctx.log("未找到 Python 源码，跳过源码审计", "warn")
        return
    facts = await asyncio.to_thread(collect_flask_facts, index)
    candidates, counts = await asyncio.to_thread(collect_candidates, index, facts)
    await ctx.log(
        f"静态分析完成：解析 {len(index.modules)} 个 Python 文件，污点候选 {counts['taint']} 条，"
        f"越权与鉴权候选 {counts['authz']} 条，敏感信息候选 {counts['secrets']} 条"
    )
    if not candidates:
        await ctx.log("没有发现候选漏洞")
        return
    ctx.check_stop()

    llm = get_llm(**ctx.runtime.llm_options())
    enabled = ctx.runtime.llm_enabled
    if enabled and llm.configured:
        await ctx.log(f"交给大模型研判 {len(candidates)} 条候选，并发 {ctx.runtime.llm_concurrency}")
    else:
        reason = "已在配置页关闭" if not enabled else "未配置"
        await ctx.log(f"大模型{reason}，{NO_MODEL}", "warn")
    judgements = await judge_all(index, candidates, llm, enabled=enabled, concurrency=ctx.runtime.llm_concurrency)
    ctx.check_stop()

    saved = await save_findings(ctx.task_id, candidates, judgements)
    for finding, judgement in saved[:MAX_LOGGED]:
        suffix = "，模型判定误报" if judgement.false_positive else ""
        await ctx.log(
            f"{finding.code} {SEVERITY_LABELS[judgement.severity]} {judgement.score:.1f} "
            f"{finding.title}（{finding.file}:{finding.line}）{suffix}"
        )
    if len(saved) > MAX_LOGGED:
        await ctx.log(f"其余 {len(saved) - MAX_LOGGED} 条见漏洞列表")

    counted = Counter(j.severity for _, j in saved if not j.false_positive)
    by_severity = "、".join(f"{SEVERITY_LABELS[s]} {counted[s]}" for s in Severity if counted[s]) or "无"
    rejected = sum(j.false_positive for _, j in saved)
    await ctx.log(f"研判完成：{by_severity}；模型判定误报 {rejected} 条，不计入评分")
