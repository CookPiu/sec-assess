"""补丁与报告阶段（DESIGN.md 5.5）：为已验证漏洞生成修复补丁，计算安全评分与综合等级，由大模型写评估结论和
逐条整改行动，落库后供工作台与报告中心查看、导出。

评分、等级和整改优先级由规则算出；模型不可用、被关闭或输出不合法时，结论按统计数据生成，整改行动
按漏洞类别的默认指引（D-002），补丁跳过生成。
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import delete

from app.core.db import session_factory
from app.core.llm import InputTooLarge, LLMClient, get_llm
from app.models import Patch, Report
from app.models.enums import CATEGORY_LABELS, SEVERITY_LABELS, VerifyStatus
from app.patch.diff import diff_stats
from app.patch.generate import PatchResult, PatchTarget, generate_patches
from app.pipeline.state import TaskContext
from app.report.render import ReportData, cvss_text, default_conclusion, load_report_data, render_markdown
from app.report.scoring import PRIORITY_LABELS, remediation_order

MAX_FINDINGS_IN_PROMPT = 40
MAX_PATHS_IN_PROMPT = 10
MAX_CONCLUSION_CHARS = 500
MAX_ACTION_CHARS = 300
MAX_PATCH_LOGGED = 30

SYSTEM_PROMPT = """你是安全评估报告的撰写人。输入是一次源码安全评估的综合等级、安全评分、漏洞清单和多步攻击路径，等级、分数和优先级已由规则算出。
请据此写评估结论和每条漏洞的整改行动，不要改动等级、分数和优先级，不要增加输入中没有的漏洞。
只输出一个 JSON 对象：
{"conclusion": "中文，概括整体风险、最需要优先处理的漏洞与攻击路径，200 字以内",
 "actions": {"漏洞编号": "中文，针对该漏洞所在位置的具体整改措施，80 字以内"}}"""


def build_prompt(data: ReportData) -> str:
    score, level, reason = data.summary()
    by_code = {f.code: f for f in data.findings}
    lines = [f"综合安全等级：{level}（{reason}）", f"安全评分：{score} / 100", "漏洞清单（按整改优先级排序）："]
    ranked = remediation_order(data.score_items(), data.code_execution_codes())
    for prio, item in ranked[:MAX_FINDINGS_IN_PROMPT]:
        f = by_code[item.code]
        route = (f.route or {}).get("path")
        lines.append(
            f"- {f.code} [{PRIORITY_LABELS[prio]}] {CATEGORY_LABELS.get(f.category, f.category)}：{f.title}，"
            f"位置 {f.file}:{f.line}" + (f"，路由 {route}" if route else "") + "，"
            f"{SEVERITY_LABELS.get(f.severity, f.severity)} CVSS {cvss_text(f)}，"
            f"{'已验证' if f.status == VerifyStatus.VERIFIED else '疑似'}"
        )
    if data.paths:
        lines.append("多步攻击路径：")
        for path in data.paths[:MAX_PATHS_IN_PROMPT]:
            labels = [data.nodes[i].label for i in path.node_ids if i in data.nodes]
            lines.append(f"- 目标 {path.target}：{' → '.join(labels)}")
    else:
        lines.append("多步攻击路径：无")
    return "\n".join(lines)


def parse_reply(reply: dict[str, Any] | None, codes: set[str]) -> tuple[str | None, dict[str, str]]:
    """取出合法的结论与整改行动；不认识的编号和空文字丢弃。"""
    if not reply:
        return None, {}
    conclusion = reply.get("conclusion")
    conclusion = conclusion.strip()[:MAX_CONCLUSION_CHARS] if isinstance(conclusion, str) and conclusion.strip() else None
    raw = reply.get("actions")
    actions = {}
    if isinstance(raw, dict):
        for code, text in raw.items():
            if code in codes and isinstance(text, str) and text.strip():
                actions[code] = text.strip()[:MAX_ACTION_CHARS]
    return conclusion, actions


async def write_texts(data: ReportData, llm: LLMClient, *, enabled: bool) -> tuple[str, dict[str, str], bool]:
    """返回（评估结论、整改行动、结论是否来自模型）。"""
    codes = {f.code for f in data.counted}
    reply = None
    if codes and enabled and llm.configured:
        try:
            reply = await llm.chat_json(SYSTEM_PROMPT, build_prompt(data))
        except InputTooLarge:
            reply = None
    conclusion, actions = parse_reply(reply, codes)
    if conclusion is None:
        return default_conclusion(data), actions, False
    return conclusion, actions, True


async def save_report(task_id: int, conclusion: str, actions: dict[str, str], by_model: bool) -> None:
    async with session_factory()() as session:
        await session.execute(delete(Report).where(Report.task_id == task_id))
        session.add(
            Report(task_id=task_id, conclusion=conclusion, actions=actions, written_by="model" if by_model else "template")
        )
        await session.commit()


def patch_targets(data: ReportData) -> list[PatchTarget]:
    """只为已验证漏洞生成补丁（FR-012）。"""
    return [
        PatchTarget(
            finding_id=f.id,
            code=f.code,
            category=f.category,
            title=f.title,
            file=f.file,
            line=f.line,
            route=f.route,
            reason=f.reason,
            steps=[(s.file, s.line, s.snippet, s.note) for s in data.steps.get(f.id, [])],
        )
        for f in data.counted
        if f.status == VerifyStatus.VERIFIED
    ]


async def save_patches(targets: list[PatchTarget], results: list[PatchResult]) -> None:
    """重新生成时替换这些漏洞已有的补丁（采纳状态一并清除）。"""
    async with session_factory()() as session:
        await session.execute(delete(Patch).where(Patch.finding_id.in_([t.finding_id for t in targets])))
        session.add_all(Patch(finding_id=r.target.finding_id, diff=r.diff) for r in results if r.diff)
        await session.commit()


async def make_patches(ctx: TaskContext, data: ReportData, llm: LLMClient) -> None:
    targets = patch_targets(data)
    if not targets:
        return
    if not (ctx.runtime.llm_enabled and llm.configured):
        reason = "已在配置页关闭" if not ctx.runtime.llm_enabled else "未配置"
        await ctx.log(f"大模型{reason}，跳过 {len(targets)} 条已验证漏洞的补丁生成", "warn")
        return
    await ctx.log(f"交给大模型为 {len(targets)} 条已验证漏洞生成修复补丁，并发 {ctx.runtime.llm_concurrency}")
    results = await generate_patches(llm, ctx.source_dir, targets, concurrency=ctx.runtime.llm_concurrency)
    ctx.check_stop()
    await save_patches(targets, results)
    for result in results[:MAX_PATCH_LOGGED]:
        if result.diff:
            added, removed = diff_stats(result.diff)
            await ctx.log(f"{result.target.code} 补丁已生成：{result.summary}（{result.target.file}，+{added} -{removed}）")
        else:
            await ctx.log(f"{result.target.code} 未生成补丁：{result.error}", "warn")
    if len(results) > MAX_PATCH_LOGGED:
        await ctx.log(f"其余 {len(results) - MAX_PATCH_LOGGED} 条见漏洞详情")
    made = sum(1 for r in results if r.diff)
    await ctx.log(f"补丁生成完成：{len(targets)} 条已验证漏洞中 {made} 条生成补丁")


async def run(ctx: TaskContext) -> None:
    ctx.check_stop()
    data = await load_report_data(ctx.task_id)
    if data is None:
        await ctx.log("任务不存在，跳过报告生成", "warn")
        return
    llm = get_llm()
    await make_patches(ctx, data, llm)
    ctx.check_stop()

    score, level, reason = data.summary()
    await ctx.log(f"安全评分 {score}，综合安全等级：{level}（{reason}）")

    counted = len(data.counted)
    enabled = ctx.runtime.llm_enabled
    if counted:
        if enabled and llm.configured:
            await ctx.log(f"交给大模型撰写评估结论与 {counted} 条漏洞的整改行动")
        else:
            await ctx.log("大模型未启用，评估结论按统计数据生成，整改行动采用漏洞类别的默认指引", "warn")
    conclusion, actions, by_model = await write_texts(data, llm, enabled=enabled)
    ctx.check_stop()
    await save_report(ctx.task_id, conclusion, actions, by_model)
    if counted and enabled and llm.configured:
        if not by_model:
            await ctx.log("模型输出不可用，评估结论改用按统计数据生成的文字", "warn")
        if len(actions) < counted:
            await ctx.log(f"{counted - len(actions)} 条漏洞没有拿到模型写的整改行动，改用类别默认指引", "warn")

    # 渲染一次 Markdown，确认报告模板可用；预览与导出时按最新数据重新渲染
    saved = await load_report_data(ctx.task_id)
    markdown = render_markdown(saved) if saved else ""
    verified = sum(f.status == VerifyStatus.VERIFIED for f in data.counted)
    await ctx.log(
        f"报告已生成：{markdown.count(chr(10) + '## ')} 个章节，已验证漏洞 {verified} 条、多步攻击路径 "
        f"{len(data.paths)} 条、整改建议 {counted} 条，可在报告中心预览与导出"
    )
