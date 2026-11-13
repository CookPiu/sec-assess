"""攻击路径推演（DESIGN.md 5.4）：规则组装 DAG 与多步路径，大模型只为每条路径写阶段说明和业务危害。

模型不可用、被关闭或输出不合法时，按路径步骤生成模板文字，推演结果不受影响（D-002）。
"""

from __future__ import annotations

import asyncio
from typing import Any

from sqlalchemy import delete, select

from app.chain.assemble import (
    ADMIN,
    RUN_CODE,
    START,
    USER,
    AttackPathDraft,
    ChainFinding,
    ChainGraph,
    build_chain,
)
from app.core.db import session_factory
from app.core.llm import InputTooLarge, LLMClient, get_llm
from app.models import AttackPath, ChainEdge, ChainNode, Evidence, Finding, Task
from app.models.enums import ChainNodeKind, VerifyStatus
from app.pipeline.state import TaskContext

MAX_LOGGED = 10
MAX_SUMMARY_CHARS = 400
MAX_IMPACT_CHARS = 300

SYSTEM_PROMPT = """你是渗透测试报告的撰写人。输入是一条由规则推演出的多步攻击路径，列出每一步的节点和进入该节点所依据的能力或条件。
请据此写阶段说明和业务危害，不要增加输入中没有的步骤、漏洞或利用手法。
只输出一个 JSON 对象：
{"summary": "中文，按步骤顺序说明攻击者在每个阶段做了什么、获得了什么，200 字以内",
 "impact": "中文，说明攻陷目标对业务的潜在危害，120 字以内"}"""

ACTOR = {START: "匿名", USER: "以普通用户身份", ADMIN: "以管理员身份"}
DEFAULT_IMPACT = {
    RUN_CODE: "攻击者可在应用服务器上以应用进程权限执行任意命令，读取或篡改业务数据与配置，并可能以此为跳板继续渗透内网。",
    "读他人数据": "攻击者可读取其他用户的个人资料等敏感数据，造成用户隐私泄露，并可能引发合规风险。",
}


async def _load(task_id: int) -> tuple[dict[str, Any], list[ChainFinding], dict[int, Finding]]:
    async with session_factory()() as session:
        task = await session.get(Task, task_id)
        facts = ((task.recon or {}).get("facts") or {}) if task else {}
        rows = (
            await session.execute(
                select(Finding)
                .where(
                    Finding.task_id == task_id,
                    Finding.status == VerifyStatus.VERIFIED,
                    Finding.model_false_positive.is_(False),
                )
                .order_by(Finding.id)
            )
        ).scalars().all()
        matched: dict[int, str] = {}
        if rows:
            hits = await session.execute(
                select(Evidence.finding_id, Evidence.matched).where(
                    Evidence.finding_id.in_([f.id for f in rows]), Evidence.hit.is_(True)
                )
            )
            for finding_id, text in hits:
                matched.setdefault(finding_id, text)
    findings = [
        ChainFinding(
            id=f.id,
            code=f.code,
            category=f.category,
            title=f.title,
            access=(f.route or {}).get("access"),
            matched=matched.get(f.id),
        )
        for f in rows
    ]
    return facts, findings, {f.id: f for f in rows}


def _route_text(finding: Finding | None) -> str:
    route = (finding.route or {}) if finding else {}
    if not route:
        return ""
    return f"{' / '.join(route.get('methods') or [])} {route.get('path', '')}".strip()


def default_summary(graph: ChainGraph, path: AttackPathDraft, rows: dict[int, Finding]) -> str:
    parts: list[str] = []
    for prev, step in zip(path.steps, path.steps[1:], strict=False):
        node = graph.nodes[step["node"]]
        if node.kind == ChainNodeKind.FINDING:
            finding = rows.get(node.finding_id or 0)
            route = _route_text(finding)
            actor = ACTOR.get(prev["node"], "")
            parts.append(f"{actor}访问 {route}，利用 {node.label}" if route else f"利用 {node.label}")
        elif node.kind == ChainNodeKind.CAPABILITY:
            parts.append(f"{step['via']}，取得{node.label}" if node.label not in step["via"] else step["via"])
        else:
            parts.append(step["via"])
    return "；".join(f"{i}. {text}" for i, text in enumerate(parts, 1)) + "。"


def build_prompt(graph: ChainGraph, path: AttackPathDraft, rows: dict[int, Finding]) -> str:
    lines = [f"攻陷目标：{path.target}", "步骤："]
    for i, step in enumerate(path.steps):
        node = graph.nodes[step["node"]]
        text = f"{i}. [{node.kind}] {node.label}"
        if node.kind == ChainNodeKind.FINDING:
            finding = rows.get(node.finding_id or 0)
            if finding:
                text += f"：{finding.title}（{finding.file}:{finding.line}）"
        if step["via"]:
            text += f"；依据：{step['via']}"
        lines.append(text)
    return "\n".join(lines)


async def describe_paths(
    graph: ChainGraph, rows: dict[int, Finding], llm: LLMClient, *, enabled: bool, concurrency: int
) -> list[tuple[str, str, bool]]:
    """每条路径返回（阶段说明、业务危害、是否来自模型）。"""
    semaphore = asyncio.Semaphore(max(1, concurrency))

    async def describe(path: AttackPathDraft) -> tuple[str, str, bool]:
        reply = None
        if enabled and llm.configured:
            async with semaphore:
                try:
                    reply = await llm.chat_json(SYSTEM_PROMPT, build_prompt(graph, path, rows))
                except InputTooLarge:
                    reply = None
        summary = reply.get("summary") if reply else None
        impact = reply.get("impact") if reply else None
        if isinstance(summary, str) and summary.strip() and isinstance(impact, str) and impact.strip():
            return summary.strip()[:MAX_SUMMARY_CHARS], impact.strip()[:MAX_IMPACT_CHARS], True
        return default_summary(graph, path, rows), DEFAULT_IMPACT.get(path.target, ""), False

    async with asyncio.TaskGroup() as group:
        jobs = [group.create_task(describe(p)) for p in graph.paths]
    return [job.result() for job in jobs]


async def save_chain(task_id: int, graph: ChainGraph, texts: list[tuple[str, str, bool]]) -> list[AttackPath]:
    async with session_factory()() as session:
        # 重复执行时先清掉旧结果；外键按 path → edge → node 的顺序删除
        for model in (AttackPath, ChainEdge, ChainNode):
            await session.execute(delete(model).where(model.task_id == task_id))
        ids: dict[str, int] = {}
        for key, node in graph.nodes.items():
            row = ChainNode(task_id=task_id, kind=node.kind, finding_id=node.finding_id, label=node.label[:100])
            session.add(row)
            await session.flush()
            ids[key] = row.id
        session.add_all(
            ChainEdge(task_id=task_id, src_id=ids[e.src], dst_id=ids[e.dst], reason=e.reason[:200])
            for e in graph.edges
        )
        saved: list[AttackPath] = []
        for path, (summary, impact, by_model) in zip(graph.paths, texts, strict=True):
            row = AttackPath(
                task_id=task_id,
                node_ids=[ids[k] for k in path.nodes],
                target=path.target,
                summary=summary,
                impact=impact,
                detail={
                    "steps": [{**s, "node_id": ids[s["node"]]} for s in path.steps],
                    "written_by": "model" if by_model else "template",
                },
            )
            session.add(row)
            saved.append(row)
        await session.commit()
    return saved


async def run(ctx: TaskContext) -> None:
    ctx.check_stop()
    facts, findings, rows = await _load(ctx.task_id)
    if not findings:
        await ctx.log("没有已验证漏洞，不生成攻击路径")
        return
    graph = build_chain(findings, facts)
    for finding, reason in graph.skipped[:MAX_LOGGED]:
        await ctx.log(f"{finding.code} 未进入攻击路径图：{reason}")
    in_graph = sum(n.kind == ChainNodeKind.FINDING for n in graph.nodes.values())
    await ctx.log(
        f"能力推导完成：{len(findings)} 条已验证漏洞中 {in_graph} 条进入攻击路径图，"
        f"边 {len(graph.edges)} 条，多步攻击路径 {len(graph.paths)} 条"
    )
    if not graph.paths:
        await ctx.log("已验证漏洞之间没有能力衔接，不生成多步攻击路径")
    ctx.check_stop()

    texts: list[tuple[str, str, bool]] = []
    if graph.paths:
        llm = get_llm(**ctx.runtime.llm_options())
        enabled = ctx.runtime.llm_enabled
        if enabled and llm.configured:
            await ctx.log(f"交给大模型撰写 {len(graph.paths)} 条路径的阶段说明与业务危害")
        else:
            await ctx.log("大模型未启用，阶段说明与业务危害按路径步骤生成", "warn")
        texts = await describe_paths(
            graph, rows, llm, enabled=enabled, concurrency=ctx.runtime.llm_concurrency
        )
        ctx.check_stop()
    await save_chain(ctx.task_id, graph, texts)
    for i, path in enumerate(graph.paths[:MAX_LOGGED], 1):
        await ctx.log(f"路径 {i}：{' → '.join(graph.nodes[k].label for k in path.nodes)}")
    if len(graph.paths) > MAX_LOGGED:
        await ctx.log(f"其余 {len(graph.paths) - MAX_LOGGED} 条路径见攻击路径图")
    fallback = sum(not by_model for _, _, by_model in texts)
    if texts and fallback and fallback < len(texts):
        await ctx.log(f"{fallback} 条路径的模型输出不可用，改用按步骤生成的说明", "warn")
