"""动态验证（DESIGN.md 5.3）：启动工程副本，执行无害用例，命中特征改判 Verified。

依赖未准备好或工程无法在沙箱内启动时跳过整个阶段，相关漏洞保持疑似。
"""

from __future__ import annotations

import asyncio
from typing import Any

from sqlalchemy import select

from app.core.db import session_factory
from app.models import Finding, TaintStep, Task
from app.models.enums import VerifyStatus
from app.pipeline.state import TaskContext
from app.project.pysource import ProjectIndex
from app.sandbox.manager import SandboxError
from app.sandbox.probe import PROBE_DIR
from app.verify.execute import run_verification


async def _load(task_id: int) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    async with session_factory()() as session:
        task = await session.get(Task, task_id)
        if task is None:
            return {}, {}, []
        facts = ((task.recon or {}).get("facts") or {})
        dependencies = task.deps_result or {}
        rows = (
            await session.execute(
                select(Finding)
                .where(Finding.task_id == task_id, Finding.status == VerifyStatus.UNVERIFIED)
                .order_by(Finding.id)
            )
        ).scalars().all()
        findings = [
            {
                "id": row.id,
                "code": row.code,
                "category": row.category,
                "severity": row.severity,
                "file": row.file,
                "line": row.line,
                "route": row.route,
                "model_false_positive": row.model_false_positive,
            }
            for row in rows
        ]
        steps: dict[int, list[dict[str, Any]]] = {item["id"]: [] for item in findings}
        if findings:
            step_rows = (
                await session.execute(
                    select(TaintStep)
                    .where(TaintStep.finding_id.in_(steps))
                    .order_by(TaintStep.finding_id, TaintStep.seq)
                )
            ).scalars().all()
            for step in step_rows:
                steps[step.finding_id].append(
                    {"file": step.file, "line": step.line, "snippet": step.snippet, "note": step.note}
                )
    for item in findings:
        item["steps"] = steps.get(item["id"], [])
    return facts, dependencies, findings


async def run(ctx: TaskContext) -> None:
    ctx.check_stop()
    facts, dependencies, findings = await _load(ctx.task_id)
    if not facts.get("is_flask") or not facts.get("entry"):
        await ctx.log("跳过动态验证：未识别到 Flask 启动入口", "warn")
        return
    if dependencies.get("ok") is not True or dependencies.get("missing"):
        await ctx.log("跳过动态验证：工程依赖未准备就绪", "warn")
        return
    # 大模型判定为误报的候选不进动态验证，避免把误报改判成 Verified
    findings = [item for item in findings if not item["model_false_positive"]]
    if not findings:
        await ctx.log("没有需要动态验证的候选漏洞")
        return
    if not PROBE_DIR.is_dir():
        await ctx.log("探针脚本缺失，跳过动态验证", "warn")
        return
    ctx.check_stop()
    index = await asyncio.to_thread(ProjectIndex, ctx.source_dir)
    try:
        await run_verification(ctx, index, findings, facts)
    except (SandboxError, OSError, ValueError, KeyError) as exc:
        await ctx.log(f"动态验证中止：{exc}，相关漏洞保持疑似", "warn")
