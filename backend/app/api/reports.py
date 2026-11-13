"""报告接口：报告中心列表、在线预览与 Markdown / HTML / PDF 导出（FR-015、FR-020）。

所有登录用户可查看列表与预览；导出限安全工程师与研发人员，每次导出写审计日志。
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.tasks import SeverityCounts, severity_counts
from app.chain.assemble import RUN_CODE
from app.core import audit
from app.core.auth import get_current_user, require_roles
from app.core.db import get_session
from app.models import AttackPath, Finding, Project, Task, User
from app.models.enums import Role, TaskStatus, VerifyStatus
from app.report.pdf import PdfUnavailable, render_pdf
from app.report.render import ReportData, load_report_data, markdown_to_html, render_markdown, report_title
from app.report.scoring import ScoreItem, overall_level, security_score

router = APIRouter(prefix="/api", tags=["reports"], dependencies=[Depends(get_current_user)])

MEDIA_TYPES = {
    "md": "text/markdown; charset=utf-8",
    "html": "text/html; charset=utf-8",
    "pdf": "application/pdf",
}


class ReportBrief(BaseModel):
    task_id: int
    project_id: int
    project_name: str
    finished_at: datetime | None
    score: int
    level: str
    counts: SeverityCounts


class ReportOut(BaseModel):
    task_id: int
    project_name: str
    title: str
    score: int
    level: str
    level_reason: str
    html: str


@router.get("/reports", response_model=list[ReportBrief])
async def list_reports(session: AsyncSession = Depends(get_session)) -> list[ReportBrief]:
    """已完成的评估任务，最新的在前。"""
    rows = (
        await session.execute(
            select(Task, Project.name)
            .join(Project, Project.id == Task.project_id)
            .where(Task.status == TaskStatus.COMPLETED)
            .order_by(Task.id.desc())
        )
    ).all()
    ids = [task.id for task, _ in rows]
    items: dict[int, list[ScoreItem]] = {i: [] for i in ids}
    rce: set[int] = set()
    if ids:
        for f in (await session.execute(select(Finding).where(Finding.task_id.in_(ids)))).scalars():
            items[f.task_id].append(
                ScoreItem(f.code, f.severity, f.cvss_score, f.status == VerifyStatus.VERIFIED, f.model_false_positive)
            )
        rce = set(
            (
                await session.execute(
                    select(AttackPath.task_id).where(AttackPath.task_id.in_(ids), AttackPath.target == RUN_CODE)
                )
            ).scalars()
        )
    counts = await severity_counts(session, ids)
    return [
        ReportBrief(
            task_id=task.id,
            project_id=task.project_id,
            project_name=name,
            finished_at=task.finished_at,
            score=security_score(items[task.id]),
            level=overall_level(items[task.id], task.id in rce)[0],
            counts=counts[task.id],
        )
        for task, name in rows
    ]


async def _completed_report(task_id: int) -> ReportData:
    data = await load_report_data(task_id)
    if data is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    if data.task.status != TaskStatus.COMPLETED:
        raise HTTPException(status_code=409, detail="评估尚未完成，暂无报告")
    return data


@router.get("/tasks/{task_id}/report", response_model=ReportOut)
async def preview_report(task_id: int) -> ReportOut:
    data = await _completed_report(task_id)
    score, level, reason = data.summary()
    title = report_title(data)
    return ReportOut(
        task_id=task_id,
        project_name=data.project.name,
        title=title,
        score=score,
        level=level,
        level_reason=reason,
        html=markdown_to_html(render_markdown(data), title),
    )


def _attachment(filename: str, fallback: str) -> str:
    """中文文件名用 RFC 5987 编码，旧客户端退回 ASCII 文件名。"""
    return f"attachment; filename=\"{fallback}\"; filename*=UTF-8''{quote(filename)}"


@router.get("/tasks/{task_id}/report/export")
async def export_report(
    task_id: int,
    fmt: Literal["md", "html", "pdf"] = Query(alias="format"),
    user: User = Depends(require_roles(Role.ENGINEER, Role.DEVELOPER)),
    session: AsyncSession = Depends(get_session),
) -> Response:
    data = await _completed_report(task_id)
    title = report_title(data)
    markdown = render_markdown(data)
    if fmt == "md":
        content = markdown.encode("utf-8")
    else:
        html = markdown_to_html(markdown, title)
        if fmt == "html":
            content = html.encode("utf-8")
        else:
            try:
                content = await render_pdf(html)
            except PdfUnavailable as exc:
                raise HTTPException(status_code=503, detail=str(exc)) from exc
    audit.record(
        session,
        audit.AuditAction.REPORT_EXPORT,
        user=user,
        target_type="task",
        target_id=task_id,
        detail={"format": fmt, "project_name": data.project.name},
    )
    await session.commit()
    return Response(
        content=content,
        media_type=MEDIA_TYPES[fmt],
        headers={"Content-Disposition": _attachment(f"{title}-任务{task_id}.{fmt}", f"report-task-{task_id}.{fmt}")},
    )
