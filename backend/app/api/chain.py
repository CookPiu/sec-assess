"""攻击路径接口：任务的攻击路径图（节点、带能力说明的边）与多步路径（FR-011、FR-017）。所有登录用户可查看。"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import get_current_user
from app.core.db import get_session
from app.models import AttackPath, ChainEdge, ChainNode, Finding, Task

router = APIRouter(prefix="/api/tasks", tags=["chain"], dependencies=[Depends(get_current_user)])


class ChainNodeOut(BaseModel):
    id: int
    kind: str
    label: str
    finding_id: int | None
    # 漏洞节点附带漏洞的等级、标题与入口路由，供拓扑图着色和提示
    severity: str | None = None
    title: str | None = None
    route: dict[str, Any] | None = None


class ChainEdgeOut(BaseModel):
    id: int
    src: int
    dst: int
    reason: str


class AttackPathOut(BaseModel):
    id: int
    node_ids: list[int]
    target: str
    summary: str | None
    impact: str | None
    # 每一步的节点与进入该节点所依据的能力或条件
    steps: list[dict[str, Any]]
    written_by: str | None


class ChainOut(BaseModel):
    nodes: list[ChainNodeOut]
    edges: list[ChainEdgeOut]
    paths: list[AttackPathOut]


@router.get("/{task_id}/chain", response_model=ChainOut)
async def get_chain(task_id: int, session: AsyncSession = Depends(get_session)) -> ChainOut:
    if await session.get(Task, task_id) is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    rows = (
        await session.execute(
            select(ChainNode, Finding)
            .outerjoin(Finding, ChainNode.finding_id == Finding.id)
            .where(ChainNode.task_id == task_id)
            .order_by(ChainNode.id)
        )
    ).all()
    nodes = [
        ChainNodeOut(
            id=node.id,
            kind=node.kind,
            label=node.label,
            finding_id=node.finding_id,
            severity=finding.severity if finding else None,
            title=finding.title if finding else None,
            route=finding.route if finding else None,
        )
        for node, finding in rows
    ]
    edges = (
        await session.execute(select(ChainEdge).where(ChainEdge.task_id == task_id).order_by(ChainEdge.id))
    ).scalars()
    paths = (
        await session.execute(select(AttackPath).where(AttackPath.task_id == task_id).order_by(AttackPath.id))
    ).scalars()
    return ChainOut(
        nodes=nodes,
        edges=[ChainEdgeOut(id=e.id, src=e.src_id, dst=e.dst_id, reason=e.reason) for e in edges],
        paths=[
            AttackPathOut(
                id=p.id,
                node_ids=p.node_ids,
                target=p.target,
                summary=p.summary,
                impact=p.impact,
                steps=(p.detail or {}).get("steps") or [],
                written_by=(p.detail or {}).get("written_by"),
            )
            for p in paths
        ],
    )
