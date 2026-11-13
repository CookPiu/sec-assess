from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import get_current_user
from app.core.db import get_session
from app.core.events import bus, format_sse
from app.models import Task

router = APIRouter(prefix="/api/tasks", tags=["events"])

HEARTBEAT_SECONDS = 15


@router.get("/{task_id}/events", dependencies=[Depends(get_current_user)])
async def task_events(task_id: int, request: Request, session: AsyncSession = Depends(get_session)) -> StreamingResponse:
    """任务的实时事件流。前端用 fetch 读取，以便携带 Authorization 头。"""
    if await session.get(Task, task_id) is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    queue = bus.subscribe(task_id)

    async def stream() -> AsyncIterator[str]:
        try:
            yield ": connected\n\n"
            while not await request.is_disconnected():
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=HEARTBEAT_SECONDS)
                except TimeoutError:
                    yield ": ping\n\n"
                    continue
                yield format_sse(event)
        finally:
            bus.unsubscribe(task_id, queue)

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
