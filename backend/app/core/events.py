"""进程内事件总线：流水线与资源采样线程发布事件，SSE 接口按任务订阅（FR-014）。

事件类型：stage（阶段变化）、log（日志行）、metrics（资源指标）、status（任务状态）。
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections import defaultdict
from typing import Any

from app.core.db import utcnow

logger = logging.getLogger(__name__)

QUEUE_SIZE = 500


class EventBus:
    def __init__(self) -> None:
        self._subscribers: dict[int, set[asyncio.Queue[dict[str, Any]]]] = defaultdict(set)
        self._loop: asyncio.AbstractEventLoop | None = None

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    def subscribe(self, task_id: int) -> asyncio.Queue[dict[str, Any]]:
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=QUEUE_SIZE)
        self._subscribers[task_id].add(queue)
        return queue

    def unsubscribe(self, task_id: int, queue: asyncio.Queue[dict[str, Any]]) -> None:
        subs = self._subscribers.get(task_id)
        if subs is None:
            return
        subs.discard(queue)
        if not subs:
            self._subscribers.pop(task_id, None)

    def publish(self, task_id: int, event_type: str, data: dict[str, Any]) -> None:
        """可在事件循环线程或其他线程中调用；没有订阅者时直接丢弃。"""
        event = {"type": event_type, "data": data, "ts": utcnow().isoformat() + "Z"}
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is not None and (self._loop is None or running is self._loop):
            self._deliver(task_id, event)
        elif self._loop is not None and not self._loop.is_closed():
            self._loop.call_soon_threadsafe(self._deliver, task_id, event)
        else:
            logger.debug("事件循环未绑定，丢弃任务 %s 的 %s 事件", task_id, event_type)

    def _deliver(self, task_id: int, event: dict[str, Any]) -> None:
        for queue in list(self._subscribers.get(task_id, ())):
            if queue.full():
                # 前端处理不过来时丢掉最旧的一条，保证最新状态能送达
                try:
                    queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            queue.put_nowait(event)


def format_sse(event: dict[str, Any]) -> str:
    payload = json.dumps({"data": event["data"], "ts": event["ts"]}, ensure_ascii=False)
    return f"event: {event['type']}\ndata: {payload}\n\n"


bus = EventBus()
