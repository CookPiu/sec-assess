from __future__ import annotations

import asyncio
import json
import threading

from app.core.events import QUEUE_SIZE, EventBus, format_sse


def test_publish_from_other_thread_is_delivered() -> None:
    async def scenario() -> dict:
        bus = EventBus()
        bus.bind_loop(asyncio.get_running_loop())
        queue = bus.subscribe(7)
        thread = threading.Thread(target=bus.publish, args=(7, "log", {"message": "hello"}))
        thread.start()
        thread.join()
        return await asyncio.wait_for(queue.get(), timeout=2)

    event = asyncio.run(scenario())
    assert event["type"] == "log"
    assert event["data"] == {"message": "hello"}


def test_events_are_scoped_to_task() -> None:
    async def scenario() -> tuple[int, int]:
        bus = EventBus()
        bus.bind_loop(asyncio.get_running_loop())
        q1, q2 = bus.subscribe(1), bus.subscribe(2)
        bus.publish(1, "stage", {"stage": "recon"})
        return q1.qsize(), q2.qsize()

    assert asyncio.run(scenario()) == (1, 0)


def test_full_queue_drops_oldest() -> None:
    async def scenario() -> dict:
        bus = EventBus()
        bus.bind_loop(asyncio.get_running_loop())
        queue = bus.subscribe(1)
        for i in range(QUEUE_SIZE + 5):
            bus.publish(1, "log", {"i": i})
        assert queue.qsize() == QUEUE_SIZE
        return queue.get_nowait()

    assert asyncio.run(scenario())["data"] == {"i": 5}


def test_unsubscribe_stops_delivery() -> None:
    async def scenario() -> int:
        bus = EventBus()
        bus.bind_loop(asyncio.get_running_loop())
        queue = bus.subscribe(1)
        bus.unsubscribe(1, queue)
        bus.publish(1, "log", {})
        return queue.qsize()

    assert asyncio.run(scenario()) == 0


def test_format_sse() -> None:
    text = format_sse({"type": "metrics", "data": {"cpu_percent": 12.5}, "ts": "2026-11-13T00:00:00Z"})
    lines = text.split("\n")
    assert lines[0] == "event: metrics"
    assert json.loads(lines[1].removeprefix("data: "))["data"] == {"cpu_percent": 12.5}
    assert text.endswith("\n\n")


def test_events_endpoint_requires_login_and_task(client, login) -> None:
    assert client.get("/api/tasks/1/events").status_code == 401
    assert client.get("/api/tasks/999999/events", headers=login("engineer")).status_code == 404
