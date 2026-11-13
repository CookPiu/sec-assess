"""FastAPI 入口。开发启动：在 backend 目录执行 uv run python -m app.main"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI

from app.api import audit, auth, chain, events, findings, projects, tasks
from app.core.auth import seed_users
from app.core.config import get_settings
from app.core.db import dispose_engine, init_db, session_factory, setup_engine
from app.core.events import bus
from app.pipeline.runner import runner
from app.sandbox.manager import sandbox_manager

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    settings.resolved_data_dir.mkdir(parents=True, exist_ok=True)
    setup_engine(settings.resolved_database_url)
    await init_db()
    async with session_factory()() as session:
        await seed_users(session)
    bus.bind_loop(asyncio.get_running_loop())
    await runner.startup()
    yield
    await runner.shutdown()
    await dispose_engine()


app = FastAPI(title="sec-assess", lifespan=lifespan)
app.include_router(auth.router)
app.include_router(audit.router)
app.include_router(projects.router)
app.include_router(tasks.router)
app.include_router(events.router)
app.include_router(findings.router)
app.include_router(chain.router)


@app.get("/api/health")
async def health() -> dict[str, object]:
    docker_ok = await asyncio.to_thread(sandbox_manager.ping)
    return {"status": "ok", "docker": docker_ok}


if __name__ == "__main__":
    s = get_settings()
    uvicorn.run("app.main:app", host=s.api_host, port=s.api_port, reload=False)
