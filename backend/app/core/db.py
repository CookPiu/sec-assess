"""数据库引擎与会话。启动时调用 setup_engine，测试可传入临时库地址。"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime

from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


def utcnow() -> datetime:
    """统一用不带时区的 UTC 时间入库，SQLite 不保存时区信息。"""
    return datetime.now(UTC).replace(tzinfo=None)


_engine: AsyncEngine | None = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


def setup_engine(url: str) -> AsyncEngine:
    global _engine, _sessionmaker
    engine = create_async_engine(url, connect_args={"timeout": 30})

    if url.startswith("sqlite"):

        @event.listens_for(engine.sync_engine, "connect")
        def _sqlite_pragmas(dbapi_conn, _record) -> None:
            cursor = dbapi_conn.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.close()

    _engine = engine
    _sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
    return engine


def get_engine() -> AsyncEngine:
    if _engine is None:
        raise RuntimeError("数据库引擎尚未初始化，请先调用 setup_engine")
    return _engine


def session_factory() -> async_sessionmaker[AsyncSession]:
    if _sessionmaker is None:
        raise RuntimeError("数据库引擎尚未初始化，请先调用 setup_engine")
    return _sessionmaker


async def get_session() -> AsyncIterator[AsyncSession]:
    async with session_factory()() as session:
        yield session


async def init_db() -> None:
    import app.models  # noqa: F401  注册全部表

    async with get_engine().begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def dispose_engine() -> None:
    global _engine, _sessionmaker
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _sessionmaker = None
