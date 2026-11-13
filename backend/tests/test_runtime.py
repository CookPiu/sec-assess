from __future__ import annotations

from sqlalchemy import delete

from app.core.db import session_factory
from app.core.runtime import RuntimeConfig, load_runtime
from app.models import Setting


def test_defaults_match_spec() -> None:
    cfg = RuntimeConfig()
    assert (cfg.cpus, cfg.memory_mb, cfg.pids) == (1.0, 1024, 256)
    assert (cfg.task_timeout_min, cfg.probe_timeout_s, cfg.max_concurrent) == (30, 10, 1)
    assert cfg.network_policy == "none"


def test_overrides_apply_and_invalid_values_ignored(client, run_async) -> None:
    async def scenario() -> RuntimeConfig:
        async with session_factory()() as session:
            session.add_all(
                [
                    Setting(key="memory_mb", value=2048),
                    Setting(key="cpus", value=-1),
                    Setting(key="network_policy", value="bridge"),
                    Setting(key="unknown_key", value=1),
                ]
            )
            await session.commit()
            try:
                return await load_runtime(session)
            finally:
                await session.execute(delete(Setting))
                await session.commit()

    cfg = run_async(scenario)
    assert cfg.memory_mb == 2048
    assert cfg.cpus == 1.0
    assert cfg.network_policy == "none"
