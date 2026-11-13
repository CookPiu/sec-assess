from __future__ import annotations

import asyncio

from app.core.llm import LLMClient, parse_json_reply
from app.sandbox.stats import parse_stats

SAMPLE = {
    "cpu_stats": {
        "cpu_usage": {"total_usage": 2_000_000_000},
        "system_cpu_usage": 20_000_000_000,
        "online_cpus": 4,
    },
    "precpu_stats": {
        "cpu_usage": {"total_usage": 1_000_000_000},
        "system_cpu_usage": 10_000_000_000,
    },
    "memory_stats": {
        "usage": 300 * 1024 * 1024,
        "limit": 1024 * 1024 * 1024,
        "stats": {"inactive_file": 100 * 1024 * 1024},
    },
    "pids_stats": {"current": 12},
}


def test_parse_stats() -> None:
    result = parse_stats(SAMPLE)
    assert result == {"cpu_percent": 40.0, "memory_mb": 200.0, "memory_limit_mb": 1024.0, "pids": 12}


def test_parse_stats_tolerates_missing_fields() -> None:
    assert parse_stats({}) == {"cpu_percent": 0.0, "memory_mb": 0.0, "memory_limit_mb": 0.0, "pids": 0}


def test_parse_json_reply() -> None:
    assert parse_json_reply('{"a": 1}') == {"a": 1}
    assert parse_json_reply('```json\n{"a": 1}\n```') == {"a": 1}
    assert parse_json_reply("[1, 2]") is None
    assert parse_json_reply("不是 JSON") is None


def test_unconfigured_llm_returns_none(app_env) -> None:
    client = LLMClient()
    assert not client.configured
    assert asyncio.run(client.chat_json("system", "user")) is None
