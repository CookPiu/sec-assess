"""资源采样：读取 Docker stats 流，约每秒回调一次 CPU、内存、进程数（FR-014）。"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from typing import Any

from docker.errors import APIError, NotFound

from app.sandbox.manager import SandboxManager, container_name

logger = logging.getLogger(__name__)


def parse_stats(raw: dict[str, Any]) -> dict[str, float | int]:
    """把 Docker stats 原始数据换算成百分比与 MB。字段缺失时按 0 处理。"""
    cpu = raw.get("cpu_stats") or {}
    pre = raw.get("precpu_stats") or {}
    cpu_delta = (cpu.get("cpu_usage") or {}).get("total_usage", 0) - (pre.get("cpu_usage") or {}).get(
        "total_usage", 0
    )
    sys_delta = cpu.get("system_cpu_usage", 0) - pre.get("system_cpu_usage", 0)
    online = cpu.get("online_cpus") or len((cpu.get("cpu_usage") or {}).get("percpu_usage") or []) or 1
    cpu_percent = cpu_delta / sys_delta * online * 100 if sys_delta > 0 and cpu_delta > 0 else 0.0

    mem = raw.get("memory_stats") or {}
    mem_stats = mem.get("stats") or {}
    cache = mem_stats.get("inactive_file", mem_stats.get("cache", 0))
    used = max(mem.get("usage", 0) - cache, 0)
    limit = mem.get("limit", 0)

    return {
        "cpu_percent": round(cpu_percent, 1),
        "memory_mb": round(used / 1024 / 1024, 1),
        "memory_limit_mb": round(limit / 1024 / 1024, 1),
        "pids": int((raw.get("pids_stats") or {}).get("current", 0)),
    }


class StatsSampler:
    """后台线程持续读取 stats 流；容器被删除或调用 stop 后结束。"""

    def __init__(
        self,
        manager: SandboxManager,
        task_id: int,
        on_sample: Callable[[dict[str, float | int]], None],
        # Docker stats 流约每秒一个样本；节流阈值小于该间隔即逐个推送，刷新间隔约 1 秒（SC-005 要求不超过 2 秒）
        interval: float = 0.5,
    ) -> None:
        self._manager = manager
        self._task_id = task_id
        self._on_sample = on_sample
        self._interval = interval
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name=f"stats-{task_id}", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        try:
            container = self._manager.client.containers.get(container_name(self._task_id))
            last = 0.0
            for raw in container.stats(stream=True, decode=True):
                if self._stop.is_set():
                    break
                now = time.monotonic()
                if now - last < self._interval:
                    continue
                last = now
                self._on_sample(parse_stats(raw))
        except (NotFound, APIError):
            pass
        except Exception:  # 采样失败不影响评估流程
            logger.exception("任务 %s 的资源采样异常结束", self._task_id)
