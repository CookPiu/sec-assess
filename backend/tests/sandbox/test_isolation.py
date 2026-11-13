"""沙箱隔离集成测试（SC-006、SC-007）。需要 Docker 已启动且沙箱镜像已构建，否则跳过。"""

from __future__ import annotations

import os
import random
import threading
import time
from pathlib import Path

import pytest

from app.sandbox.manager import LABEL, LABEL_INSTANCE, Quota, SandboxManager, volume_name
from app.sandbox.stats import StatsSampler

pytestmark = pytest.mark.docker

IMAGE = os.environ.get("SANDBOX_IMAGE", "sec-assess/sandbox-python:3.12")


@pytest.fixture(scope="module")
def manager(app_env) -> SandboxManager:
    # app_env 让本模块使用测试数据目录对应的实例标识，遗留清理不会碰到开发后端的容器
    m = SandboxManager()
    if not m.ping():
        pytest.skip("Docker 未启动")
    if not m.image_exists(IMAGE):
        pytest.skip(f"沙箱镜像 {IMAGE} 未构建")
    return m


@pytest.fixture
def sandbox(manager: SandboxManager, tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "hello.py").write_text("print('hello from copy')\n", encoding="utf-8")
    # 测试用任务号取大数，避免与真实任务的容器重名
    task_id = 9_000_000 + random.randint(0, 999_999)
    manager.create(task_id, src, IMAGE, Quota(cpus=0.5, memory_mb=256, pids=64))
    yield task_id
    manager.destroy(task_id)


def test_runs_as_non_root_and_cannot_escalate(manager: SandboxManager, sandbox: int) -> None:
    assert manager.exec(sandbox, ["id", "-u"]).stdout.strip() == "10001"
    result = manager.exec(sandbox, ["python", "-c", "import os; os.setuid(0)"])
    assert result.exit_code != 0


def test_quota_and_hardening_applied(manager: SandboxManager, sandbox: int) -> None:
    """FR-003：配额与加固项落到容器配置上。"""
    attrs = manager._container(sandbox).attrs
    host = attrs["HostConfig"]
    assert (host["NanoCpus"], host["Memory"], host["MemorySwap"], host["PidsLimit"]) == (
        500_000_000,
        256 * 1024 * 1024,
        256 * 1024 * 1024,
        64,
    )
    assert host["NetworkMode"] == "none" and host["ReadonlyRootfs"] is True
    assert host["CapDrop"] == ["ALL"] and "no-new-privileges:true" in host["SecurityOpt"]
    assert attrs["Config"]["User"] == "10001:10001"
    mounts = {m["Destination"]: m["RW"] for m in attrs["Mounts"]}
    assert mounts["/src"] is False and mounts["/work"] is True


def test_only_loopback_interface_and_no_outbound(manager: SandboxManager, sandbox: int) -> None:
    ifaces = manager.exec(sandbox, ["python", "-c", "import socket; print([n for _, n in socket.if_nameindex()])"])
    assert ifaces.ok, ifaces.stderr
    assert ifaces.stdout.strip() == "['lo']"
    outbound = manager.exec(
        sandbox,
        ["python", "-c", "import socket; socket.create_connection(('1.1.1.1', 80), timeout=3)"],
        timeout=10,
    )
    assert outbound.exit_code != 0


def test_src_and_rootfs_read_only(manager: SandboxManager, sandbox: int) -> None:
    assert manager.exec(sandbox, ["cat", "/src/hello.py"]).ok
    assert not manager.exec(sandbox, ["touch", "/src/new.txt"]).ok
    assert not manager.exec(sandbox, ["touch", "/usr/local/new.txt"]).ok


def test_work_and_tmp_writable(manager: SandboxManager, sandbox: int) -> None:
    assert manager.exec(sandbox, ["touch", "/work/x", "/tmp/x"]).ok


def test_copy_source_creates_writable_copy(manager: SandboxManager, sandbox: int) -> None:
    assert manager.copy_source(sandbox).ok
    result = manager.exec(sandbox, ["python", "hello.py"], workdir="/work/app")
    assert result.stdout.strip() == "hello from copy"
    assert manager.exec(sandbox, ["sh", "-c", "echo x >> /work/app/hello.py"]).ok


def test_exec_timeout(manager: SandboxManager, sandbox: int) -> None:
    result = manager.exec(sandbox, ["sleep", "10"], timeout=1)
    assert result.timed_out


def test_stats_sampler_reports(manager: SandboxManager, sandbox: int) -> None:
    samples: list[dict] = []
    got = threading.Event()

    def on_sample(sample: dict) -> None:
        samples.append(sample)
        got.set()

    sampler = StatsSampler(manager, sandbox, on_sample, interval=0.5)
    sampler.start()
    try:
        assert got.wait(timeout=10), "10 秒内没有收到资源样本"
    finally:
        sampler.stop()
    assert set(samples[0]) == {"cpu_percent", "memory_mb", "memory_limit_mb", "pids"}
    assert samples[0]["memory_limit_mb"] == 256.0


def test_destroy_removes_container_and_volume_quickly(manager: SandboxManager, sandbox: int) -> None:
    start = time.monotonic()
    manager.destroy(sandbox)
    assert time.monotonic() - start < 5
    assert not manager.exists(sandbox)
    assert not manager.client.volumes.list(filters={"name": volume_name(sandbox)})


def test_cleanup_leftovers_spares_other_instances(manager: SandboxManager, sandbox: int) -> None:
    """启动清理只删本实例的遗留容器，另一个后端实例（如开发后端）正在用的容器保留。"""
    other = manager.client.containers.run(
        IMAGE,
        command=["sleep", "infinity"],
        detach=True,
        labels={LABEL: "1", LABEL_INSTANCE: "other000"},
        network_mode="none",
    )
    try:
        assert manager.cleanup_leftovers() >= 1
        assert not manager.exists(sandbox)
        other.reload()
        assert other.status == "running"
    finally:
        other.remove(force=True)
