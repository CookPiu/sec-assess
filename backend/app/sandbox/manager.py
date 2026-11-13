"""每个评估任务一个容器：创建、执行命令、复制工程副本、销毁与遗留清理（D-001、D-016）。

docker SDK 是同步接口，异步代码里通过 asyncio.to_thread 调用。
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

import docker
from docker.errors import APIError, DockerException, ImageNotFound, NotFound
from docker.models.containers import Container

logger = logging.getLogger(__name__)

LABEL = "sec-assess"
LABEL_TASK = "sec-assess.task"
SANDBOX_USER = "10001:10001"
TIMEOUT_EXIT_CODE = 124  # coreutils timeout 超时退出码


class SandboxError(RuntimeError):
    pass


@dataclass(frozen=True)
class Quota:
    cpus: float = 1.0
    memory_mb: int = 1024
    pids: int = 256


@dataclass(frozen=True)
class ExecResult:
    exit_code: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.exit_code == 0

    @property
    def timed_out(self) -> bool:
        return self.exit_code == TIMEOUT_EXIT_CODE


def container_name(task_id: int) -> str:
    return f"sec-assess-task-{task_id}"


def volume_name(task_id: int) -> str:
    return f"sec-assess-work-{task_id}"


def _decode(data: bytes | None) -> str:
    return data.decode("utf-8", errors="replace") if data else ""


class SandboxManager:
    def __init__(self, client: docker.DockerClient | None = None) -> None:
        self._client = client

    @property
    def client(self) -> docker.DockerClient:
        if self._client is None:
            try:
                self._client = docker.from_env()
            except DockerException as exc:
                raise SandboxError(f"无法连接 Docker：{exc}") from exc
        return self._client

    def ping(self) -> bool:
        try:
            return bool(self.client.ping())
        except (DockerException, SandboxError):
            return False

    def image_exists(self, image: str) -> bool:
        try:
            self.client.images.get(image)
            return True
        except ImageNotFound:
            return False

    def create(
        self,
        task_id: int,
        src_dir: Path,
        image: str,
        quota: Quota,
        *,
        wheels_dir: Path | None = None,
        probe_dir: Path | None = None,
    ) -> str:
        """创建并启动任务容器，返回容器 ID。同名遗留容器和卷会先被删除。"""
        if not src_dir.is_dir():
            raise SandboxError(f"源码目录不存在：{src_dir}")
        if not self.image_exists(image):
            raise SandboxError(f"沙箱镜像不存在：{image}，请先运行 sandbox-images/build.ps1")
        self.destroy(task_id)

        labels = {LABEL: "1", LABEL_TASK: str(task_id)}
        work_volume = volume_name(task_id)
        self.client.volumes.create(name=work_volume, labels=labels)

        volumes: dict[str, dict[str, str]] = {
            str(src_dir.resolve()): {"bind": "/src", "mode": "ro"},
            work_volume: {"bind": "/work", "mode": "rw"},
        }
        if wheels_dir is not None:
            volumes[str(wheels_dir.resolve())] = {"bind": "/wheels", "mode": "ro"}
        if probe_dir is not None:
            volumes[str(probe_dir.resolve())] = {"bind": "/opt/probe", "mode": "ro"}

        try:
            container: Container = self.client.containers.run(
                image,
                command=["sleep", "infinity"],
                name=container_name(task_id),
                labels=labels,
                detach=True,
                init=True,
                user=SANDBOX_USER,
                working_dir="/work",
                environment={"HOME": "/work", "PYTHONDONTWRITEBYTECODE": "1"},
                read_only=True,
                network_mode="none",
                cap_drop=["ALL"],
                security_opt=["no-new-privileges:true"],
                nano_cpus=int(quota.cpus * 1_000_000_000),
                mem_limit=f"{quota.memory_mb}m",
                memswap_limit=f"{quota.memory_mb}m",
                pids_limit=quota.pids,
                tmpfs={"/tmp": "rw,nosuid,nodev,size=64m,mode=1777"},
                volumes=volumes,
            )
        except (APIError, DockerException) as exc:
            self.destroy(task_id)
            raise SandboxError(f"创建沙箱容器失败：{exc}") from exc
        logger.info("任务 %s 的沙箱容器已启动：%s", task_id, container.short_id)
        return container.id

    def _container(self, task_id: int) -> Container:
        try:
            return self.client.containers.get(container_name(task_id))
        except NotFound as exc:
            raise SandboxError(f"任务 {task_id} 的沙箱容器不存在") from exc

    def exists(self, task_id: int) -> bool:
        try:
            self.client.containers.get(container_name(task_id))
            return True
        except NotFound:
            return False

    def exec(
        self,
        task_id: int,
        cmd: list[str],
        *,
        timeout: int | None = None,
        workdir: str = "/work",
        env: dict[str, str] | None = None,
    ) -> ExecResult:
        """在容器内执行命令并等待结束。timeout 由容器内的 coreutils timeout 实现，超时退出码为 124。"""
        if timeout is not None:
            cmd = ["timeout", "--kill-after=2", str(timeout), *cmd]
        container = self._container(task_id)
        try:
            exit_code, (stdout, stderr) = container.exec_run(
                cmd, workdir=workdir, environment=env, demux=True
            )
        except (APIError, DockerException) as exc:
            raise SandboxError(f"容器内执行失败：{exc}") from exc
        return ExecResult(exit_code=exit_code if exit_code is not None else -1, stdout=_decode(stdout), stderr=_decode(stderr))

    def exec_detached(
        self,
        task_id: int,
        cmd: list[str],
        *,
        workdir: str = "/work",
        env: dict[str, str] | None = None,
    ) -> None:
        """后台启动一个长期运行的进程（例如工程副本），不等待结束。"""
        container = self._container(task_id)
        try:
            container.exec_run(cmd, workdir=workdir, environment=env, detach=True)
        except (APIError, DockerException) as exc:
            raise SandboxError(f"容器内启动进程失败：{exc}") from exc

    def copy_source(self, task_id: int) -> ExecResult:
        """把只读的 /src 复制成可写的工程副本 /work/app。"""
        return self.exec(
            task_id,
            ["sh", "-c", "rm -rf /work/app && mkdir -p /work/app && cp -r /src/. /work/app/"],
            timeout=120,
        )

    def destroy(self, task_id: int) -> None:
        """强制删除任务容器和任务卷；不存在时什么也不做。"""
        try:
            self.client.containers.get(container_name(task_id)).remove(force=True)
        except NotFound:
            pass
        except APIError as exc:
            logger.warning("删除任务 %s 的容器失败：%s", task_id, exc)
        try:
            self.client.volumes.get(volume_name(task_id)).remove(force=True)
        except NotFound:
            pass
        except APIError as exc:
            logger.warning("删除任务 %s 的工作卷失败：%s", task_id, exc)

    def cleanup_leftovers(self) -> int:
        """删除所有带本系统标签的容器和卷，返回删除的容器数。后端启动时调用。"""
        removed = 0
        for container in self.client.containers.list(all=True, filters={"label": LABEL}):
            try:
                container.remove(force=True)
                removed += 1
            except APIError as exc:
                logger.warning("清理遗留容器 %s 失败：%s", container.name, exc)
        for volume in self.client.volumes.list(filters={"label": LABEL}):
            try:
                volume.remove(force=True)
            except APIError as exc:
                logger.warning("清理遗留卷 %s 失败：%s", volume.name, exc)
        return removed


sandbox_manager = SandboxManager()
