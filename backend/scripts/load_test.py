"""评估压测：在独立的后端实例上按不同并发上限成批提交靶场评估，统计吞吐、排队、阶段耗时、接口延迟、事件流延迟和沙箱资源。

脚本自己启动一个后端子进程，使用临时数据目录和空闲端口，不影响开发后端和它的数据库；
数据目录里复制一份 data/wheelhouse，依赖准备与开发环境一致。需要 Docker 已启动、.env 已配置。

用法（在 backend 目录）：
    uv run python scripts/load_test.py --levels 1,2,4 --tasks 8 --llm off --out lt-off.json
    uv run python scripts/load_test.py --levels 4 --tasks 8 --llm on --out lt-on.json
"""

from __future__ import annotations

import argparse
import io
import json
import math
import os
import shutil
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[2]
TARGETS = ("shop-admin", "user-center")
STAGE_ORDER = ("环境侦察", "源码审计", "动态验证", "攻击路径推演", "补丁与报告")
FINAL = {"completed", "failed", "stopped"}
ACTIVE = {"created", "running"}


def log(msg: str) -> None:
    print(time.strftime("%H:%M:%S"), msg, flush=True)


def pct(values: list[float], q: float) -> float | None:
    """最近秩法分位数，样本为空时返回 None。"""
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(q * len(ordered)) - 1))
    return round(ordered[index], 3)


def summary(values: list[float]) -> dict:
    if not values:
        return {"n": 0}
    return {
        "n": len(values),
        "mean": round(statistics.fmean(values), 3),
        "p50": pct(values, 0.5),
        "p95": pct(values, 0.95),
        "max": round(max(values), 3),
    }


def parse_time(text: str) -> datetime:
    value = datetime.fromisoformat(text)
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def target_zip(name: str) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for path in sorted((ROOT / "targets" / name).rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".db":
                archive.write(path, f"{name}/{path.relative_to(ROOT / 'targets' / name).as_posix()}")
    return buffer.getvalue()


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Server:
    """独立后端实例：临时数据目录 + 空闲端口。"""

    def __init__(self, data_dir: Path, port: int) -> None:
        self.data_dir = data_dir
        self.port = port
        self.base = f"http://127.0.0.1:{port}"
        self.proc: subprocess.Popen | None = None
        self.log_file = None

    def start(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        wheels = ROOT / "data" / "wheelhouse"
        if wheels.is_dir() and not (self.data_dir / "wheelhouse").exists():
            shutil.copytree(wheels, self.data_dir / "wheelhouse")
        env = {**os.environ, "DATA_DIR": str(self.data_dir), "API_PORT": str(self.port), "PYTHONIOENCODING": "utf-8"}
        self.log_file = open(self.data_dir / "server.log", "w", encoding="utf-8")  # noqa: SIM115
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "app.main"],
            cwd=ROOT / "backend",
            env=env,
            stdout=self.log_file,
            stderr=subprocess.STDOUT,
        )
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(f"后端启动失败，见 {self.data_dir / 'server.log'}")
            try:
                httpx.get(f"{self.base}/docs", timeout=2)
                return
            except httpx.HTTPError:
                time.sleep(0.5)
        raise TimeoutError("后端 60 秒内未就绪")

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        if self.log_file:
            self.log_file.close()


class Client:
    def __init__(self, base: str, password: str) -> None:
        self.http = httpx.Client(base_url=base, timeout=120)
        self.tokens = {u: self._login(u, password) for u in ("engineer", "admin")}

    def _login(self, user: str, password: str) -> str:
        resp = self.http.post("/api/auth/login", json={"username": user, "password": password})
        resp.raise_for_status()
        return resp.json()["token"]

    def headers(self, user: str = "engineer") -> dict[str, str]:
        return {"Authorization": f"Bearer {self.tokens[user]}"}

    def get(self, path: str, user: str = "engineer", **kw) -> httpx.Response:
        return self.http.get(path, headers=self.headers(user), **kw)


def listen(base: str, token: str, task_id: int, sink: list, stop: threading.Event) -> None:
    """订阅任务事件流，记录每条日志事件的推送延迟和资源事件的到达时间。"""
    try:
        with httpx.Client(base_url=base, timeout=httpx.Timeout(60, read=None)) as client:
            with client.stream("GET", f"/api/tasks/{task_id}/events", headers={"Authorization": f"Bearer {token}"}) as resp:
                kind = None
                for line in resp.iter_lines():
                    now = time.time()
                    if stop.is_set():
                        return
                    if line.startswith("event: "):
                        kind = line[7:]
                    elif line.startswith("data: ") and kind:
                        data = json.loads(line[6:]).get("data")
                        if kind == "log" and isinstance(data, dict) and data.get("created_at"):
                            sink.append(("log", now - parse_time(data["created_at"]).timestamp()))
                        elif kind == "metrics":
                            sink.append(("metrics", now))
                        elif kind == "status" and isinstance(data, dict) and data.get("status") in FINAL:
                            return
    except Exception as exc:  # 记录后继续，压测不因单个事件流中断
        sink.append(("error", str(exc)))


def probe_api(client: Client, task_ids: list[int], sink: dict[str, list[float]], stop: threading.Event) -> None:
    """评估进行期间持续请求页面会用到的接口，记录响应时间（毫秒）。"""
    i = 0
    while not stop.is_set():
        task_id = task_ids[i % len(task_ids)]
        for name, path in (
            ("GET /api/projects", "/api/projects"),
            ("GET /api/tasks/{id}", f"/api/tasks/{task_id}"),
            ("GET /api/tasks/{id}/findings", f"/api/tasks/{task_id}/findings"),
        ):
            start = time.perf_counter()
            try:
                ok = client.get(path).status_code == 200
            except httpx.HTTPError:
                ok = False
            sink.setdefault(name, []).append((time.perf_counter() - start) * 1000 if ok else -1)
        i += 1
        stop.wait(0.5)


def parse_size(text: str) -> float:
    """docker stats 的内存读数换算为 MB。"""
    text = text.strip()
    units = {"KiB": 1 / 1024, "MiB": 1, "GiB": 1024, "kB": 1 / 1000, "MB": 1, "GB": 1000, "B": 1 / 1024 / 1024}
    for unit, factor in units.items():
        if text.endswith(unit):
            return float(text[: -len(unit)]) * factor
    return 0.0


def sample_docker(prefix: str, sink: list, stop: threading.Event) -> None:
    """周期读取本实例沙箱容器的 CPU 与内存，记录同时存在的容器数和合计用量。"""
    while not stop.is_set():
        proc = subprocess.run(
            ["docker", "stats", "--no-stream", "--format", "{{json .}}"], capture_output=True, text=True, timeout=30
        )
        rows = [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]
        mine = [r for r in rows if r.get("Name", "").startswith(prefix)]
        cpu = sum(float(r["CPUPerc"].rstrip("%") or 0) for r in mine)
        mem = sum(parse_size(r["MemUsage"].split("/")[0]) for r in mine)
        sink.append({"t": time.time(), "containers": len(mine), "cpu_pct": round(cpu, 1), "mem_mb": round(mem, 1)})
        stop.wait(1)


def stage_durations(logs: list[dict]) -> dict[str, float]:
    out = {}
    for item in logs:
        message = item["message"]
        if message.startswith("阶段结束："):
            label, _, rest = message[len("阶段结束：") :].partition("，用时 ")
            try:
                out[label] = float(rest.split(" ")[0])
            except ValueError:
                continue
    return out


def wait_idle(client: Client, task_ids: list[int], timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while task_ids and time.monotonic() < deadline:
        if all(client.get(f"/api/tasks/{t}").json()["status"] in FINAL for t in task_ids):
            return
        time.sleep(1)


def run_level(client: Client, base: str, prefix: str, level: int, n_tasks: int, llm: bool, timeout: float) -> dict:
    resp = client.http.put(
        "/api/settings", headers=client.headers("admin"), json={"max_concurrent": level, "llm_enabled": llm}
    )
    resp.raise_for_status()
    zips = {name: target_zip(name) for name in TARGETS}

    stop = threading.Event()
    docker_samples: list = []
    sampler = threading.Thread(target=sample_docker, args=(prefix, docker_samples, stop), daemon=True)
    sampler.start()

    # 一次性提交整批任务，超出并发上限的进入排队
    tasks, submit_ms = [], []
    for i in range(n_tasks):
        name = TARGETS[i % len(TARGETS)]
        start = time.perf_counter()
        r = client.http.post(
            "/api/tasks", headers=client.headers(), files={"file": (f"{name}.zip", zips[name], "application/zip")}
        )
        submit_ms.append((time.perf_counter() - start) * 1000)
        r.raise_for_status()
        tasks.append({"id": r.json()["id"], "target": name})
    task_ids = [t["id"] for t in tasks]
    log(f"并发 {level}：已提交任务 {task_ids[0]}–{task_ids[-1]}")

    events: dict[int, list] = {t: [] for t in task_ids}
    listeners = [
        threading.Thread(target=listen, args=(base, client.tokens["engineer"], t, events[t], stop), daemon=True)
        for t in task_ids
    ]
    for th in listeners:
        th.start()
    api_lat: dict[str, list[float]] = {}
    prober = threading.Thread(target=probe_api, args=(client, task_ids, api_lat, stop), daemon=True)
    prober.start()

    max_running = 0
    deadline = time.monotonic() + timeout
    while True:
        statuses = [client.get(f"/api/tasks/{t}").json()["status"] for t in task_ids]
        max_running = max(max_running, statuses.count("running"))
        if all(s in FINAL for s in statuses):
            break
        if time.monotonic() > deadline:
            log(f"并发 {level}：等待超时，停止剩余任务")
            for t, s in zip(task_ids, statuses):
                if s in ACTIVE:
                    client.http.post(f"/api/tasks/{t}/stop", headers=client.headers())
            wait_idle(client, task_ids, 60)
            break
        time.sleep(1)
    stop.set()
    for th in (*listeners, prober, sampler):
        th.join(timeout=10)

    rows = []
    for t in tasks:
        body = client.get(f"/api/tasks/{t['id']}").json()
        logs = client.get(f"/api/tasks/{t['id']}/logs").json()
        findings = client.get(f"/api/tasks/{t['id']}/findings").json()
        created, started, finished = (
            parse_time(body[k]) if body[k] else None for k in ("created_at", "started_at", "finished_at")
        )
        rows.append({
            "id": t["id"],
            "target": t["target"],
            "status": body["status"],
            "error": body["error"],
            "queue_s": (started - created).total_seconds() if started else None,
            "run_s": (finished - started).total_seconds() if started and finished else None,
            "e2e_s": (finished - created).total_seconds() if finished else None,
            "created": created.timestamp(),
            "finished": finished.timestamp() if finished else None,
            "stages": stage_durations(logs),
            "verified": sum(1 for f in findings if f["status"] == "verified"),
            "findings": len(findings),
        })

    done = [r for r in rows if r["finished"]]
    makespan = max(r["finished"] for r in done) - min(r["created"] for r in rows) if done else None
    log_lat = [v for evs in events.values() for kind, v in evs if kind == "log"]
    gaps = []
    for evs in events.values():
        times = [v for kind, v in evs if kind == "metrics"]
        gaps += [b - a for a, b in zip(times, times[1:])]
    seen = {s for r in rows for s in r["stages"]}
    stage_names = [s for s in STAGE_ORDER if s in seen] + sorted(seen - set(STAGE_ORDER))
    by_target = {}
    for name in TARGETS:
        mine = [r for r in rows if r["target"] == name and r["status"] == "completed"]
        by_target[name] = {
            "completed": len(mine),
            "verified_min": min((r["verified"] for r in mine), default=None),
            "verified_max": max((r["verified"] for r in mine), default=None),
            "run_s": summary([r["run_s"] for r in mine if r["run_s"] is not None]),
        }
    return {
        "level": level,
        "llm": llm,
        "tasks": n_tasks,
        "status": {s: sum(1 for r in rows if r["status"] == s) for s in sorted({r["status"] for r in rows})},
        "makespan_s": round(makespan, 1) if makespan else None,
        "throughput_per_min": round(len(done) / makespan * 60, 2) if makespan else None,
        "max_running_observed": max_running,
        "max_containers_observed": max((s["containers"] for s in docker_samples), default=0),
        "submit_ms": summary(submit_ms),
        "queue_s": summary([r["queue_s"] for r in rows if r["queue_s"] is not None]),
        "run_s": summary([r["run_s"] for r in rows if r["run_s"] is not None]),
        "e2e_s": summary([r["e2e_s"] for r in rows if r["e2e_s"] is not None]),
        "stage_mean_s": {
            s: round(statistics.fmean([r["stages"][s] for r in rows if s in r["stages"]]), 2) for s in stage_names
        },
        "api_ms": {
            k: {**summary([v for v in vs if v >= 0]), "errors": sum(1 for v in vs if v < 0)} for k, vs in api_lat.items()
        },
        "sse_log_latency_s": summary(log_lat),
        "sse_metrics_gap_s": summary(gaps),
        "sse_errors": sum(1 for evs in events.values() for kind, _ in evs if kind == "error"),
        "sandbox_peak": {
            "cpu_pct": max((s["cpu_pct"] for s in docker_samples), default=0),
            "mem_mb": max((s["mem_mb"] for s in docker_samples), default=0),
        },
        "by_target": by_target,
        "rows": rows,
    }


def print_table(results: list[dict]) -> None:
    head = "| 并发 | 大模型 | 任务 | 完成 | 总耗时 s | 吞吐 个/分 | 排队 p50/max s | 单任务 p50/p95 s | 接口 p95 ms | 日志推送 p95 s |"
    print(head)
    print("|" + "---|" * (head.count("|") - 1))
    for r in results:
        api_p95 = max((v.get("p95") or 0) for v in r["api_ms"].values()) if r["api_ms"] else None
        print(
            f"| {r['level']} | {'开' if r['llm'] else '关'} | {r['tasks']} | {r['status'].get('completed', 0)} "
            f"| {r['makespan_s']} | {r['throughput_per_min']} | {r['queue_s'].get('p50')}/{r['queue_s'].get('max')} "
            f"| {r['run_s'].get('p50')}/{r['run_s'].get('p95')} | {api_p95} | {r['sse_log_latency_s'].get('p95')} |"
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--levels", default="1,2,4", help="逗号分隔的并发上限，取值 1–4")
    parser.add_argument("--tasks", type=int, default=8, help="每档提交的任务数，两个靶场交替")
    parser.add_argument("--llm", choices=("on", "off"), default="off", help="是否调用大模型")
    parser.add_argument("--timeout", type=float, default=1800, help="每档最长等待秒数")
    parser.add_argument("--data-dir", type=Path, help="独立实例的数据目录，默认新建临时目录")
    parser.add_argument("--out", type=Path, help="结果 JSON 输出路径")
    args = parser.parse_args()

    data_dir = (args.data_dir or Path(tempfile.mkdtemp(prefix="sec-assess-lt-"))).resolve()
    # 与后端同一套规则推导实例标识，只统计本实例的沙箱容器
    os.environ["DATA_DIR"] = str(data_dir)
    sys.path.insert(0, str(ROOT / "backend"))
    from app.core.config import get_settings
    from app.sandbox.manager import instance_id

    server = Server(data_dir, free_port())
    log(f"启动独立后端 {server.base}，数据目录 {data_dir}")
    server.start()
    results = []
    try:
        client = Client(server.base, get_settings().seed_password)
        prefix = f"sec-assess-{instance_id()}-"
        for level in (int(x) for x in args.levels.split(",")):
            started = time.time()
            result = run_level(client, server.base, prefix, level, args.tasks, args.llm == "on", args.timeout)
            log(f"并发 {level} 结束，用时 {time.time() - started:.0f} 秒：{result['status']}")
            results.append(result)
            if args.out:
                args.out.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    finally:
        server.stop()
    print_table(results)


if __name__ == "__main__":
    main()
