"""依赖准备的纯逻辑部分：需求串整理、目标平台、下载重试策略、结果归类。"""

from __future__ import annotations

from pathlib import Path

from app.sandbox import deps
from app.sandbox.deps import Target


def dep(name: str, spec: str = "", ecosystem: str = "pypi", dev: bool = False) -> dict:
    return {"ecosystem": ecosystem, "name": name, "spec": spec, "source": "requirements.txt", "dev": dev}


def test_requirement_specs() -> None:
    reqs, notes = deps.requirement_specs(
        [
            dep("flask", "==3.0.3"),
            dep("pyjwt", ">=2.8, <3"),
            dep("requests", "^2.31"),
            dep("flask", ">=2"),
            dep("pytest", "", dev=True),
            dep("vue", "^3.5", ecosystem="npm"),
            dep("--index-url", ""),
        ]
    )
    assert reqs == ["flask==3.0.3", "pyjwt>=2.8, <3", "requests"]
    assert notes == ["requests 的版本约束 ^2.31 无法识别，按最新版本准备", "跳过无法识别的依赖名：--index-url"]
    assert [deps.requirement_name(r) for r in reqs] == ["flask", "pyjwt", "requests"]


def test_target_platforms_and_download_command(tmp_path: Path) -> None:
    target = Target(machine="x86_64", glibc_minor=36, python="3.12")
    assert target.tag == "cp312-manylinux_2_36_x86_64"
    plats = target.platforms()
    assert plats[0] == "manylinux_2_36_x86_64" and "manylinux_2_17_x86_64" in plats
    assert plats[-1] == "manylinux2014_x86_64"

    cmd = deps.pip_download_cmd(["flask==3.0.3"], tmp_path, target, "https://pypi.org/simple")
    assert "--only-binary=:all:" in cmd and cmd[cmd.index("--abi") + 1] == "cp312"
    # 需求串放在 -- 之后，不会被当成 pip 选项
    assert cmd[-2:] == ["--", "flask==3.0.3"]


def test_download_retries_one_by_one(tmp_path: Path, monkeypatch) -> None:
    calls: list[list[str]] = []

    def fake_run(cmd, timeout, should_stop):
        reqs = cmd[cmd.index("--") + 1 :]
        calls.append(reqs)
        if "nowheel==1.0" in reqs:
            return 1, "ERROR: Could not find a version that satisfies the requirement nowheel==1.0"
        return 0, "Saved"

    monkeypatch.setattr(deps, "_run", fake_run)
    target = Target("x86_64", 36, "3.12")
    ok, failed = deps.download_wheels(["flask", "nowheel==1.0"], tmp_path / "w", target, "https://x", lambda: False)
    assert calls == [["flask", "nowheel==1.0"], ["flask"], ["nowheel==1.0"]]
    assert ok == ["flask"] and failed["nowheel==1.0"].startswith("ERROR: Could not find a version")


def test_download_stops_retrying_when_index_unreachable(tmp_path: Path, monkeypatch) -> None:
    calls: list[list[str]] = []

    def fake_run(cmd, timeout, should_stop):
        calls.append(cmd)
        return 1, "WARNING: Retrying ... NewConnectionError ...\nERROR: No matching distribution found for flask"

    monkeypatch.setattr(deps, "_run", fake_run)
    ok, failed = deps.download_wheels(["flask", "pyjwt"], tmp_path / "w", Target("x86_64", 36, "3.12"), "https://x",
                                      lambda: False)  # fmt: skip
    assert len(calls) == 1 and ok == []
    assert failed == {"flask": "无法连接 PyPI 索引", "pyjwt": "无法连接 PyPI 索引"}


def test_summarize_classifies_sources() -> None:
    reqs = ["flask==3.0.3", "pyjwt==2.9.0", "werkzeug", "ghost==1.0"]
    installed = {
        "flask": {"version": "3.1.0", "location": "/usr/local/lib/python3.12/site-packages"},
        "pyjwt": {"version": "2.9.0", "location": "/work/venv/lib/python3.12/site-packages"},
        "werkzeug": {"version": "3.1.3", "location": "/usr/local/lib/python3.12/site-packages"},
        "ghost": None,
    }
    result = deps.summarize(
        reqs, {"flask==3.0.3": "no wheel", "ghost==1.0": "not found"}, {}, installed, Target("x86_64", 36, "3.12")
    )
    assert result["ok"] is False
    assert result["installed"] == [{"name": "pyjwt", "version": "2.9.0"}]
    assert [(p["name"], p["fallback"]) for p in result["preinstalled"]] == [("flask", True), ("werkzeug", False)]
    assert result["missing"] == [{"name": "ghost", "requirement": "ghost==1.0", "reason": "not found"}]
