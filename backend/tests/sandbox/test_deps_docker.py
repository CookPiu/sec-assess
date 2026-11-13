"""真实容器里的依赖准备：宿主机下载 wheel，容器内离线安装；需要 Docker 和访问 PyPI 的网络。"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.core.config import get_settings
from app.sandbox import deps
from app.sandbox.manager import Quota, sandbox_manager

pytestmark = [pytest.mark.docker, pytest.mark.network]

TASK_ID = 990001


@pytest.fixture
def container(tmp_path: Path, app_env):
    if not sandbox_manager.ping():
        pytest.skip("Docker 未启动")
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.py").write_text("print('ok')\n", encoding="utf-8")
    wheels = tmp_path / "wheelhouse"
    wheels.mkdir()
    sandbox_manager.create(TASK_ID, src, get_settings().sandbox_image, Quota(), wheels_dir=wheels)
    yield wheels
    sandbox_manager.destroy(TASK_ID)


def test_prepare_in_real_container(container: Path) -> None:
    target = deps.probe_target(sandbox_manager, TASK_ID)
    assert target.python == "3.12" and target.glibc_minor >= 17

    # PyJWT 不在镜像预装列表里，flask 已预装，最后一个包不存在
    reqs = ["pyjwt==2.9.0", "flask>=3", "sec-assess-no-such-package==0.0.1"]
    ok, failed = deps.download_wheels(reqs, container / target.tag, target, "https://pypi.org/simple", lambda: False)
    assert "pyjwt==2.9.0" in ok and "flask>=3" in ok
    assert list(failed) == ["sec-assess-no-such-package==0.0.1"]
    assert any(p.name.startswith("PyJWT-2.9.0") for p in (container / target.tag).iterdir())

    install_failed = deps.install_in_container(sandbox_manager, TASK_ID, ok, f"{deps.WHEELS_MOUNT}/{target.tag}")
    assert install_failed == {}
    names = [deps.requirement_name(r) for r in reqs]
    installed = deps.check_installed(sandbox_manager, TASK_ID, names)
    result = deps.summarize(reqs, failed, install_failed, installed, target)

    assert result["installed"] == [{"name": "pyjwt", "version": "2.9.0"}]
    assert [p["name"] for p in result["preinstalled"]] == ["flask"]
    assert [m["name"] for m in result["missing"]] == ["sec-assess-no-such-package"]
    run = sandbox_manager.exec(TASK_ID, [deps.VENV_PYTHON, "-c", "import jwt, flask; print(jwt.__version__)"], timeout=30)
    assert run.ok and run.stdout.strip() == "2.9.0"
