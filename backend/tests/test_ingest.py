import io
import stat
import zipfile
from pathlib import Path

import pytest

from app.project.ingest import IngestError, extract_zip, repo_name_from_url, validate_git_url


def make_zip(entries: dict[str, bytes], *, symlinks: tuple[str, ...] = ()) -> io.BytesIO:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
        for name in symlinks:
            info = zipfile.ZipInfo(name)
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(info, "/etc/passwd")
    buf.seek(0)
    return buf


def test_extract_strips_single_top_dir_and_macosx(tmp_path: Path) -> None:
    src = make_zip({"shop/app.py": b"print(1)\n", "shop/templates/a.html": b"<p>", "__MACOSX/shop/._app.py": b"x"})
    dest = tmp_path / "src"
    extract_zip(src, dest)
    assert (dest / "app.py").read_text() == "print(1)\n"
    assert (dest / "templates" / "a.html").exists()
    assert not (dest / "__MACOSX").exists()


def test_extract_keeps_multiple_top_entries(tmp_path: Path) -> None:
    dest = tmp_path / "src"
    extract_zip(make_zip({"app.py": b"", "pkg/mod.py": b""}), dest)
    assert (dest / "app.py").exists() and (dest / "pkg" / "mod.py").exists()


@pytest.mark.parametrize(
    ("entries", "message"),
    [
        ({"../evil.py": b"x"}, "路径穿越"),
        ({"a/../../evil.py": b"x"}, "路径穿越"),
        ({"/etc/evil": b"x"}, "绝对路径"),
        ({"C:/evil": b"x"}, "绝对路径"),
        ({"a\\..\\..\\evil": b"x"}, "路径穿越"),
    ],
)
def test_extract_rejects_unsafe_paths(tmp_path: Path, entries: dict[str, bytes], message: str) -> None:
    dest = tmp_path / "src"
    with pytest.raises(IngestError, match=message):
        extract_zip(make_zip(entries), dest)
    assert not dest.exists()
    assert not (tmp_path / "evil.py").exists()


def test_extract_rejects_symlink(tmp_path: Path) -> None:
    with pytest.raises(IngestError, match="符号链接"):
        extract_zip(make_zip({"app.py": b""}, symlinks=("link",)), tmp_path / "src")


def test_extract_enforces_size_limits(tmp_path: Path) -> None:
    big = make_zip({"a.txt": b"0" * 4096})
    with pytest.raises(IngestError, match="解压后超过"):
        extract_zip(big, tmp_path / "src", max_bytes=1024)
    with pytest.raises(IngestError, match="压缩包超过"):
        extract_zip(make_zip({"a.txt": b"x"}), tmp_path / "src", max_zip_bytes=10)
    with pytest.raises(IngestError, match="条目超过"):
        extract_zip(make_zip({f"{i}.txt": b"" for i in range(5)}), tmp_path / "src", max_entries=3)


def test_extract_rejects_bad_or_empty_zip(tmp_path: Path) -> None:
    with pytest.raises(IngestError, match="有效的 zip"):
        extract_zip(io.BytesIO(b"not a zip"), tmp_path / "src")
    with pytest.raises(IngestError, match="没有文件"):
        extract_zip(make_zip({"__MACOSX/x": b""}), tmp_path / "src")


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/a/b.git",
        "git@github.com:a/b.git",
        "file:///etc",
        "https://user:token@github.com/a/b.git",
        "https://github.com/a/b.git?x=1",
        "https://localhost/a.git",
        "https://127.0.0.1/a.git",
        "https://192.168.1.10/a.git",
        "https://[::1]/a.git",
        "https:///a.git",
    ],
)
def test_validate_git_url_rejects(url: str) -> None:
    with pytest.raises(IngestError):
        validate_git_url(url)


def test_validate_git_url_accepts_public_https() -> None:
    assert validate_git_url("  https://github.com/pallets/flask.git ") == "https://github.com/pallets/flask.git"
    assert repo_name_from_url("https://github.com/pallets/flask.git") == "flask"
    assert repo_name_from_url("https://gitee.com/a/shop-admin/") == "shop-admin"
