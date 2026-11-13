"""容器内探针脚本的契约：请求编码、报文回传与文件检查。直接用本机 HTTP 服务代替容器内服务。"""

from __future__ import annotations

import base64
import json
import socket
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

RUNNER = Path(__file__).resolve().parents[2] / "sandbox-images" / "probe" / "runner.py"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args) -> None:
        pass

    def _reply(self, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Set-Cookie", "session=probe-cookie; Path=/")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        self._reply({"method": "GET", "path": self.path})

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length)
        self._reply({"method": "POST", "body": raw.decode("utf-8", "replace")[:4000]})


def run_case(case: dict) -> dict:
    encoded = base64.b64encode(json.dumps(case, ensure_ascii=False).encode()).decode()
    proc = subprocess.run(
        [sys.executable, str(RUNNER), encoded], capture_output=True, text=True, timeout=30
    )
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout.strip().splitlines()[-1])


def test_query_and_cookie() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        result = run_case({"port": port, "method": "GET", "path": "/orders", "query": {"keyword": "a b"}})
        assert result["ok"] is True and result["status"] == 200
        assert "keyword=a+b" in result["request_raw"] or "keyword=a%20b" in result["request_raw"]
        assert "GET /orders?keyword=" in result["response_raw"] or result["ok"]
        assert result["set_cookie"] == ["session=probe-cookie; Path=/"]
    finally:
        server.shutdown()
        server.server_close()


def test_multipart_filename_is_preserved(tmp_path: Path) -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        marker = tmp_path / "marker.txt"
        marker.write_text("x", encoding="utf-8")
        case = {
            "port": port,
            "method": "POST",
            "path": "/upload",
            "body": {
                "kind": "multipart",
                "data": {"product_id": "1"},
                "files": [{
                    "field": "image",
                    "filename": "../probe.txt",
                    "content_type": "text/plain",
                    "content_b64": base64.b64encode(b"probe").decode(),
                }],
            },
            "checks": {"files_exist": [str(marker), str(tmp_path / "missing.txt")], "find": {"root": str(tmp_path), "name": "marker.txt"}},
        }
        result = run_case(case)
    finally:
        server.shutdown()
        server.server_close()
    assert result["ok"] is True
    echoed = json.loads(result["body"])["body"]
    assert 'name="image"' in echoed
    assert 'filename="../probe.txt"' in echoed
    assert result["files_exist"] == {str(marker): True, str(tmp_path / "missing.txt"): False}
    assert [Path(p).name for p in result["found"]] == ["marker.txt"]


def test_connection_refused_is_reported() -> None:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    result = run_case({"port": port, "method": "GET", "path": "/"})
    assert result["ok"] is False
    assert result["error"].startswith("连接失败")
