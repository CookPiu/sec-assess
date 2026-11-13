"""容器内探针：接收用例，向容器内 127.0.0.1 发送请求，回传报文和文件检查结果（D-014）。

宿主机通过 docker exec 把用例 JSON 的 base64 作为第一个参数传入。脚本只用标准库，
不访问外网，也不读写工程副本以外的位置（用例里的文件检查路径除外）。
输出一行 JSON；请求失败时 ok 为 false，报文仍尽量返回。
"""

from __future__ import annotations

import base64
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid

MAX_BODY = 32 * 1024
MAX_REQUEST_BODY = 2 * 1024
MAX_FOUND = 20
DEFAULT_PORT = 5000


def _escape(value: object) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\r", "").replace("\n", "")


def _multipart(body: dict) -> tuple[bytes, str]:
    boundary = uuid.uuid4().hex
    parts: list[bytes] = []
    for key, value in (body.get("data") or {}).items():
        parts.append(
            f'--{boundary}\r\nContent-Disposition: form-data; name="{_escape(key)}"\r\n\r\n{value}\r\n'.encode()
        )
    for item in body.get("files") or []:
        content = base64.b64decode(item.get("content_b64") or "")
        filename = _escape(item.get("filename") or "file.bin")
        content_type = item.get("content_type") or "application/octet-stream"
        parts.append(
            f'--{boundary}\r\nContent-Disposition: form-data; name="{_escape(item.get("field") or "file")}"; '
            f'filename="{filename}"\r\nContent-Type: {content_type}\r\n\r\n'.encode()
        )
        parts.extend([content, b"\r\n"])
    parts.append(f"--{boundary}--\r\n".encode())
    return b"".join(parts), f"multipart/form-data; boundary={boundary}"


def _payload(body: dict | None) -> tuple[bytes, str | None]:
    if not body:
        return b"", None
    kind = body.get("kind")
    if kind == "json":
        return json.dumps(body.get("data") or {}, ensure_ascii=False).encode(), "application/json"
    if kind == "form":
        return urllib.parse.urlencode(body.get("data") or {}, doseq=True).encode(), (
            "application/x-www-form-urlencoded"
        )
    if kind == "raw":
        return base64.b64decode(body.get("content_b64") or ""), body.get("content_type") or (
            "application/octet-stream"
        )
    if kind == "multipart":
        return _multipart(body)
    return b"", None


def _raw_request(method: str, path: str, port: int, headers: dict[str, str], body: bytes) -> str:
    lines = [f"{method} {path} HTTP/1.1", f"Host: 127.0.0.1:{port}"]
    if body:
        lines.append(f"Content-Length: {len(body)}")
    lines += [f"{key}: {value}" for key, value in headers.items()]
    head = "\r\n".join(lines)
    text = body[:MAX_REQUEST_BODY].decode("utf-8", "replace")
    if len(body) > MAX_REQUEST_BODY:
        text += "…（请求体已截断）"
    return f"{head}\r\n\r\n{text}"


def _raw_response(status: int, reason: str, headers: object, body: bytes) -> str:
    lines = [f"HTTP/1.1 {status} {reason}"]
    get_all = getattr(headers, "get_all", None)
    if callable(get_all):
        for name in dict(headers.items()):
            for value in get_all(name) or []:
                lines.append(f"{name}: {value}")
    else:
        lines += [f"{key}: {value}" for key, value in dict(headers or {}).items()]
    text = body[:MAX_BODY].decode("utf-8", "replace")
    if len(body) > MAX_BODY:
        text += "…（响应体已截断）"
    head = "\r\n".join(lines)
    return f"{head}\r\n\r\n{text}"


def _checks(case: dict) -> tuple[dict[str, bool], list[str]]:
    spec = case.get("checks") or {}
    files_exist = {path: os.path.exists(path) for path in spec.get("files_exist") or []}
    found: list[str] = []
    find = spec.get("find") or {}
    name = find.get("name")
    root = find.get("root") or "/work/app"
    if name and os.path.isdir(root):
        for dirpath, _dirnames, filenames in os.walk(root):
            if name in filenames:
                found.append(os.path.join(dirpath, name))
                if len(found) >= MAX_FOUND:
                    break
    return files_exist, found


def send(case: dict) -> dict:
    port = int(case.get("port") or DEFAULT_PORT)
    path = case.get("path") or "/"
    query = case.get("query") or {}
    if query:
        path += ("&" if "?" in path else "?") + urllib.parse.urlencode(query, doseq=True)
    body, content_type = _payload(case.get("body"))
    headers = {str(k): str(v) for k, v in (case.get("headers") or {}).items()}
    if content_type:
        headers["Content-Type"] = content_type
    method = (case.get("method") or ("POST" if body else "GET")).upper()
    timeout = float(case.get("timeout_s") or 8)
    request_raw = _raw_request(method, path, port, headers, body)

    result: dict = {
        "ok": False,
        "error": None,
        "status": None,
        "headers": {},
        "set_cookie": [],
        "body": "",
        "request_raw": request_raw,
        "response_raw": "",
    }
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=body or None,
        headers=headers,
        method=method,
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        try:
            response = opener.open(request, timeout=timeout)
        except urllib.error.HTTPError as exc:  # 4xx/5xx 也是有效响应
            response = exc
        with response:
            status = int(response.status if hasattr(response, "status") else response.code)
            raw = response.read(MAX_BODY + 1)
            headers_out = response.headers
            reason = getattr(response, "reason", "") or ""
    except (urllib.error.URLError, OSError) as exc:
        reason = getattr(exc, "reason", None) or exc
        result["error"] = f"连接失败：{reason}"
        files_exist, found = _checks(case)
        result["files_exist"] = files_exist
        result["found"] = found
        return result

    result.update(
        ok=True,
        status=status,
        headers=dict(headers_out.items()),
        set_cookie=headers_out.get_all("Set-Cookie") or [],
        body=raw[:MAX_BODY].decode("utf-8", "replace"),
        response_raw=_raw_response(status, reason, headers_out, raw),
    )
    files_exist, found = _checks(case)
    result["files_exist"] = files_exist
    result["found"] = found
    return result


def main() -> None:
    try:
        encoded = sys.argv[1] if len(sys.argv) > 1 else ""
        case = json.loads(base64.b64decode(encoded).decode("utf-8")) if encoded else {}
        output = send(case)
    except Exception as exc:  # 探针自身出错也要返回结构化结果
        output = {"ok": False, "error": f"探针内部错误：{exc}", "request_raw": "", "response_raw": ""}
    print(json.dumps(output, ensure_ascii=False))


if __name__ == "__main__":
    main()
