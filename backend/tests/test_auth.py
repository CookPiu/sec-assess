from __future__ import annotations

from app.core.auth import hash_password, verify_password


def test_password_hash_roundtrip() -> None:
    hashed = hash_password("s3cret")
    assert hashed != "s3cret"
    assert verify_password("s3cret", hashed)
    assert not verify_password("wrong", hashed)
    assert not verify_password("s3cret", "not-a-bcrypt-hash")


def test_login_and_me(client, login) -> None:
    headers = login("engineer")
    resp = client.get("/api/auth/me", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["username"] == "engineer"
    assert body["role"] == "engineer"


def test_wrong_password_rejected_and_audited(client, login) -> None:
    resp = client.post("/api/auth/login", json={"username": "developer", "password": "wrong"})
    assert resp.status_code == 401
    logs = client.get("/api/audit-logs", params={"action": "login_failed"}, headers=login("admin"))
    assert logs.status_code == 200
    assert any(item["username"] == "developer" for item in logs.json()["items"])


def test_requires_token(client) -> None:
    assert client.get("/api/auth/me").status_code == 401
    assert client.get("/api/auth/me", headers={"Authorization": "Bearer not-a-token"}).status_code == 401


def test_audit_logs_admin_only(client, login) -> None:
    assert client.get("/api/audit-logs", headers=login("engineer")).status_code == 403
    assert client.get("/api/audit-logs", headers=login("developer")).status_code == 403
    resp = client.get("/api/audit-logs", headers=login("admin"))
    assert resp.status_code == 200
    assert any(item["action"] == "login" for item in resp.json()["items"])
