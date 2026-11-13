"""登录与管理员校验。登录态保存在 Flask 签名 Cookie 里。"""

import functools

from flask import Blueprint, abort, jsonify, request, session

from db import get_db, hash_password

bp = Blueprint("auth", __name__)


def admin_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("is_admin"):
            abort(403)
        return view(*args, **kwargs)

    return wrapped


@bp.post("/login")
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    user = get_db().execute(
        "SELECT id, username, password_md5, is_admin FROM users WHERE username = ?", (username,)
    ).fetchone()
    if user is None or user["password_md5"] != hash_password(password):
        return jsonify({"error": "用户名或密码错误"}), 401
    session.clear()
    session["user_id"] = user["id"]
    session["is_admin"] = bool(user["is_admin"])
    return jsonify({"username": user["username"], "is_admin": bool(user["is_admin"])})


@bp.post("/logout")
def logout():
    session.clear()
    return jsonify({"ok": True})
