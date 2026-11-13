"""user-center 用户中心教学靶场入口。

U1 越权：用户资料接口按路径里的 ID 查询，没有比对当前登录用户。
U2 缺失鉴权：用户导出接口没有登录校验，返回全部用户的联系方式。
诱饵：订单详情按当前用户过滤，只能看到自己的订单。
"""

from pathlib import Path

from flask import Flask, g, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash

from auth import issue_token, login_required
from db import close_db, get_db, init_db

app = Flask(__name__)
app.config["DATABASE"] = str(Path(__file__).resolve().parent / "users.db")
app.teardown_appcontext(close_db)

with app.app_context():
    init_db()

PROFILE_COLUMNS = "id, username, email, phone, address"


@app.post("/api/register")
def register():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))
    if not username or len(password) < 6:
        return jsonify({"error": "用户名不能为空，密码至少 6 位"}), 400
    db = get_db()
    try:
        cursor = db.execute(
            "INSERT INTO users (username, password_hash, email, phone) VALUES (?, ?, ?, ?)",
            (username, generate_password_hash(password), str(data.get("email", "")), str(data.get("phone", ""))),
        )
        db.commit()
    except db.IntegrityError:
        return jsonify({"error": "用户名已存在"}), 409
    return jsonify({"id": cursor.lastrowid, "username": username}), 201


@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    user = get_db().execute(
        "SELECT id, password_hash FROM users WHERE username = ?", (str(data.get("username", "")),)
    ).fetchone()
    if user is None or not check_password_hash(user["password_hash"], str(data.get("password", ""))):
        return jsonify({"error": "用户名或密码错误"}), 401
    return jsonify({"token": issue_token(user["id"]), "user_id": user["id"]})


@app.get("/api/me")
@login_required
def me():
    row = get_db().execute(f"SELECT {PROFILE_COLUMNS} FROM users WHERE id = ?", (g.user_id,)).fetchone()
    return jsonify(dict(row))


@app.get("/api/users/<int:user_id>")
@login_required
def user_profile(user_id):
    row = get_db().execute(f"SELECT {PROFILE_COLUMNS} FROM users WHERE id = ?", (user_id,)).fetchone()
    if row is None:
        return jsonify({"error": "用户不存在"}), 404
    return jsonify(dict(row))


@app.get("/api/orders/<int:order_id>")
@login_required
def order_detail(order_id):
    row = get_db().execute(
        "SELECT id, item, amount FROM orders WHERE id = ? AND user_id = ?", (order_id, g.user_id)
    ).fetchone()
    if row is None:
        return jsonify({"error": "订单不存在"}), 404
    return jsonify(dict(row))


@app.get("/api/users/export")
def export_users():
    rows = get_db().execute(f"SELECT {PROFILE_COLUMNS} FROM users ORDER BY id").fetchall()
    return jsonify([dict(row) for row in rows])


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
