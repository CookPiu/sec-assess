"""SQLite 连接与种子数据。密码用 werkzeug 的加盐哈希存储。"""

import sqlite3

from flask import current_app, g
from werkzeug.security import generate_password_hash

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    email TEXT NOT NULL,
    phone TEXT NOT NULL,
    address TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    item TEXT NOT NULL,
    amount REAL NOT NULL
);
"""

SEED_USERS = [
    ("alice", "alice-pass-1", "alice@example.com", "555-0101", "示例路 1 号"),
    ("bob", "bob-pass-2", "bob@example.com", "555-0102", "示例路 2 号"),
]
SEED_ORDERS = [(1, "年度会员", 199.0), (2, "季度会员", 59.0)]


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db


def close_db(_exc=None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db() -> None:
    db = get_db()
    db.executescript(SCHEMA)
    if db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        db.executemany(
            "INSERT INTO users (username, password_hash, email, phone, address) VALUES (?, ?, ?, ?, ?)",
            [(name, generate_password_hash(pw), email, phone, addr) for name, pw, email, phone, addr in SEED_USERS],
        )
        db.executemany("INSERT INTO orders (user_id, item, amount) VALUES (?, ?, ?)", SEED_ORDERS)
        db.commit()
