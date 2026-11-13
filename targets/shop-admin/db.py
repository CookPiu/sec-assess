"""SQLite 连接与种子数据。

S5 弱密码存储：用户密码用无盐 MD5 存储，拿到数据库内容即可离线比对常见口令。
"""

import hashlib
import sqlite3

from flask import current_app, g

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_md5 TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    price REAL NOT NULL,
    image TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    customer TEXT NOT NULL,
    product_id INTEGER NOT NULL,
    amount REAL NOT NULL,
    status TEXT NOT NULL
);
"""

SEED_USERS = [("admin", "admin123", 1), ("operator", "operator2024", 0)]
SEED_PRODUCTS = [("机械键盘", 399.0), ("无线鼠标", 129.0), ("显示器支架", 219.0)]
SEED_ORDERS = [("张三", 1, 399.0, "已发货"), ("李四", 2, 129.0, "待付款"), ("王五", 3, 219.0, "已完成")]


def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()


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
            "INSERT INTO users (username, password_md5, is_admin) VALUES (?, ?, ?)",
            [(name, hash_password(password), admin) for name, password, admin in SEED_USERS],
        )
        db.executemany("INSERT INTO products (name, price) VALUES (?, ?)", SEED_PRODUCTS)
        db.executemany("INSERT INTO orders (customer, product_id, amount, status) VALUES (?, ?, ?, ?)", SEED_ORDERS)
        db.commit()
