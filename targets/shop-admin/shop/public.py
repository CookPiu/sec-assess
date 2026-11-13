"""前台接口，无需登录。

S1 SQL 注入：订单查询把关键字用 f-string 拼进 SQL。
S2 配置暴露：调试配置接口未鉴权，返回 SECRET_KEY。
诱饵：商品排序按白名单取列名，商品详情用参数化查询。
"""

from flask import Blueprint, current_app, jsonify, request

from db import get_db

bp = Blueprint("public", __name__)

SORT_COLUMNS = {"price": "price", "name": "name", "newest": "created_at"}


@bp.get("/orders/search")
def search_orders():
    keyword = request.args.get("keyword", "")
    sql = f"SELECT id, customer, product_id, amount, status FROM orders WHERE customer LIKE '%{keyword}%'"
    rows = get_db().execute(sql).fetchall()
    return jsonify([dict(row) for row in rows])


@bp.get("/products")
def list_products():
    column = SORT_COLUMNS.get(request.args.get("sort", ""), "id")
    rows = get_db().execute(f"SELECT id, name, price, image FROM products ORDER BY {column}").fetchall()
    return jsonify([dict(row) for row in rows])


@bp.get("/products/<int:product_id>")
def product_detail(product_id):
    row = get_db().execute("SELECT id, name, price, image FROM products WHERE id = ?", (product_id,)).fetchone()
    if row is None:
        return jsonify({"error": "商品不存在"}), 404
    return jsonify(dict(row))


@bp.get("/debug/config")
def debug_config():
    return jsonify(
        {
            "SHOP_NAME": current_app.config["SHOP_NAME"],
            "DATABASE": current_app.config["DATABASE"],
            "SECRET_KEY": current_app.config["SECRET_KEY"],
        }
    )
