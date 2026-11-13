"""后台接口，需要管理员登录。

S6 命令注入：物流连通性检测把主机名拼进 shell 命令。
S7 反序列化：导入备份直接 pickle.loads 上传的文件。
S8 模板注入：邮件模板预览把用户提交的模板交给 render_template_string。
S9 文件上传 / 路径穿越：商品图片按原始文件名保存。
诱饵：域名解析检测用列表参数调用 subprocess，商品说明书上传经过 secure_filename。
"""

import os
import pickle
import subprocess

from flask import Blueprint, current_app, jsonify, render_template_string, request
from werkzeug.utils import secure_filename

from db import get_db
from shop.auth import admin_required

bp = Blueprint("admin", __name__)


@bp.post("/logistics/ping")
@admin_required
def logistics_ping():
    host = request.form.get("host", "")
    result = subprocess.run(f"ping -c 1 -W 1 {host}", shell=True, capture_output=True, text=True, timeout=10)
    return jsonify({"output": result.stdout + result.stderr})


@bp.post("/logistics/lookup")
@admin_required
def logistics_lookup():
    domain = request.form.get("domain", "")
    result = subprocess.run(["getent", "hosts", domain], capture_output=True, text=True, timeout=10)
    return jsonify({"output": result.stdout or "未解析到地址"})


@bp.post("/backup/import")
@admin_required
def import_backup():
    data = request.files["backup"].read()
    backup = pickle.loads(data)
    return jsonify({"orders": len(backup.get("orders", [])) if isinstance(backup, dict) else 0})


@bp.post("/mail/preview")
@admin_required
def mail_preview():
    template = request.form.get("template", "")
    html = render_template_string(template, shop_name=current_app.config["SHOP_NAME"], customer="张三")
    return jsonify({"html": html})


@bp.post("/products/<int:product_id>/image")
@admin_required
def upload_image(product_id):
    image = request.files["image"]
    os.makedirs(current_app.config["UPLOAD_DIR"], exist_ok=True)
    image.save(os.path.join(current_app.config["UPLOAD_DIR"], image.filename))
    db = get_db()
    db.execute("UPDATE products SET image = ? WHERE id = ?", (image.filename, product_id))
    db.commit()
    return jsonify({"image": image.filename})


@bp.post("/products/<int:product_id>/manual")
@admin_required
def upload_manual(product_id):
    manual = request.files["manual"]
    filename = secure_filename(manual.filename)
    os.makedirs(current_app.config["MANUAL_DIR"], exist_ok=True)
    manual.save(os.path.join(current_app.config["MANUAL_DIR"], f"{product_id}-{filename}"))
    return jsonify({"manual": filename})
