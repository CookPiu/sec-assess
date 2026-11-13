"""shop-admin 配置。

S4 硬编码密钥：SECRET_KEY 直接写在源码里，Flask 用它签名会话 Cookie。
"""

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

SECRET_KEY = "shop-admin-dev-secret-2024"
DATABASE = str(BASE_DIR / "shop.db")
UPLOAD_DIR = str(BASE_DIR / "static" / "uploads")
MANUAL_DIR = str(BASE_DIR / "static" / "manuals")
SHOP_NAME = "示例商城"
