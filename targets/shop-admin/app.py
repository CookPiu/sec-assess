"""shop-admin 电商后台教学靶场入口。

S3 调试模式：以 debug=True 启动，异常时暴露 Werkzeug 调试页。
"""

from flask import Flask

import config
from db import close_db, init_db
from shop import admin, auth, public

app = Flask(__name__)
app.config.from_object(config)
app.teardown_appcontext(close_db)
app.register_blueprint(public.bp)
app.register_blueprint(auth.bp)
app.register_blueprint(admin.bp, url_prefix="/admin")

with app.app_context():
    init_db()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
