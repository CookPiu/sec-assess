from pathlib import Path
from textwrap import dedent

from app.models.enums import Category
from app.project.flask_facts import collect_flask_facts
from app.project.pysource import ProjectIndex
from app.taint.rules_authz import find_authz_candidates
from app.taint.rules_secrets import find_secret_candidates


def load(tmp_path: Path, files: dict[str, str]):
    for rel, text in files.items():
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(dedent(text), encoding="utf-8")
    index = ProjectIndex(tmp_path)
    return index, collect_flask_facts(index)


def summary(candidates) -> set[tuple[str, str, int]]:
    return {(c.category, c.file, c.line) for c in candidates}


def test_secret_rules(tmp_path: Path) -> None:
    index, facts = load(
        tmp_path,
        {
            "config.py": """
                import os

                SECRET_KEY = "shop-dev-secret-2024"
                DATABASE_PASSWORD = os.environ.get("DB_PASSWORD")
                API_TOKEN = "short"
                DEBUG = True
            """,
            "app.py": """
                import hashlib

                import jwt
                from flask import Flask, jsonify, request
                from flask_login import login_required

                app = Flask(__name__)
                app.config["JWT_SECRET"] = "jwt-signing-secret"


                def issue(uid):
                    return jwt.encode({"uid": uid}, "another-hardcoded-key", algorithm="HS256")


                @app.get("/debug/config")
                def show_config():
                    return jsonify({k: str(v) for k, v in app.config.items()})


                @app.get("/admin/config")
                @login_required
                def admin_config():
                    if not request.args.get("is_admin"):
                        return "no", 403
                    return jsonify(dict(app.config))


                @app.post("/register")
                def register():
                    pw = request.form["password"]
                    return hashlib.md5(pw.encode()).hexdigest()


                if __name__ == "__main__":
                    app.run(debug=True)
            """,
            "tests/test_app.py": 'SECRET_KEY = "only-used-in-tests"\n',
        },
    )
    found = find_secret_candidates(index, facts)
    by_cat: dict[str, list] = {}
    for c in found:
        by_cat.setdefault(c.category, []).append(c)

    secrets = {(c.file, c.message) for c in by_cat[Category.HARDCODED_SECRET]}
    assert secrets == {
        ("config.py", "SECRET_KEY 以明文写在源码中"),
        ("app.py", "JWT_SECRET 以明文写在源码中"),
        ("app.py", "jwt.encode 的签名密钥 以明文写在源码中"),
    }
    assert {c.file for c in by_cat[Category.DEBUG_MODE]} == {"config.py", "app.py"}

    exposure = by_cat[Category.CONFIG_EXPOSURE]
    assert len(exposure) == 1 and exposure[0].route["path"] == "/debug/config"
    assert exposure[0].route["access"] == "anonymous"

    weak = by_cat[Category.WEAK_PASSWORD_STORAGE]
    assert len(weak) == 1 and weak[0].file == "app.py" and "无盐" in weak[0].message
    assert weak[0].steps[0].snippet == "return hashlib.md5(pw.encode()).hexdigest()"


def test_authz_rules(tmp_path: Path) -> None:
    index, facts = load(
        tmp_path,
        {
            "app.py": """
                from flask import Flask, abort, jsonify
                from flask_login import current_user, login_required

                from models import Order, Product, User

                app = Flask(__name__)


                @app.get("/users/<int:user_id>")
                @login_required
                def profile(user_id):
                    user = User.query.get_or_404(user_id)
                    return jsonify(user.to_dict())


                @app.get("/orders/<int:order_id>")
                @login_required
                def my_order(order_id):
                    order = Order.query.filter_by(id=order_id, user_id=current_user.id).first_or_404()
                    return jsonify(order.to_dict())


                def load_order(order_id):
                    order = Order.query.get_or_404(order_id)
                    if order.user_id != current_user.id:
                        abort(403)
                    return order


                @app.post("/orders/<int:order_id>/cancel")
                @login_required
                def cancel_order(order_id):
                    load_order(order_id)
                    Order.query.filter_by(id=order_id).delete()
                    return "ok"


                @app.get("/users/export")
                def export_users():
                    return jsonify([u.to_dict() for u in User.query.all()])


                @app.get("/products")
                def products():
                    return jsonify([p.to_dict() for p in Product.query.all()])


                @app.post("/login")
                def login():
                    return jsonify(User.query.filter_by(name="x").first().to_dict())


                @app.get("/admin/users/<int:user_id>")
                def admin_user(user_id):
                    if not current_user.is_admin:
                        return "no", 403
                    return jsonify(User.query.get(user_id).to_dict())
            """,
        },
    )
    found = find_authz_candidates(index, facts["routes"])
    assert {(c.category, c.route["path"], c.route["access"]) for c in found} == {
        (Category.IDOR, "/users/<int:user_id>", "user"),
        (Category.MISSING_AUTH, "/users/export", "anonymous"),
    }
    idor = next(c for c in found if c.category == Category.IDOR)
    assert idor.steps[-1].snippet == "user = User.query.get_or_404(user_id)"
    assert "普通用户" in idor.steps[0].note
