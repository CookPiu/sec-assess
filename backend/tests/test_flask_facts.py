from pathlib import Path
from textwrap import dedent

from app.project.flask_facts import collect_flask_facts
from app.project.pysource import ProjectIndex


def write_project(root: Path, files: dict[str, str]) -> ProjectIndex:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(dedent(text), encoding="utf-8")
    return ProjectIndex(root)


FACTORY_PROJECT = {
    "shop/__init__.py": """
        from flask import Flask

        from .admin import admin_bp
        from . import auth


        def create_app():
            app = Flask(__name__)
            app.register_blueprint(auth.bp, url_prefix="/account")
            app.register_blueprint(admin_bp)
            return app
    """,
    "shop/decorators.py": """
        from functools import wraps

        import jwt
        from flask import abort, request


        def need_auth(fn):
            @wraps(fn)
            def wrapper(*args, **kwargs):
                try:
                    jwt.decode(request.headers.get("Authorization", ""), "k", algorithms=["HS256"])
                except jwt.PyJWTError:
                    abort(401)
                return fn(*args, **kwargs)
            return wrapper
    """,
    "shop/auth.py": """
        import hashlib

        from flask import Blueprint, request, session

        bp = Blueprint("auth", __name__)


        @bp.route("/register", methods=["POST"])
        def register():
            data = request.get_json() or {}
            username = data["username"]
            password = data.get("password")
            digest = hashlib.md5(password.encode()).hexdigest()
            return {"user": username, "hash": digest}


        @bp.post("/login")
        def login():
            user = request.form["username"]
            if user is None or request.form.get("password") != "x":
                return "bad", 401
            session["user_id"] = 1
            return "ok"
    """,
    "shop/admin.py": """
        from flask import Blueprint, abort, g, session

        from .decorators import need_auth

        admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


        @admin_bp.before_request
        def only_admin():
            if not session.get("is_admin"):
                abort(403)


        @admin_bp.route("/orders/<int:order_id>", methods=["GET", "DELETE"])
        def order(order_id):
            return str(order_id)


        @need_auth
        def profile():
            if g.user.role != "admin":
                abort(403)
            return "admin"
    """,
}


def test_routes_prefixes_and_access(tmp_path: Path) -> None:
    facts = collect_flask_facts(write_project(tmp_path, FACTORY_PROJECT))
    routes = {(r["path"], tuple(r["methods"])): r for r in facts["routes"]}

    assert set(routes) == {
        ("/account/register", ("POST",)),
        ("/account/login", ("POST",)),
        ("/admin/orders/<int:order_id>", ("GET", "DELETE")),
    }
    assert routes[("/account/register", ("POST",))]["access"] == "anonymous"
    # 登录失败返回 401 的分支不算登录校验
    assert routes[("/account/login", ("POST",))]["access"] == "anonymous"
    admin = routes[("/admin/orders/<int:order_id>", ("GET", "DELETE"))]
    assert admin["access"] == "admin" and admin["params"] == ["order_id"]
    assert admin["file"] == "shop/admin.py" and admin["handler"] == "order"

    assert facts["is_flask"] is True
    assert facts["entry"]["kind"] == "factory" and facts["entry"]["app"] == "shop:create_app()"
    assert facts["auth"]["register"] == {
        "path": "/account/register", "method": "POST", "fields": ["username", "password"], "content": "json",
    }  # fmt: skip
    assert facts["auth"]["login"]["fields"] == ["username", "password"]
    assert facts["auth"]["login"]["content"] == "form"
    storage = facts["password_storage"]
    assert storage["kind"] == "unsalted_hash" and storage["detail"] == "hashlib.md5" and storage["file"] == "shop/auth.py"
    assert facts["session"] == {"flask_session": True, "flask_login": False, "jwt": True}


def test_single_file_app_entry_and_custom_decorator(tmp_path: Path) -> None:
    index = write_project(
        tmp_path,
        {
            "app.py": """
                from flask import Flask, abort, session
                from flask_login import login_required
                from werkzeug.security import generate_password_hash

                from guards import staff_only

                app = Flask(__name__)


                @app.route("/")
                def index():
                    return "hi"


                @app.get("/me")
                @login_required
                def me():
                    return generate_password_hash("x")


                @app.get("/staff")
                @staff_only
                def staff():
                    return "ok"


                @app.get("/inline")
                def inline():
                    if "user_id" not in session:
                        abort(401)
                    return "ok"


                if __name__ == "__main__":
                    app.run(host="0.0.0.0", port=8080, debug=True)
            """,
            "guards.py": """
                from flask import abort, session


                def staff_only(fn):
                    def wrapper(*a, **kw):
                        if session.get("role") != "admin":
                            abort(403)
                        return fn(*a, **kw)
                    return wrapper
            """,
        },
    )
    facts = collect_flask_facts(index)
    access = {r["path"]: r["access"] for r in facts["routes"]}
    assert access == {"/": "anonymous", "/me": "user", "/staff": "admin", "/inline": "user"}
    assert facts["entry"] == {
        "kind": "run", "module": "app", "file": "app.py", "line": facts["entry"]["line"],
        "app": "app:app", "port": 8080, "debug": True,
    }  # fmt: skip
    assert facts["password_storage"]["kind"] == "salted_hash"
    assert facts["session"]["flask_login"] is True
    assert facts["auth"] == {}


def test_not_flask_and_syntax_errors(tmp_path: Path) -> None:
    index = write_project(tmp_path, {"main.py": "print('hi')\n", "broken.py": "def f(:\n"})
    facts = collect_flask_facts(index)
    assert facts["is_flask"] is False and facts["entry"] is None and facts["routes"] == []
    assert len(facts["parse_errors"]) == 1 and facts["parse_errors"][0].startswith("broken.py:")


def test_test_code_is_excluded(tmp_path: Path) -> None:
    index = write_project(
        tmp_path,
        {
            "app.py": """
                from flask import Flask

                app = Flask(__name__)


                @app.get("/")
                def home():
                    return "ok"
            """,
            "tests/test_app.py": """
                from flask import Flask

                app = Flask(__name__)


                @app.get("/only-in-tests")
                def fixture_route():
                    return "x"


                app.run(port=9999, debug=True)
            """,
            "conftest.py": "SECRET_KEY = 'fixture-secret-value'\n",
            "app_test.py": "import app\n",
        },
    )
    assert sorted(m.file for m in index.modules.values()) == ["app.py"]
    facts = collect_flask_facts(index)
    assert [r["path"] for r in facts["routes"]] == ["/"]
    assert facts["entry"]["kind"] == "app" and facts["entry"]["port"] == 5000
