from pathlib import Path

from app.project.stack import analyze_stack, parse_requirement


def write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_parse_requirement_lines() -> None:
    assert parse_requirement("Flask==3.0.3") == ("flask", "==3.0.3")
    assert parse_requirement("Flask_SQLAlchemy>=3.1 ; python_version>'3.8'  # orm") == ("flask-sqlalchemy", ">=3.1")
    assert parse_requirement("requests[socks]~=2.32") == ("requests", "~=2.32")
    assert parse_requirement("-r base.txt") is None
    assert parse_requirement("git+https://example.com/x.git#egg=x") is None
    assert parse_requirement("# comment") is None


def test_analyze_python_flask_project(tmp_path: Path) -> None:
    write(tmp_path, "requirements.txt", "Flask==3.0.3\nPyJWT>=2.8\n\n-r dev.txt\n")
    write(tmp_path, "app.py", "from flask import Flask\n\napp = Flask(__name__)\n\n\n@app.get('/')\ndef index():\n    return 'ok'\n")
    write(tmp_path, "templates/index.html", "<html>\n\n<body></body>\n</html>\n")
    write(tmp_path, "node_modules/x/index.js", "ignored()\n" * 50)
    write(tmp_path, ".venv/lib/site.py", "ignored = 1\n" * 50)

    stack = analyze_stack(tmp_path)

    assert stack["primary_language"] == "Python"
    assert {x["name"]: x["loc"] for x in stack["languages"]} == {"Python": 5, "HTML": 3}
    assert stack["loc"] == 8
    assert stack["frameworks"] == [{"name": "Flask", "version": "3.0.3", "ecosystem": "pypi"}]
    assert stack["manifests"] == ["requirements.txt"]
    assert [d["name"] for d in stack["dependencies"]] == ["flask", "pyjwt"]


def test_framework_detected_from_imports_without_manifest(tmp_path: Path) -> None:
    write(tmp_path, "server/main.py", "import flask\n")
    stack = analyze_stack(tmp_path)
    assert stack["frameworks"] == [{"name": "Flask", "version": None, "ecosystem": "pypi"}]
    assert stack["manifests"] == []


def test_analyze_other_manifests(tmp_path: Path) -> None:
    write(
        tmp_path,
        "pyproject.toml",
        '[project]\nname = "x"\ndependencies = ["fastapi>=0.110", "uvicorn"]\n'
        '[tool.poetry.dependencies]\npython = "^3.12"\nDjango = { version = "5.0" }\n',
    )
    write(tmp_path, "web/package.json", '{"dependencies": {"express": "^4.19.2"}, "devDependencies": {"jest": "29"}}')
    write(
        tmp_path,
        "api/pom.xml",
        '<project xmlns="http://maven.apache.org/POM/4.0.0">'
        "<parent><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-parent</artifactId>"
        "<version>3.2.0</version></parent><dependencies><dependency><groupId>junit</groupId>"
        "<artifactId>junit</artifactId><version>4.13</version><scope>test</scope></dependency></dependencies></project>",
    )
    write(tmp_path, "web/broken/package.json", "{not json")

    stack = analyze_stack(tmp_path)

    names = {f["name"]: f["version"] for f in stack["frameworks"]}
    assert names == {"FastAPI": None, "Django": None, "Express": "4.19.2", "Spring Boot": "3.2.0"}
    deps = {(d["ecosystem"], d["name"]): d for d in stack["dependencies"]}
    assert deps[("npm", "jest")]["dev"] is True
    assert deps[("maven", "junit:junit")]["dev"] is True
    assert ("pypi", "python") not in deps
    assert sorted(stack["manifests"]) == ["api/pom.xml", "pyproject.toml", "web/package.json"]
    assert len(stack["errors"]) == 1 and "web/broken/package.json" in stack["errors"][0]
