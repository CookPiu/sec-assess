"""Source / Sink / Sanitizer 规则表（DESIGN.md 5.2）。

调用名先按导入别名规范化，例如 `from pickle import loads as l` 后的 `l(x)` 记为 pickle.loads。
"""

from __future__ import annotations

from dataclasses import dataclass

from app.models.enums import Category

# Flask 请求对象上的用户输入
SOURCE_ROOTS = (
    "request.args", "request.form", "request.values", "request.json", "request.files",
    "request.headers", "request.cookies", "request.data", "request.stream",
    "request.get_json()", "request.get_data()",
)  # fmt: skip


def source_label(expr: str) -> str | None:
    """expr 为 dotted() 的结果；属于请求输入时返回其根，否则返回 None。"""
    expr = expr.removeprefix("flask.")
    for root in SOURCE_ROOTS:
        if expr == root or expr.startswith(root + ".") or expr.startswith(root + "("):
            return root
    return None


@dataclass(frozen=True)
class Sink:
    category: Category
    label: str
    exact: frozenset[str] = frozenset()  # 规范化后的完整调用名
    methods: frozenset[str] = frozenset()  # 任意对象上的同名方法
    arg: int = 0
    kwarg: str | None = None
    require_shell: bool = False  # subprocess 只有 shell=True 时字符串参数才会经过 shell
    safe_loader: bool = False  # yaml.load 指定了安全 Loader 时不算


SINKS: tuple[Sink, ...] = (
    Sink(Category.SQL_INJECTION, "SQL 执行", methods=frozenset({"execute", "executemany", "executescript"})),
    Sink(Category.SQL_INJECTION, "SQLAlchemy text()", exact=frozenset({"sqlalchemy.text", "sqlalchemy.sql.text"})),
    Sink(
        Category.COMMAND_INJECTION,
        "系统命令执行",
        exact=frozenset({"os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput"}),
    ),
    Sink(
        Category.COMMAND_INJECTION,
        "subprocess（shell=True）",
        exact=frozenset({"subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output",
                         "subprocess.Popen"}),  # fmt: skip
        kwarg="args",
        require_shell=True,
    ),
    Sink(
        Category.TEMPLATE_INJECTION,
        "模板字符串渲染",
        exact=frozenset({"flask.render_template_string", "jinja2.Template", "render_template_string"}),
        methods=frozenset({"from_string"}),
        kwarg="source",
    ),
    Sink(
        Category.DESERIALIZATION,
        "反序列化",
        exact=frozenset({"pickle.loads", "pickle.load", "_pickle.loads", "cPickle.loads", "dill.loads",
                         "marshal.loads", "jsonpickle.decode", "yaml.unsafe_load"}),  # fmt: skip
    ),
    Sink(Category.DESERIALIZATION, "yaml.load（未指定安全 Loader）", exact=frozenset({"yaml.load"}), safe_loader=True),
    Sink(Category.PATH_TRAVERSAL, "文件打开", exact=frozenset({"open", "io.open", "codecs.open"}), kwarg="file"),
    Sink(Category.PATH_TRAVERSAL, "文件保存", methods=frozenset({"save"}), kwarg="dst"),
    Sink(Category.PATH_TRAVERSAL, "文件下载", exact=frozenset({"flask.send_file"}), kwarg="path_or_file"),
    Sink(Category.PATH_TRAVERSAL, "文件删除", exact=frozenset({"os.remove", "os.unlink"})),
)

ALL_CATEGORIES = frozenset(Category)
# 调用名 → 净化后不再适用的类别
SANITIZERS: dict[str, frozenset[Category]] = {
    "int": ALL_CATEGORIES,
    "float": ALL_CATEGORIES,
    "bool": ALL_CATEGORIES,
    "len": ALL_CATEGORIES,
    "abs": ALL_CATEGORIES,
    "uuid.UUID": ALL_CATEGORIES,
    "werkzeug.utils.secure_filename": frozenset({Category.PATH_TRAVERSAL}),
    "werkzeug.secure_filename": frozenset({Category.PATH_TRAVERSAL}),
    "secure_filename": frozenset({Category.PATH_TRAVERSAL}),
    "os.path.basename": frozenset({Category.PATH_TRAVERSAL}),
    "werkzeug.security.safe_join": frozenset({Category.PATH_TRAVERSAL}),
    "werkzeug.utils.safe_join": frozenset({Category.PATH_TRAVERSAL}),
    "flask.safe_join": frozenset({Category.PATH_TRAVERSAL}),
    "shlex.quote": frozenset({Category.COMMAND_INJECTION}),
    "pipes.quote": frozenset({Category.COMMAND_INJECTION}),
}

SAFE_YAML_LOADERS = ("SafeLoader", "CSafeLoader", "BaseLoader")

MESSAGES: dict[Category, str] = {
    Category.SQL_INJECTION: "用户输入拼接进 SQL 语句后执行",
    Category.COMMAND_INJECTION: "用户输入拼接进系统命令后执行",
    Category.TEMPLATE_INJECTION: "用户输入作为模板源码被渲染",
    Category.DESERIALIZATION: "用户提供的数据被不安全地反序列化",
    Category.PATH_TRAVERSAL: "用户输入未经过滤用作文件路径",
}
