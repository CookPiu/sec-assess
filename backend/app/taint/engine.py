"""污点引擎（FR-006、D-003、D-018）。

从 Flask 路由处理函数出发，把请求输入和 URL 参数标为污点，沿赋值、字符串拼接（+、f-string、%、format）、
函数参数和返回值传播；到达 Sink 且途中没有经过对应净化函数时生成候选漏洞，并记录每一步的文件和行号。

取舍：
- 跨文件调用最多追 3 层；方法调用、类属性、容器元素和动态调用不追踪。
- 分支两侧的结果取并集，循环体只走一遍。
- `x in 白名单` 为真的分支里、以及 `x not in 白名单` 时提前返回之后，x 视为已净化。
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Any

from app.project.pysource import FunctionInfo, ProjectIndex, dotted, is_true, keyword
from app.taint.model import Candidate, Step, Taint
from app.taint.rules import MESSAGES, SAFE_YAML_LOADERS, SANITIZERS, SINKS, Sink, source_label

MAX_DEPTH = 3
ALL = frozenset(SANITIZERS["int"])
Env = dict[str, Taint]


@dataclass
class _Entry:
    route: dict[str, Any] | None
    candidates: dict[tuple[str, str, int], Candidate] = field(default_factory=dict)


class TaintEngine:
    def __init__(self, index: ProjectIndex, routes: list[dict[str, Any]]) -> None:
        self.index = index
        self.routes = routes

    def run(self) -> list[Candidate]:
        found: dict[tuple[str, str, int], Candidate] = {}
        route_handlers: set[tuple[str, str]] = set()
        # 先从路由入口分析，同一个触发点保留带路由信息的那条
        for route in self.routes:
            fn = self._route_function(route)
            if fn is None:
                continue
            route_handlers.add((fn.module, fn.name))
            env: Env = {}
            for param in route["params"]:
                if param in fn.params:
                    step = Step(fn.file, fn.node.lineno, self.index.snippet(fn.file, fn.node.lineno), f"URL 参数 <{param}>")
                    env[param] = Taint((step,))
            info = {"path": route["path"], "methods": route["methods"], "access": route["access"]}
            self._analyze_entry(fn, env, info, found)
        for key, fn in self.index.functions.items():
            if key not in route_handlers:
                self._analyze_entry(fn, {}, None, found)
        return sorted(found.values(), key=lambda c: (c.file, c.line, c.category))

    def _route_function(self, route: dict[str, Any]) -> FunctionInfo | None:
        fn = self.index.functions.get((route["module"], route["handler"]))
        if fn is not None and fn.node.lineno == route["line"]:
            return fn
        module = self.index.modules.get(route["module"])
        if module is None:
            return None
        for node in ast.walk(module.tree):  # create_app 里定义的嵌套处理函数
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.lineno == route["line"]:
                return FunctionInfo(module.name, node.name, node, module.file)
        return None

    def _analyze_entry(self, fn: FunctionInfo, env: Env, route: dict[str, Any] | None,
                       found: dict[tuple[str, str, int], Candidate]) -> None:  # fmt: skip
        entry = _Entry(route)
        _FunctionRun(self, fn, env, 0, (fn.qualname,), entry, [fn.qualname]).run()
        for key, cand in entry.candidates.items():
            found.setdefault(key, cand)


class _FunctionRun:
    def __init__(self, engine: TaintEngine, fn: FunctionInfo, env: Env, depth: int, stack: tuple[str, ...],
                 entry: _Entry, path: list[str]) -> None:  # fmt: skip
        self.engine = engine
        self.index = engine.index
        self.fn = fn
        self.module = fn.module
        self.imports = self.index.modules[fn.module].imports
        self.env = env
        self.depth = depth
        self.stack = stack
        self.entry = entry
        self.path = path
        self.returns: list[Taint] = []

    def run(self) -> Taint | None:
        self.block(self.fn.node.body, self.env)
        return self.returns[0] if self.returns else None

    # ---------- 工具 ----------

    def step(self, node: ast.AST, note: str) -> Step:
        line = getattr(node, "lineno", self.fn.node.lineno)
        return Step(self.fn.file, line, self.index.snippet(self.fn.file, line), note)

    def canonical(self, func: ast.expr) -> str:
        name = dotted(func)
        if not name:
            return ""
        head, _, rest = name.partition(".")
        if head in self.imports:
            target, attr = self.imports[head]
            base = f"{target}.{attr}" if attr else target
            return f"{base}.{rest}" if rest else base
        return name

    def is_function_call(self, func: ast.expr) -> bool:
        """foo(...)、os.path.join(...) 这类函数调用；obj.method(...) 这类方法调用返回 False。

        以导入的模块（或小写开头的导入名）开头的属性链视为模块函数，类名开头的视为方法调用。
        """
        if isinstance(func, ast.Name):
            return True
        chain = dotted(func)
        if not chain or "()" in chain:  # 链上有调用或下标，如 sqlite3.connect().execute
            return False
        head = chain.split(".")[0]
        if head not in self.imports:
            return False
        return self.imports[head][1] is None or head[:1].islower()

    # ---------- 语句 ----------

    def block(self, stmts: list[ast.stmt], env: Env) -> None:
        for stmt in stmts:
            self.statement(stmt, env)

    def statement(self, node: ast.stmt, env: Env) -> None:
        if isinstance(node, ast.Assign):
            taint = self.expr(node.value, env)
            for target in node.targets:
                self.bind(target, taint, env, node)
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            self.bind(node.target, self.expr(node.value, env), env, node)
        elif isinstance(node, ast.AugAssign):
            taint = self.expr(node.value, env)
            if isinstance(node.target, ast.Name):
                current = env.get(node.target.id)
                merged = taint or current
                if merged is not None:
                    env[node.target.id] = merged.extend(self.step(node, f"拼接到 {node.target.id}"))
        elif isinstance(node, ast.Expr):
            self.expr(node.value, env)
        elif isinstance(node, ast.Return) and node.value is not None:
            taint = self.expr(node.value, env)
            if taint is not None:
                self.returns.append(taint.extend(self.step(node, f"由 {self.fn.name}() 返回")))
        elif isinstance(node, ast.If):
            self.if_statement(node, env)
        elif isinstance(node, ast.For | ast.AsyncFor):
            taint = self.expr(node.iter, env)
            self.bind(node.target, taint, env, node)
            self.block(node.body, env)
            self.block(node.orelse, env)
        elif isinstance(node, ast.While):
            self.expr(node.test, env)
            self.block(node.body, env)
            self.block(node.orelse, env)
        elif isinstance(node, ast.With | ast.AsyncWith):
            for item in node.items:
                taint = self.expr(item.context_expr, env)
                if item.optional_vars is not None:
                    self.bind(item.optional_vars, taint, env, node)
            self.block(node.body, env)
        elif isinstance(node, ast.Try):
            self.block(node.body, env)
            for handler in node.handlers:
                self.block(handler.body, env)
            self.block(node.orelse, env)
            self.block(node.finalbody, env)

    def bind(self, target: ast.expr, taint: Taint | None, env: Env, node: ast.AST) -> None:
        if isinstance(target, ast.Name):
            if taint is None:
                env.pop(target.id, None)
            else:
                env[target.id] = taint.extend(self.step(node, f"赋值给 {target.id}"))
        elif isinstance(target, ast.Tuple | ast.List):
            for elt in target.elts:
                self.bind(elt.value if isinstance(elt, ast.Starred) else elt, taint, env, node)

    def if_statement(self, node: ast.If, env: Env) -> None:
        self.expr(node.test, env)
        guard = self.whitelist_guard(node.test, env)
        body_env = dict(env)
        if guard and guard[1] == "in":
            body_env[guard[0]] = body_env[guard[0]].sanitize(ALL)
        self.block(node.body, body_env)
        else_env = dict(env)
        self.block(node.orelse, else_env)
        env.clear()
        for name in body_env.keys() | else_env.keys():
            env[name] = body_env.get(name) or else_env[name]
        if guard and guard[1] == "not in" and guard[0] in env and self.rejects_or_resets(node.body, guard[0]):
            env[guard[0]] = env[guard[0]].sanitize(ALL)

    def whitelist_guard(self, test: ast.expr, env: Env) -> tuple[str, str] | None:
        """识别 `x in 常量集合` / `x not in 常量集合`。"""
        if not (isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.left, ast.Name)):
            return None
        name = test.left.id
        if name not in env or self.expr(test.comparators[0], {}) is not None:
            return None
        if isinstance(test.ops[0], ast.In):
            return name, "in"
        if isinstance(test.ops[0], ast.NotIn):
            return name, "not in"
        return None

    @staticmethod
    def rejects_or_resets(body: list[ast.stmt], name: str) -> bool:
        """分支里提前返回、抛异常、abort，或把变量改成默认值。"""
        for stmt in body:
            if isinstance(stmt, ast.Return | ast.Raise):
                return True
            if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call) and dotted(stmt.value.func).endswith("abort"):
                return True
            if isinstance(stmt, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in stmt.targets):
                return True
        return False

    # ---------- 表达式 ----------

    def expr(self, node: ast.expr | None, env: Env) -> Taint | None:
        if node is None or isinstance(node, ast.Constant):
            return None
        if isinstance(node, ast.Name):
            return env.get(node.id)
        if isinstance(node, ast.JoinedStr):
            taints = [self.expr(v.value, env) for v in node.values if isinstance(v, ast.FormattedValue)]
            first = next((t for t in taints if t is not None), None)
            return first.extend(self.step(node, "f-string 拼接")) if first else None
        if isinstance(node, ast.BinOp):
            left, right = self.expr(node.left, env), self.expr(node.right, env)
            taint = left or right
            if taint is None:
                return None
            if isinstance(node.op, ast.Mod) and isinstance(node.left, ast.Constant):
                return taint.extend(self.step(node, "% 格式化拼接"))
            return taint.extend(self.step(node, "字符串拼接")) if isinstance(node.op, ast.Add) else taint
        if isinstance(node, ast.BoolOp):
            taints = [self.expr(v, env) for v in node.values]
            return next((t for t in taints if t is not None), None)
        if isinstance(node, ast.IfExp):
            self.expr(node.test, env)
            return self.expr(node.body, env) or self.expr(node.orelse, env)
        if isinstance(node, ast.Compare):
            self.expr(node.left, env)
            for comp in node.comparators:
                self.expr(comp, env)
            return None
        if isinstance(node, ast.Attribute | ast.Subscript):
            return self.access(node, env)
        if isinstance(node, ast.Call):
            return self.call(node, env)
        if isinstance(node, ast.Await | ast.Starred | ast.FormattedValue):
            return self.expr(node.value, env)
        if isinstance(node, ast.List | ast.Tuple | ast.Set):
            for elt in node.elts:  # 容器元素不追踪，只检查里面的调用
                self.expr(elt, env)
            return None
        if isinstance(node, ast.Dict):
            for value in node.values:
                self.expr(value, env)
            return None
        return None

    def access(self, node: ast.Attribute | ast.Subscript, env: Env) -> Taint | None:
        label = source_label(dotted(node.value)) if isinstance(node, ast.Subscript) else source_label(dotted(node))
        if label is not None:
            text = ast.unparse(node)
            return Taint((self.step(node, f"读取用户输入 {text}"),))
        if isinstance(node, ast.Subscript):
            self.expr(node.slice, env)
        return self.expr(node.value, env)  # 常量容器以污点为键取值时，结果不算污点

    def call(self, node: ast.Call, env: Env) -> Taint | None:
        func = node.func
        if isinstance(func, ast.Attribute) and source_label(dotted(func.value)) is not None:
            for arg in node.args:
                self.expr(arg, env)
            return Taint((self.step(node, f"读取用户输入 {ast.unparse(node)}"),))
        if source_label(dotted(node)) is not None:
            return Taint((self.step(node, f"读取用户输入 {ast.unparse(node)}"),))

        name = self.canonical(func)
        is_method = isinstance(func, ast.Attribute) and not self.is_function_call(func)
        # 接收者总要分析一遍，才能发现链式调用中间的 Sink
        receiver = self.expr(func.value, env) if isinstance(func, ast.Attribute) else None
        args = [self.expr(a, env) for a in node.args]
        kwargs = {kw.arg: self.expr(kw.value, env) for kw in node.keywords}

        for sink in SINKS:
            if self.sink_matches(sink, name, node):
                self.check_sink(sink, node, args, kwargs)

        tainted_arg = next((t for t in [*args, *kwargs.values()] if t is not None), None)
        if name in SANITIZERS:
            if tainted_arg is None:
                return None
            cats = SANITIZERS[name]
            return None if cats == ALL else tainted_arg.sanitize(cats)

        target = self.index.resolve_call(self.module, func)
        if target is not None and target.qualname not in self.stack and self.depth < MAX_DEPTH:
            return self.follow(target, node, args, kwargs)

        if is_method:
            assert isinstance(func, ast.Attribute)
            if receiver is not None:
                return receiver
            if func.attr in ("format", "join") and isinstance(func.value, ast.Constant) and tainted_arg is not None:
                return tainted_arg.extend(self.step(node, f"str.{func.attr} 拼接"))
            return None
        return tainted_arg

    def sink_matches(self, sink: Sink, name: str, node: ast.Call) -> bool:
        if name in sink.exact:
            return True
        return isinstance(node.func, ast.Attribute) and node.func.attr in sink.methods

    def check_sink(self, sink: Sink, node: ast.Call, args: list[Taint | None], kwargs: dict[str | None, Taint | None]) -> None:
        if sink.require_shell and not is_true(keyword(node, "shell")):
            return
        if sink.safe_loader:
            loader = keyword(node, "Loader") or (node.args[1] if len(node.args) > 1 else None)
            if loader is not None and dotted(loader).split(".")[-1] in SAFE_YAML_LOADERS:
                return
        taint = args[sink.arg] if len(args) > sink.arg else kwargs.get(sink.kwarg) if sink.kwarg else None
        if taint is None or sink.category in taint.sanitized:
            return
        steps = taint.extend(self.step(node, f"进入{sink.label}")).steps
        cand = Candidate(
            category=sink.category,
            file=self.fn.file,
            line=node.lineno,
            function=self.fn.qualname,
            message=MESSAGES[sink.category],
            steps=list(steps),
            route=self.entry.route,
            functions=list(self.path),
        )
        self.entry.candidates.setdefault(cand.key, cand)

    def follow(self, target: FunctionInfo, node: ast.Call, args: list[Taint | None],
               kwargs: dict[str | None, Taint | None]) -> Taint | None:  # fmt: skip
        """把实参的污点绑定到被调函数的形参，进入被调函数继续分析，返回其返回值的污点。"""
        params = target.params
        callee_env: Env = {}
        bound: list[tuple[str, Taint]] = list(zip(params, args, strict=False))  # type: ignore[arg-type]
        bound += [(k, v) for k, v in kwargs.items() if k in params and v is not None]
        for param, taint in bound:
            if taint is None:
                continue
            passed = taint.extend(self.step(node, f"作为参数 {param} 传入 {target.name}()"))
            entry_step = Step(target.file, target.node.lineno, self.index.snippet(target.file, target.node.lineno),
                              f"进入 {target.name}()，参数 {param}")  # fmt: skip
            callee_env[param] = passed.extend(entry_step)
        sub = _FunctionRun(self.engine, target, callee_env, self.depth + 1, (*self.stack, target.qualname),
                           self.entry, [*self.path, target.qualname])  # fmt: skip
        result = sub.run()
        return result.extend(self.step(node, f"{target.name}() 的返回值")) if result else None


def find_taint_candidates(index: ProjectIndex, routes: list[dict[str, Any]]) -> list[Candidate]:
    return TaintEngine(index, routes).run()
