"""攻击路径组装（DESIGN.md 5.4、D-002、D-008）：只用已验证漏洞，按“获得的能力满足下一步前置条件”连边。

输入是已验证漏洞（类别、所在路由的访问前提、命中特征）和侦察事实，输出 DAG 与多步路径，不读库、不调模型。

- 起点“匿名攻击者”，身份节点“普通用户身份”“管理员身份”，终点“执行代码”“读他人数据”。
- 身份只升不降：漏洞推导出的身份必须高于进入该漏洞时已有的身份，因此图中不会出现环。
- 只保留既能从起点到达、又能到达终点的节点；经过至少两个漏洞节点的起点到终点路径为多步路径。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.models.enums import CATEGORY_LABELS, Category, ChainNodeKind

START = "start"
USER = "cap:user"
ADMIN = "cap:admin"
GOAL_RCE = "goal:rce"
GOAL_DATA = "goal:data"

LEVEL = {"anonymous": 0, "user": 1, "admin": 2}
IDENTITY_LEVEL = {START: 0, USER: 1, ADMIN: 2}
ACCESS_TEXT = {
    START: "无需登录即可访问",
    USER: "普通用户身份满足登录要求",
    ADMIN: "管理员身份满足后台访问要求",
}

READ_DB = "读数据库"
READ_SECRET = "读应用密钥"
READ_DATA = "读他人数据"
WRITE_FILE = "写任意文件"
RUN_CODE = "执行代码"

GAINS: dict[str, str] = {
    Category.SQL_INJECTION: READ_DB,
    Category.CONFIG_EXPOSURE: READ_SECRET,
    Category.IDOR: READ_DATA,
    Category.MISSING_AUTH: READ_DATA,
    Category.PATH_TRAVERSAL: WRITE_FILE,
    Category.COMMAND_INJECTION: RUN_CODE,
    Category.TEMPLATE_INJECTION: RUN_CODE,
    Category.DESERIALIZATION: RUN_CODE,
}

WEAK_STORAGE = {"plaintext": "明文", "unsalted_hash": "无盐哈希"}
MAX_PATHS = 30


@dataclass(frozen=True)
class ChainFinding:
    id: int
    code: str
    category: str
    title: str
    # 所在路由的访问前提；没有路由时为 None，不进入攻击路径
    access: str | None
    # 动态验证的命中特征，写入边的说明
    matched: str | None = None


@dataclass
class Node:
    key: str
    kind: ChainNodeKind
    label: str
    finding_id: int | None = None


@dataclass(frozen=True)
class Edge:
    src: str
    dst: str
    reason: str


@dataclass
class AttackPathDraft:
    nodes: list[str]
    target: str
    # 每一步：节点、进入该节点所用的边说明
    steps: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class ChainGraph:
    nodes: dict[str, Node]
    edges: list[Edge]
    paths: list[AttackPathDraft]
    # 未进入路径图的已验证漏洞及原因，写日志用
    skipped: list[tuple[ChainFinding, str]] = field(default_factory=list)

    def finding_count(self, path: AttackPathDraft) -> int:
        return sum(self.nodes[key].kind == ChainNodeKind.FINDING for key in path.nodes)


def _finding_key(f: ChainFinding) -> str:
    return f"finding:{f.id}"


def _entry_node(level: int, identities: set[str]) -> str | None:
    """满足访问前提的最低身份节点：匿名用起点；需登录时优先普通用户身份，没有再用管理员身份。"""
    if level == 0:
        return START
    for key in (USER, ADMIN):
        if IDENTITY_LEVEL[key] >= level and key in identities:
            return key
    return None


def _derivations(f: ChainFinding, facts: dict[str, Any]) -> list[tuple[str, str]]:
    """漏洞获得的能力能推出的下一跳（身份节点或终点）与推导说明。"""
    gain = GAINS.get(f.category)
    if gain == RUN_CODE:
        return [(GOAL_RCE, "执行代码")]
    if gain == READ_DATA:
        return [(GOAL_DATA, "读取他人数据")]
    if gain == READ_DB:
        storage = facts.get("password_storage") or {}
        kind = storage.get("kind")
        if kind in WEAK_STORAGE:
            how = f"（{storage['detail']}）" if storage.get("detail") else ""
            verb = "直接取得" if kind == "plaintext" else "离线破解"
            return [(ADMIN, f"读出用户表，密码以{WEAK_STORAGE[kind]}{how}存储，{verb}管理员口令后登录")]
    if gain == READ_SECRET and (facts.get("session") or {}).get("flask_session"):
        return [(ADMIN, "用泄露的应用密钥伪造 Flask 签名会话，冒充管理员")]
    if gain == WRITE_FILE:
        where = f"（{f.matched}）" if f.matched else ""
        return [(GOAL_RCE, f"文件写到上传目录之外的工程目录{where}，覆盖源码或模板后随进程重载执行代码")]
    return []


def build_chain(findings: list[ChainFinding], facts: dict[str, Any]) -> ChainGraph:
    nodes: dict[str, Node] = {START: Node(START, ChainNodeKind.START, "匿名攻击者")}
    edges: dict[tuple[str, str], str] = {}
    skipped: list[tuple[ChainFinding, str]] = []

    usable: list[ChainFinding] = []
    for f in findings:
        if f.category not in GAINS:
            skipped.append((f, "该类别没有登记可获得的能力"))
        elif f.access not in LEVEL:
            skipped.append((f, "没有入口路由，无法确定前置条件"))
        else:
            usable.append(f)

    identities: set[str] = set()
    register = (facts.get("auth") or {}).get("register")
    if register:
        identities.add(USER)
        nodes[USER] = Node(USER, ChainNodeKind.CAPABILITY, "普通用户身份")
        edges[(START, USER)] = f"开放注册接口 {register.get('method', 'POST')} {register.get('path', '')}，注册即得普通用户身份"

    # 身份节点会随推导增加，反复连边直到不再变化；身份只有两级，最多三轮
    while True:
        before = set(identities)
        for f in usable:
            entry = _entry_node(LEVEL[f.access], identities)
            if entry is None:
                continue
            key = _finding_key(f)
            label = f"{f.code} {CATEGORY_LABELS[Category(f.category)]}"
            nodes.setdefault(key, Node(key, ChainNodeKind.FINDING, label, f.id))
            edges[(entry, key)] = ACCESS_TEXT[entry]
            for dst, reason in _derivations(f, facts):
                if dst in IDENTITY_LEVEL and IDENTITY_LEVEL[dst] <= IDENTITY_LEVEL[entry]:
                    continue  # 不推导出已有或更低的身份，避免成环
                if dst == ADMIN and ADMIN not in nodes:
                    nodes[ADMIN] = Node(ADMIN, ChainNodeKind.CAPABILITY, "管理员身份")
                if dst == GOAL_RCE and dst not in nodes:
                    nodes[dst] = Node(dst, ChainNodeKind.GOAL, RUN_CODE)
                if dst == GOAL_DATA and dst not in nodes:
                    nodes[dst] = Node(dst, ChainNodeKind.GOAL, READ_DATA)
                edges[(key, dst)] = reason
                if dst in IDENTITY_LEVEL:
                    identities.add(dst)
        if identities == before:
            break
        # 新身份出现后，原先由更高身份进入的漏洞可能改由更低身份进入，重建漏洞相关的边
        edges = {k: v for k, v in edges.items() if k == (START, USER)}

    for f in usable:
        if _finding_key(f) not in nodes:
            skipped.append((f, "前置条件无法满足"))

    edge_list = [Edge(src, dst, reason) for (src, dst), reason in edges.items()]
    nodes, edge_list = _prune(nodes, edge_list)
    for f in usable:
        if _finding_key(f) not in nodes and not any(s[0] is f for s in skipped):
            skipped.append((f, "获得的能力无法衔接到执行代码或读他人数据"))
    graph = ChainGraph(nodes=nodes, edges=edge_list, paths=[], skipped=skipped)
    graph.paths = _multi_step_paths(graph)
    return graph


def _prune(nodes: dict[str, Node], edges: list[Edge]) -> tuple[dict[str, Node], list[Edge]]:
    """只保留从起点可达且能到达终点的节点。"""
    succ: dict[str, list[str]] = {}
    pred: dict[str, list[str]] = {}
    for e in edges:
        succ.setdefault(e.src, []).append(e.dst)
        pred.setdefault(e.dst, []).append(e.src)

    def reach(starts: list[str], nxt: dict[str, list[str]]) -> set[str]:
        seen = set(starts)
        stack = list(starts)
        while stack:
            for n in nxt.get(stack.pop(), []):
                if n not in seen:
                    seen.add(n)
                    stack.append(n)
        return seen

    goals = [k for k, n in nodes.items() if n.kind == ChainNodeKind.GOAL]
    keep = reach([START], succ) & reach(goals, pred)
    if not goals:
        keep = set()
    kept_nodes = {k: n for k, n in nodes.items() if k in keep}
    kept_edges = [e for e in edges if e.src in keep and e.dst in keep]
    return kept_nodes, kept_edges


def _multi_step_paths(graph: ChainGraph) -> list[AttackPathDraft]:
    succ: dict[str, list[Edge]] = {}
    for e in graph.edges:
        succ.setdefault(e.src, []).append(e)
    found: list[AttackPathDraft] = []

    def walk(key: str, trail: list[str], reasons: list[str]) -> None:
        node = graph.nodes[key]
        if node.kind == ChainNodeKind.GOAL:
            draft = AttackPathDraft(nodes=list(trail), target=node.label)
            draft.steps = [
                {"node": k, "label": graph.nodes[k].label, "kind": str(graph.nodes[k].kind), "via": r}
                for k, r in zip(trail, ["", *reasons], strict=True)
            ]
            if graph.finding_count(draft) >= 2:
                found.append(draft)
            return
        for e in succ.get(key, []):
            if e.dst not in trail:
                walk(e.dst, [*trail, e.dst], [*reasons, e.reason])

    if START in graph.nodes:
        walk(START, [START], [])
    # 执行代码优先，其次漏洞节点多的，再按节点顺序保证结果稳定
    found.sort(key=lambda p: (p.target != RUN_CODE, -graph.finding_count(p), -len(p.nodes), p.nodes))
    return found[:MAX_PATHS]
