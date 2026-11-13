"""评估报告渲染（T039）：从各表汇集报告数据，按需求 2.5.8 的章节用 Jinja2 生成 Markdown，再转换为 HTML。

HTML 由同一份 Markdown 转换而来，PDF 打印该 HTML，三种格式内容一致。转换时禁用原始 HTML，被评估工程的
代码片段、响应报文等内容只会以转义后的文本出现。
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined
from markdown_it import MarkdownIt
from markupsafe import Markup
from sqlalchemy import select

from app.chain.assemble import READ_DATA, RUN_CODE
from app.core.db import session_factory
from app.models import (
    AttackPath,
    ChainEdge,
    ChainNode,
    Evidence,
    Finding,
    Patch,
    Project,
    Report,
    StageLog,
    TaintStep,
    Task,
)
from app.models.enums import (
    CATEGORY_LABELS,
    SEVERITY_LABELS,
    STAGE_LABELS,
    STAGE_ORDER,
    Category,
    ChainNodeKind,
    JudgedBy,
    SourceType,
    Stage,
    VerifyStatus,
)
from app.project.flask_facts import ACCESS_LABELS
from app.report import charts
from app.report.scoring import PRIORITY_LABELS, ScoreItem, overall_level, remediation_order, security_score

TEMPLATES = Path(__file__).with_name("templates")
MAX_RAW_CHARS = 3000

STAGE_AGENTS: dict[Stage, str] = {
    Stage.RECON: "侦察 Agent",
    Stage.CODE_AUDIT: "审计 Agent",
    Stage.POC_VERIFY: "验证 Agent",
    Stage.EXPLOIT_CHAIN: "推演 Agent",
    Stage.REPORT_GEN: "报告 Agent",
}

# 整改行动的默认指引：模型不可用或没有为某条漏洞写行动时使用
REMEDIATION: dict[str, str] = {
    Category.SQL_INJECTION: "改用参数化查询或 ORM 绑定参数，不要用 f-string、% 或 + 把请求参数拼进 SQL；排序列名等无法参数化的部分按白名单取值。",
    Category.COMMAND_INJECTION: "去掉 shell=True，以列表形式把参数传给 subprocess，并按格式校验主机名、地址等输入。",
    Category.TEMPLATE_INJECTION: "不要把请求内容作为模板源码交给 render_template_string，改用固定模板文件，用户内容只作为模板变量传入。",
    Category.DESERIALIZATION: "不要对外部输入调用 pickle.loads 等反序列化函数，改用 JSON 等纯数据格式；确需导入备份时先校验签名。",
    Category.PATH_TRAVERSAL: "用 secure_filename 处理文件名，校验最终路径位于上传目录内并限制扩展名，上传目录不要放在源码目录下。",
    Category.IDOR: "查询资源时校验其归属当前登录用户，不属于当前用户的资源返回 403 或 404。",
    Category.MISSING_AUTH: "为接口加上登录校验，并按调用者身份限制可返回的数据范围。",
    Category.DEBUG_MODE: "生产环境关闭 debug 模式，改由环境变量控制，避免 Werkzeug 调试控制台和异常堆栈对外暴露。",
    Category.CONFIG_EXPOSURE: "删除或限制调试配置接口，响应中不要返回 SECRET_KEY 等配置项；已经泄露的密钥立即轮换。",
    Category.HARDCODED_SECRET: "把密钥移到环境变量或密钥管理服务，从代码和版本历史中清除，并轮换已提交过的密钥。",
    Category.WEAK_PASSWORD_STORAGE: "改用 bcrypt、scrypt 或 werkzeug.security.generate_password_hash 等加盐慢哈希存储密码，用户下次登录时迁移旧哈希。",
}

# CVSS 分布矩阵的行：标签与区间下限，从高到低
MATRIX_ROWS = (
    ("严重（9.0–10.0）", 9.0),
    ("高危（7.0–8.9）", 7.0),
    ("中危（4.0–6.9）", 4.0),
    ("低危（0.1–3.9）", 0.1),
    ("无风险评分（0.0）", 0.0),
)


@dataclass
class ReportData:
    task: Task
    project: Project
    findings: list[Finding]
    steps: dict[int, list[TaintStep]]
    evidence: dict[int, Evidence]
    patches: dict[int, Patch]
    nodes: dict[int, ChainNode]
    edges: list[ChainEdge]
    paths: list[AttackPath]
    logs: list[StageLog]
    report: Report | None

    @property
    def counted(self) -> list[Finding]:
        """计入评分与统计的漏洞（排除模型判定误报）。"""
        return [f for f in self.findings if not f.model_false_positive]

    def score_items(self) -> list[ScoreItem]:
        return [
            ScoreItem(
                code=f.code,
                severity=f.severity,
                cvss=f.cvss_score,
                verified=f.status == VerifyStatus.VERIFIED,
                false_positive=f.model_false_positive,
            )
            for f in self.findings
        ]

    def finding_codes(self, path: AttackPath) -> list[str]:
        codes = {f.id: f.code for f in self.findings}
        return [
            codes[self.nodes[i].finding_id]
            for i in path.node_ids
            if i in self.nodes and self.nodes[i].finding_id in codes
        ]

    def code_execution_codes(self) -> set[str]:
        """位于“执行代码”路径上的漏洞编号。"""
        return {code for p in self.paths if p.target == RUN_CODE for code in self.finding_codes(p)}

    @property
    def reaches_code_execution(self) -> bool:
        return any(path.target == RUN_CODE for path in self.paths)

    def summary(self) -> tuple[int, str, str]:
        """安全评分、综合等级与判定依据。"""
        items = self.score_items()
        level, reason = overall_level(items, self.reaches_code_execution)
        return security_score(items), level, reason


async def load_report_data(task_id: int) -> ReportData | None:
    async with session_factory()() as session:
        task = await session.get(Task, task_id)
        if task is None:
            return None
        project = await session.get(Project, task.project_id)
        findings = list(
            (await session.execute(select(Finding).where(Finding.task_id == task_id).order_by(Finding.id))).scalars()
        )
        ids = [f.id for f in findings]
        steps: dict[int, list[TaintStep]] = defaultdict(list)
        evidence: dict[int, Evidence] = {}
        patches: dict[int, Patch] = {}
        if ids:
            for step in (
                await session.execute(
                    select(TaintStep).where(TaintStep.finding_id.in_(ids)).order_by(TaintStep.finding_id, TaintStep.seq)
                )
            ).scalars():
                steps[step.finding_id].append(step)
            # 每条漏洞取第一条命中的证据
            for item in (
                await session.execute(
                    select(Evidence).where(Evidence.finding_id.in_(ids), Evidence.hit.is_(True)).order_by(Evidence.id)
                )
            ).scalars():
                evidence.setdefault(item.finding_id, item)
            for patch in (await session.execute(select(Patch).where(Patch.finding_id.in_(ids)))).scalars():
                patches[patch.finding_id] = patch
        nodes = {
            n.id: n for n in (await session.execute(select(ChainNode).where(ChainNode.task_id == task_id))).scalars()
        }
        edges = list((await session.execute(select(ChainEdge).where(ChainEdge.task_id == task_id))).scalars())
        paths = list(
            (
                await session.execute(select(AttackPath).where(AttackPath.task_id == task_id).order_by(AttackPath.id))
            ).scalars()
        )
        logs = list(
            (await session.execute(select(StageLog).where(StageLog.task_id == task_id).order_by(StageLog.id))).scalars()
        )
        report = (await session.execute(select(Report).where(Report.task_id == task_id))).scalar_one_or_none()
    return ReportData(task, project, findings, steps, evidence, patches, nodes, edges, paths, logs, report)


# ---------- 文字整理 ----------


def local_time(value: datetime | None) -> str:
    """库里是不带时区的 UTC 时间，按后端进程所在时区显示并注明偏移，导出的文件离开系统后也不会误读。"""
    if value is None:
        return "—"
    local = value.replace(tzinfo=UTC).astimezone()
    offset = local.strftime("%z")
    return f"{local:%Y-%m-%d %H:%M:%S}（UTC{offset[:3]}:{offset[3:]}）"


def duration_text(seconds: float | None) -> str:
    """数字与单位之间用不换行空格，表格窄列里不会被拆成两行。"""
    if seconds is None:
        return "—"
    if seconds < 60:
        return f"{seconds:.1f} 秒"
    minutes, rest = divmod(round(seconds), 60)
    if minutes < 60:
        return f"{minutes} 分 {rest} 秒"
    return f"{minutes // 60} 时 {minutes % 60} 分"


def route_text(finding: Finding) -> str:
    route = finding.route or {}
    if not route:
        return "—"
    methods = " / ".join(route.get("methods") or [])
    access = ACCESS_LABELS.get(route.get("access") or "", "")
    text = f"{methods} {route.get('path', '')}".strip()
    return f"{text}（{access}可访问）" if access else text


def cvss_text(finding: Finding) -> str:
    return f"{finding.cvss_score:.1f}" if finding.cvss_score is not None else "—"


def clip(text: str | None, limit: int = MAX_RAW_CHARS) -> tuple[str, bool]:
    text = text or ""
    return (text[:limit], True) if len(text) > limit else (text, False)


def default_conclusion(data: ReportData) -> str:
    """模型不可用时按统计数据生成的评估结论。"""
    counted = data.counted
    if not counted:
        return "本次评估没有发现漏洞，也没有可推演的攻击路径。"
    verified = sum(f.status == VerifyStatus.VERIFIED for f in counted)
    text = f"本次评估共发现 {len(counted)} 条问题，其中已验证 {verified} 条、疑似 {len(counted) - verified} 条。"
    if data.paths:
        rce = sum(p.target == RUN_CODE for p in data.paths)
        text += f"推演出 {len(data.paths)} 条多步攻击路径，其中 {rce} 条可到达执行代码。"
    ranked = remediation_order(data.score_items(), data.code_execution_codes())
    # 疑似漏洞（P4）需要先复核，不列为优先修复项
    first = ranked[0][0]
    urgent = [item.code for prio, item in ranked if prio == first] if first < 3 else []
    if urgent:
        more = f" 等 {len(urgent)} 条" if len(urgent) > 5 else ""
        text += f"应优先修复 {PRIORITY_LABELS[first][:2]} 级的 {'、'.join(urgent[:5])}{more}。"
    else:
        text += "没有已验证漏洞，建议先人工复核疑似漏洞。"
    return text


def _stack_text(stack: dict[str, Any]) -> str:
    parts = [stack.get("primary_language") or "未识别"]
    for fw in stack.get("frameworks") or []:
        parts.append(f"{fw['name']} {fw['version']}" if fw.get("version") else fw["name"])
    return "，".join(parts)


def _loc_text(stack: dict[str, Any]) -> str:
    loc = stack.get("loc")
    if loc is None:
        return "—"
    langs = "、".join(f"{x['name']} {x['loc']} 行" for x in (stack.get("languages") or [])[:5])
    return f"{loc} 行（{langs}）" if langs else f"{loc} 行"


def _deps_text(deps: dict[str, Any] | None) -> str:
    if not deps:
        return "未执行依赖准备"
    if deps.get("error"):
        return f"依赖准备失败：{deps['error']}"
    installed = deps.get("installed") or []
    preinstalled = deps.get("preinstalled") or []
    missing = deps.get("missing") or []
    fallback = sum(bool(x.get("fallback")) for x in preinstalled)
    text = f"离线安装 {len(installed)} 个，使用沙箱预装版本 {len(preinstalled)} 个"
    if fallback:
        text += f"（其中 {fallback} 个为下载或安装失败后的回退）"
    if missing:
        text += f"，缺失 {len(missing)} 个：{'、'.join(x.get('name', '?') for x in missing)}"
    return text


def _coverage_notes(data: ReportData) -> list[str]:
    """评估没有覆盖到的范围（非 Flask 工程、依赖缺失、验证中止、大模型未参与）。"""
    recon = data.task.recon or {}
    stack = recon.get("stack") or {}
    facts = recon.get("facts") or {}
    notes: list[str] = []
    if stack and stack.get("primary_language") != "Python":
        notes.append(
            f"工程主要语言为 {stack.get('primary_language') or '未识别'}，首版只对 Python Flask 工程做污点分析与动态验证。"
        )
    if not facts.get("is_flask"):
        notes.append(
            "未识别到 Flask 应用：代码审计只运行了敏感信息规则，动态验证与攻击路径推演没有执行，"
            "报告不覆盖注入、越权等需要追踪请求参数的漏洞类型。"
        )
    elif not facts.get("entry"):
        notes.append("未识别到 Flask 启动入口，动态验证没有执行，候选漏洞均保持疑似。")
    else:
        deps = data.task.deps_result or {}
        if deps.get("ok") is not True or deps.get("missing"):
            notes.append("工程依赖未准备就绪，动态验证没有执行，候选漏洞均保持疑似。")
    for entry in data.logs:
        if entry.stage == Stage.POC_VERIFY and entry.level != "info" and "中止" in entry.message:
            notes.append(entry.message)
    if data.findings and all(f.judged_by != JudgedBy.MODEL for f in data.findings):
        notes.append("大模型没有参与研判，CVSS 采用各漏洞类别的默认向量。")
    return notes


def _stage_rows(data: ReportData, score: int, level: str) -> list[dict[str, str]]:
    times: dict[str, list[datetime]] = defaultdict(list)
    for entry in data.logs:
        if entry.stage:
            times[entry.stage].append(entry.created_at)
    recon = data.task.recon or {}
    stack = recon.get("stack") or {}
    facts = recon.get("facts") or {}
    counted = data.counted
    verified = sum(f.status == VerifyStatus.VERIFIED for f in counted)
    by_model = sum(f.judged_by == JudgedBy.MODEL for f in data.findings)
    in_graph = sum(n.kind == ChainNodeKind.FINDING for n in data.nodes.values())
    results = {
        Stage.RECON: f"{_stack_text(stack)}，代码 {stack.get('loc', 0)} 行，路由 {len(facts.get('routes') or [])} 条；"
        f"依赖：{_deps_text(data.task.deps_result)}",
        Stage.CODE_AUDIT: f"候选漏洞 {len(data.findings)} 条，大模型研判 {by_model} 条、按默认向量 "
        f"{len(data.findings) - by_model} 条，判定误报 {len(data.findings) - len(counted)} 条",
        Stage.POC_VERIFY: f"验证通过 {verified} 条，保持疑似 {len(counted) - verified} 条",
        Stage.EXPLOIT_CHAIN: f"进入攻击路径图的漏洞 {in_graph} 条，多步攻击路径 {len(data.paths)} 条",
        Stage.REPORT_GEN: f"安全评分 {score}，综合安全等级{level}",
    }
    rows = []
    for stage in STAGE_ORDER:
        stamps = times.get(stage)
        rows.append(
            {
                "label": f"{STAGE_LABELS[stage]}（{STAGE_AGENTS[stage]}）",
                "duration": duration_text((max(stamps) - min(stamps)).total_seconds()) if stamps else "未执行",
                "result": results[stage] if stamps else "—",
            }
        )
    return rows


def _paths_note(data: ReportData) -> str:
    """没有多步路径时写明原因。"""
    if not any(f.status == VerifyStatus.VERIFIED for f in data.counted):
        return "本次评估没有已验证漏洞，不生成攻击路径。"
    goals = {n.id: n.label for n in data.nodes.values() if n.kind == ChainNodeKind.GOAL}
    codes = {f.id: f.code for f in data.findings}
    direct: dict[str, list[str]] = defaultdict(list)
    for edge in data.edges:
        node = data.nodes.get(edge.src_id)
        if edge.dst_id in goals and node is not None and node.finding_id in codes:
            direct[goals[edge.dst_id]].append(codes[node.finding_id])
    if direct:
        detail = "；".join(f"{'、'.join(sorted(v))} 各自一步即可到达“{goal}”" for goal, v in direct.items())
        return f"已验证漏洞之间没有能力衔接，不构成经过两个及以上漏洞的多步攻击路径：{detail}。"
    return f"已验证漏洞获得的能力无法衔接到“{RUN_CODE}”或“{READ_DATA}”，不生成多步攻击路径。"


def _matrix(items: list[ScoreItem]) -> list[dict[str, Any]]:
    rows = []
    for i, (label, floor) in enumerate(MATRIX_ROWS):
        ceiling = MATRIX_ROWS[i - 1][1] if i else float("inf")
        bucket = [it for it in items if floor <= it.effective_cvss < ceiling]
        if floor == 0.0 and not bucket:
            continue
        verified = sum(it.verified for it in bucket)
        rows.append({"label": label, "verified": verified, "unverified": len(bucket) - verified, "total": len(bucket)})
    rows.append(
        {
            "label": "合计",
            "verified": sum(r["verified"] for r in rows),
            "unverified": sum(r["unverified"] for r in rows),
            "total": sum(r["total"] for r in rows),
        }
    )
    return rows


def _verified_item(data: ReportData, f: Finding) -> dict[str, Any]:
    ev = data.evidence.get(f.id)
    evidence = None
    if ev is not None:
        request, _ = clip(ev.request_raw)
        response, cut = clip(ev.response_raw)
        evidence = {
            "matched": ev.matched or "—",
            "request": request or "（无）",
            "response": response or "（无）",
            "response_note": f"（截取前 {MAX_RAW_CHARS} 个字符）" if cut else "",
        }
    patch = data.patches.get(f.id)
    return {
        "code": f.code,
        "title": f.title,
        "category": CATEGORY_LABELS.get(f.category, f.category),
        "severity": SEVERITY_LABELS.get(f.severity, f.severity),
        "cvss": cvss_text(f),
        "vector": f.cvss_vector or "—",
        "location": f"{f.file}:{f.line}",
        "route": route_text(f),
        "reason": f.reason or "—",
        "steps": [
            {"location": f"{s.file}:{s.line}", "note": s.note, "snippet": s.snippet.strip()}
            for s in data.steps.get(f.id, [])
        ],
        "evidence": evidence,
        "patch": patch.diff if patch else None,
    }


def _remediation(data: ReportData) -> list[dict[str, Any]]:
    by_code = {f.code: f for f in data.findings}
    path_count = Counter(code for p in data.paths for code in data.finding_codes(p))
    actions = (data.report.actions if data.report else None) or {}
    groups: dict[int, list[dict[str, Any]]] = defaultdict(list)
    ranked = remediation_order(data.score_items(), data.code_execution_codes())
    for index, (prio, item) in enumerate(ranked, 1):
        f = by_code[item.code]
        meta = [f"{SEVERITY_LABELS.get(f.severity, f.severity)} CVSS {cvss_text(f)}", "已验证" if item.verified else "疑似"]
        if path_count[item.code]:
            meta.append(f"涉及 {path_count[item.code]} 条攻击路径")
        groups[prio].append(
            {
                "index": index,
                "code": f.code,
                "title": f.title,
                "location": f"{f.file}:{f.line}",
                "meta": "，".join(meta),
                "action": actions.get(f.code) or REMEDIATION.get(f.category, "按漏洞成因修复后重新评估。"),
            }
        )
    return [{"label": PRIORITY_LABELS[p], "entries": groups[p]} for p in sorted(groups)]


def build_context(data: ReportData, now: datetime | None = None) -> dict[str, Any]:
    task, project = data.task, data.project
    stack = (task.recon or {}).get("stack") or {}
    score, level, reason = data.summary()
    counted = data.counted
    verified_rows = sorted(
        (f for f in counted if f.status == VerifyStatus.VERIFIED), key=lambda f: (-(f.cvss_score or 0), f.code)
    )
    unverified_rows = [f for f in counted if f.status != VerifyStatus.VERIFIED]

    order = list(Category)
    by_type = Counter(f.category for f in counted)
    type_rows = sorted(by_type.items(), key=lambda kv: (-kv[1], order.index(kv[0]) if kv[0] in order else len(order)))
    labelled = [(CATEGORY_LABELS.get(cat, cat), n) for cat, n in type_rows]
    chart = charts.pie_svg(labelled)

    paths = [
        {
            "title": " → ".join(data.nodes[i].label for i in path.node_ids if i in data.nodes),
            "target": path.target,
            "codes": "、".join(data.finding_codes(path)),
            # 进入依据与节点名相同（如终点“执行代码”）时不重复显示
            "steps": [
                {"label": s.get("label", ""), "via": s.get("via") if s.get("via") not in (None, "", s.get("label")) else "—"}
                for s in (path.detail or {}).get("steps") or []
            ],
            "summary": path.summary or "—",
            "impact": path.impact or "—",
            "written_by": "大模型撰写" if (path.detail or {}).get("written_by") == "model" else "按路径步骤生成",
        }
        for path in data.paths
    ]

    started, finished = task.started_at, task.finished_at
    image = (task.quota or {}).get("sandbox_image")
    manifests = stack.get("manifests") or []
    return {
        "title": report_title(data),
        "generated_at": local_time((now or datetime.now(UTC)).replace(tzinfo=None)),
        "task": {
            "id": task.id,
            "started": local_time(started),
            "finished": local_time(finished),
            "duration": duration_text((finished - started).total_seconds()) if started and finished else "—",
        },
        "project": {
            "name": project.name,
            "source": project.source_url
            if project.source_type == SourceType.GIT and project.source_url
            else "源码压缩包上传",
            "stack": _stack_text(stack) if stack else "—",
            "runtime": f"沙箱镜像 {image}" if image else "—",
            "loc": _loc_text(stack),
            "manifests": f"{'、'.join(manifests)}，共 {len(stack.get('dependencies') or [])} 项依赖"
            if manifests
            else "未找到依赖清单",
            "deps": _deps_text(task.deps_result),
        },
        "stages": _stage_rows(data, score, level),
        "coverage": _coverage_notes(data),
        "score": score,
        "level": level,
        "level_reason": reason,
        "conclusion": data.report.conclusion if data.report else default_conclusion(data),
        "stats": {
            "verified": len(verified_rows),
            "unverified": len(unverified_rows),
            "false_positive": len(data.findings) - len(counted),
        },
        "matrix": _matrix([it for it in data.score_items() if not it.false_positive]),
        "type_chart": charts.data_uri(chart) if chart else "",
        "type_rows": [{"label": label, "count": n, "share": f"{n / len(counted) * 100:.1f}%"} for label, n in labelled],
        "verified": [_verified_item(data, f) for f in verified_rows],
        "unverified": [
            {
                "code": f.code,
                "category": CATEGORY_LABELS.get(f.category, f.category),
                "severity": SEVERITY_LABELS.get(f.severity, f.severity),
                "cvss": cvss_text(f),
                "location": f"{f.file}:{f.line}",
                "reason": f.reason or "—",
            }
            for f in unverified_rows
        ],
        "paths": paths,
        "rce_paths": sum(p.target == RUN_CODE for p in data.paths),
        "paths_note": "" if data.paths else _paths_note(data),
        "remediation": _remediation(data),
    }


# ---------- Markdown 过滤器 ----------

_INLINE_SPECIAL = re.compile(r"([\\`*_\[\]<>|~#])")
_BLOCK_START = re.compile(r"^(\s*)([>+\-=]|\d+[.)])")


def md_inline(value: object) -> str:
    """行内文字：转义 Markdown 语法字符，换行改为空格。"""
    if value is None or value == "":
        return "—"
    text = " ".join(str(value).splitlines())
    return _INLINE_SPECIAL.sub(r"\\\1", text)


def md_block(value: object) -> str:
    """多行文字：逐行转义，行首的列表、引用标记也转义，行间用硬换行。"""
    if value is None or value == "":
        return "—"
    lines = []
    for line in str(value).strip().splitlines():
        escaped = _INLINE_SPECIAL.sub(r"\\\1", line.strip())
        if escaped:
            lines.append(_BLOCK_START.sub(r"\1\\\2", escaped))
    return "  \n".join(lines)


def md_code(value: object) -> str:
    """行内代码，反引号数量多于内容里最长的连续反引号。"""
    text = " ".join(str(value or "").splitlines()) or "—"
    longest = max((len(m) for m in re.findall(r"`+", text)), default=0)
    fence = "`" * (longest + 1)
    pad = " " if text.startswith("`") or text.endswith("`") else ""
    return f"{fence}{pad}{text}{pad}{fence}"


def md_fence(value: object, lang: str = "") -> str:
    """代码块，围栏长度多于内容里最长的连续反引号。"""
    text = str(value or "").rstrip("\n")
    longest = max((len(m) for m in re.findall(r"`{3,}", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}{lang}\n{text}\n{fence}"


@lru_cache
def _markdown_env() -> Environment:
    env = Environment(
        loader=FileSystemLoader(TEMPLATES),
        autoescape=False,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
        undefined=StrictUndefined,
    )
    env.filters.update(md=md_inline, block=md_block, code=md_code, fence=md_fence)
    return env


@lru_cache
def _html_env() -> Environment:
    return Environment(loader=FileSystemLoader(TEMPLATES), autoescape=True, undefined=StrictUndefined)


def _validate_link(url: str) -> bool:
    # 报告里的链接只有模板生成的 SVG 图表
    return url.startswith(charts.DATA_URI_PREFIX)


@lru_cache
def _markdown_it() -> MarkdownIt:
    md = MarkdownIt("commonmark", {"html": False}).enable("table")
    md.validateLink = _validate_link
    return md


def report_title(data: ReportData) -> str:
    return f"{data.project.name} 安全评估报告"


def render_markdown(data: ReportData, now: datetime | None = None) -> str:
    return _markdown_env().get_template("report.md.j2").render(**build_context(data, now))


def markdown_to_html(markdown: str, title: str) -> str:
    body = Markup(_markdown_it().render(markdown))
    return _html_env().get_template("report.html.j2").render(title=title, body=body)
