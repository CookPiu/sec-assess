"""各表状态字段的取值。数据库里按字符串存储。"""

from enum import StrEnum


class Role(StrEnum):
    ENGINEER = "engineer"  # 安全工程师 / 审计人员
    DEVELOPER = "developer"  # 研发人员
    ADMIN = "admin"  # 系统管理员


class SourceType(StrEnum):
    GIT = "git"
    ZIP = "zip"


class TaskStatus(StrEnum):
    CREATED = "created"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    STOPPED = "stopped"


class Stage(StrEnum):
    RECON = "recon"
    CODE_AUDIT = "code_audit"
    POC_VERIFY = "poc_verify"
    EXPLOIT_CHAIN = "exploit_chain"
    REPORT_GEN = "report_gen"


STAGE_ORDER: tuple[Stage, ...] = (
    Stage.RECON,
    Stage.CODE_AUDIT,
    Stage.POC_VERIFY,
    Stage.EXPLOIT_CHAIN,
    Stage.REPORT_GEN,
)

STAGE_LABELS: dict[Stage, str] = {
    Stage.RECON: "环境侦察",
    Stage.CODE_AUDIT: "源码审计",
    Stage.POC_VERIFY: "动态验证",
    Stage.EXPLOIT_CHAIN: "攻击路径推演",
    Stage.REPORT_GEN: "补丁与报告",
}


class Category(StrEnum):
    """漏洞类别，对应 DESIGN.md 5.3 的验证用例与 5.4 的能力登记。"""

    SQL_INJECTION = "sql_injection"
    COMMAND_INJECTION = "command_injection"
    TEMPLATE_INJECTION = "template_injection"
    DESERIALIZATION = "deserialization"
    PATH_TRAVERSAL = "path_traversal"  # 文件上传 / 路径穿越
    IDOR = "idor"
    MISSING_AUTH = "missing_auth"
    DEBUG_MODE = "debug_mode"
    CONFIG_EXPOSURE = "config_exposure"
    HARDCODED_SECRET = "hardcoded_secret"
    WEAK_PASSWORD_STORAGE = "weak_password_storage"


CATEGORY_LABELS: dict[Category, str] = {
    Category.SQL_INJECTION: "SQL 注入",
    Category.COMMAND_INJECTION: "命令注入",
    Category.TEMPLATE_INJECTION: "模板注入",
    Category.DESERIALIZATION: "不安全的反序列化",
    Category.PATH_TRAVERSAL: "文件上传 / 路径穿越",
    Category.IDOR: "越权访问",
    Category.MISSING_AUTH: "缺失鉴权",
    Category.DEBUG_MODE: "调试模式开启",
    Category.CONFIG_EXPOSURE: "配置暴露",
    Category.HARDCODED_SECRET: "硬编码密钥",
    Category.WEAK_PASSWORD_STORAGE: "弱密码存储",
}


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VerifyStatus(StrEnum):
    VERIFIED = "verified"
    UNVERIFIED = "unverified"


class JudgedBy(StrEnum):
    MODEL = "model"  # 大模型研判
    DEFAULT = "default"  # 模型不可用或关闭，按类别默认向量


class ChainNodeKind(StrEnum):
    START = "start"  # 匿名攻击者
    FINDING = "finding"  # 已验证漏洞
    CAPABILITY = "capability"  # 推导出的身份能力
    GOAL = "goal"  # 执行代码 / 读他人数据
