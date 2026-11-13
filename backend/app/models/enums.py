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
