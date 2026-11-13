import type { Access, FindingBrief } from '@/api/findings'
import type { SecurityLevel } from '@/api/reports'
import type { Severity, StageKey, TaskStatus } from '@/api/tasks'

export const STAGES: { key: StageKey; label: string }[] = [
  { key: 'recon', label: '环境侦察' },
  { key: 'code_audit', label: '源码审计' },
  { key: 'poc_verify', label: '动态验证' },
  { key: 'exploit_chain', label: '攻击路径推演' },
  { key: 'report_gen', label: '补丁与报告' },
]

export const STAGE_LABELS = Object.fromEntries(STAGES.map((s) => [s.key, s.label])) as Record<StageKey, string>

type TagType = 'primary' | 'success' | 'info' | 'warning' | 'danger'

export const STATUS_META: Record<TaskStatus, { label: string; tag: TagType }> = {
  created: { label: '排队中', tag: 'info' },
  running: { label: '评估中', tag: 'primary' },
  completed: { label: '已完成', tag: 'success' },
  failed: { label: '失败', tag: 'danger' },
  stopped: { label: '已停止', tag: 'warning' },
}

export const ACTIVE_STATUSES: TaskStatus[] = ['created', 'running']

export const SEVERITIES: { key: Severity; label: string; color: string }[] = [
  { key: 'critical', label: '严重', color: '#a8071a' },
  { key: 'high', label: '高危', color: '#f56c6c' },
  { key: 'medium', label: '中危', color: '#e6a23c' },
  { key: 'low', label: '低危', color: '#409eff' },
]

export const SEVERITY_META: Record<Severity, { label: string; tag: TagType }> = {
  critical: { label: '严重', tag: 'danger' },
  high: { label: '高危', tag: 'danger' },
  medium: { label: '中危', tag: 'warning' },
  low: { label: '低危', tag: 'primary' },
  info: { label: '信息', tag: 'info' },
}

/** 综合安全等级的标签样式，极高危用实心红色与高危区分 */
export const LEVEL_META: Record<SecurityLevel, { tag: TagType; effect: 'dark' | 'light' }> = {
  极高危: { tag: 'danger', effect: 'dark' },
  高危: { tag: 'danger', effect: 'light' },
  中危: { tag: 'warning', effect: 'light' },
  安全: { tag: 'success', effect: 'light' },
}

export const CATEGORY_LABELS: Record<string, string> = {
  sql_injection: 'SQL 注入',
  command_injection: '命令注入',
  template_injection: '模板注入',
  deserialization: '不安全的反序列化',
  path_traversal: '文件上传 / 路径穿越',
  idor: '越权访问',
  missing_auth: '缺失鉴权',
  debug_mode: '调试模式开启',
  config_exposure: '配置暴露',
  hardcoded_secret: '硬编码密钥',
  weak_password_storage: '弱密码存储',
}

export const ACCESS_LABELS: Record<Access, string> = { anonymous: '匿名', user: '普通用户', admin: '管理员' }

export type FindingGroup = 'verified' | 'unverified' | 'false_positive'

export const FINDING_GROUPS: { key: FindingGroup; label: string; tag: TagType }[] = [
  { key: 'verified', label: '已验证', tag: 'danger' },
  { key: 'unverified', label: '疑似', tag: 'warning' },
  { key: 'false_positive', label: '模型判定误报', tag: 'info' },
]

export const FINDING_GROUP_META = Object.fromEntries(FINDING_GROUPS.map((g) => [g.key, g])) as Record<
  FindingGroup,
  (typeof FINDING_GROUPS)[number]
>

/** 模型判定误报优先于验证状态：误报不进动态验证，始终是 unverified */
export function findingGroup(f: Pick<FindingBrief, 'status' | 'model_false_positive'>): FindingGroup {
  if (f.model_false_positive) return 'false_positive'
  return f.status === 'verified' ? 'verified' : 'unverified'
}
