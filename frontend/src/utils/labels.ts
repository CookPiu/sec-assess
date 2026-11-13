import type { AuditAction } from '@/api/audit'
import type { Access, FindingBrief } from '@/api/findings'
import type { SecurityLevel } from '@/api/reports'
import type { SettingKey } from '@/api/settings'
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

export const AUDIT_ACTIONS: { key: AuditAction; label: string; tag: TagType }[] = [
  { key: 'login', label: '登录', tag: 'info' },
  { key: 'login_failed', label: '登录失败', tag: 'danger' },
  { key: 'task_create', label: '新建评估', tag: 'primary' },
  { key: 'task_stop', label: '停止评估', tag: 'warning' },
  { key: 'patch_adopt', label: '采纳补丁', tag: 'success' },
  { key: 'report_export', label: '导出报告', tag: 'primary' },
  { key: 'setting_update', label: '修改配置', tag: 'warning' },
]

export const AUDIT_ACTION_META = Object.fromEntries(AUDIT_ACTIONS.map((a) => [a.key, a])) as Record<
  AuditAction,
  (typeof AUDIT_ACTIONS)[number]
>

/** 配置项名称与单位，配置页和审计日志共用 */
export const SETTING_META: Record<SettingKey, { label: string; unit?: string }> = {
  sandbox_image: { label: '沙箱镜像' },
  cpus: { label: 'CPU 核数', unit: '核' },
  memory_mb: { label: '内存上限', unit: 'MB' },
  pids: { label: '进程数上限', unit: '个' },
  task_timeout_min: { label: '单任务超时', unit: '分钟' },
  probe_timeout_s: { label: '单探针超时', unit: '秒' },
  max_concurrent: { label: '并发任务数', unit: '个' },
  network_policy: { label: '网络隔离策略' },
  pypi_index_url: { label: 'PyPI 地址' },
  llm_enabled: { label: '大模型开关' },
  llm_model: { label: '模型名称' },
  llm_base_url: { label: '接口地址' },
  llm_timeout_seconds: { label: '请求超时', unit: '秒' },
  llm_concurrency: { label: '大模型并发数', unit: '个' },
}

/** 配置项的值按页面上的写法显示，例如 1024 MB、已开启 */
export function formatSettingValue(key: string, value: unknown): string {
  if (typeof value === 'boolean') return value ? '已开启' : '已关闭'
  if (value === null || value === undefined || value === '') return '未填写'
  const unit = SETTING_META[key as SettingKey]?.unit
  return unit ? `${value} ${unit}` : String(value)
}
