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
