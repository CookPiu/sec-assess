import { request } from './http'

export type AuditAction =
  | 'login'
  | 'login_failed'
  | 'task_create'
  | 'task_stop'
  | 'patch_adopt'
  | 'report_export'
  | 'setting_update'

export interface AuditLogEntry {
  id: number
  username: string
  action: AuditAction
  target_type: 'task' | 'finding' | 'setting' | null
  target_id: string | null
  detail: Record<string, unknown> | null
  created_at: string
}

export interface AuditLogPage {
  total: number
  items: AuditLogEntry[]
}

export interface AuditLogQuery {
  action?: AuditAction
  /** 按用户名精确匹配 */
  username?: string
  limit: number
  offset: number
}

/** 审计日志，最新的在前，仅系统管理员可查 */
export function listAuditLogs(query: AuditLogQuery): Promise<AuditLogPage> {
  return request<AuditLogPage>('GET', '/api/audit-logs', { query: { ...query } })
}
