import { download, request } from './http'
import type { SeverityCounts } from './tasks'

export type SecurityLevel = '极高危' | '高危' | '中危' | '安全'
export type ReportFormat = 'md' | 'html' | 'pdf'

export interface ReportBrief {
  task_id: number
  project_id: number
  project_name: string
  finished_at: string | null
  score: number
  level: SecurityLevel
  counts: SeverityCounts
}

export interface ReportOut {
  task_id: number
  project_name: string
  title: string
  score: number
  level: SecurityLevel
  level_reason: string
  /** 完整的 HTML 文档，与导出的 HTML 文件内容一致 */
  html: string
}

/** 已完成评估的报告列表，最新的在前 */
export function listReports(): Promise<ReportBrief[]> {
  return request<ReportBrief[]>('GET', '/api/reports')
}

export function getReport(taskId: number): Promise<ReportOut> {
  return request<ReportOut>('GET', `/api/tasks/${taskId}/report`)
}

export function exportReport(taskId: number, format: ReportFormat): Promise<void> {
  return download(`/api/tasks/${taskId}/report/export`, { format }, `report-task-${taskId}.${format}`)
}
