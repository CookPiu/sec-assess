import { request } from './http'
import type { Severity } from './tasks'

export type VerifyStatus = 'verified' | 'unverified'
export type Access = 'anonymous' | 'user' | 'admin'

export interface FindingRoute {
  path: string
  methods: string[]
  access: Access
}

export interface FindingBrief {
  id: number
  code: string
  category: string
  title: string
  severity: Severity
  cvss_vector: string | null
  cvss_score: number | null
  file: string
  line: number
  route: FindingRoute | null
  status: VerifyStatus
  model_false_positive: boolean
  judged_by: 'model' | 'default' | null
}

export interface TaintStep {
  seq: number
  file: string
  line: number
  snippet: string
  note: string
}

export interface Evidence {
  id: number
  case: Record<string, unknown>
  request_raw: string | null
  response_raw: string | null
  /** 命中时为命中特征，未命中时为未命中原因 */
  matched: string | null
  hit: boolean
  created_at: string
}

export interface FindingDetail extends FindingBrief {
  task_id: number
  reason: string | null
  created_at: string
  steps: TaintStep[]
  evidence: Evidence[]
}

export function listFindings(taskId: number): Promise<FindingBrief[]> {
  return request('GET', `/api/tasks/${taskId}/findings`)
}

export function getFinding(id: number): Promise<FindingDetail> {
  return request('GET', `/api/findings/${id}`)
}

export async function getSource(taskId: number, path: string): Promise<string> {
  const body = await request<{ path: string; content: string }>('GET', `/api/tasks/${taskId}/source`, {
    query: { path },
  })
  return body.content
}
