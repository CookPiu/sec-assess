import type { FindingRoute } from './findings'
import { request } from './http'
import type { Severity } from './tasks'

export type ChainNodeKind = 'start' | 'finding' | 'capability' | 'goal'

export interface ChainNode {
  id: number
  kind: ChainNodeKind
  label: string
  finding_id: number | null
  severity: Severity | null
  title: string | null
  route: FindingRoute | null
}

export interface ChainEdge {
  id: number
  src: number
  dst: number
  /** 前一步获得的能力或推导依据 */
  reason: string
}

export interface AttackPathStep {
  node_id: number
  label: string
  kind: ChainNodeKind
  /** 进入该节点所依据的能力或条件，起点为空 */
  via: string
}

export interface AttackPath {
  id: number
  node_ids: number[]
  target: string
  summary: string | null
  impact: string | null
  steps: AttackPathStep[]
  written_by: 'model' | 'template' | null
}

export interface ChainData {
  nodes: ChainNode[]
  edges: ChainEdge[]
  paths: AttackPath[]
}

export function getChain(taskId: number): Promise<ChainData> {
  return request('GET', `/api/tasks/${taskId}/chain`)
}
