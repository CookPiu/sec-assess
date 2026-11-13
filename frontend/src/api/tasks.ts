import { request } from './http'

export type TaskStatus = 'created' | 'running' | 'completed' | 'failed' | 'stopped'
export type StageKey = 'recon' | 'code_audit' | 'poc_verify' | 'exploit_chain' | 'report_gen'
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

export type SeverityCounts = Record<Severity, number>

export interface TaskBrief {
  id: number
  status: TaskStatus
  current_stage: StageKey | null
  error: string | null
  created_at: string
  started_at: string | null
  finished_at: string | null
  counts: SeverityCounts
}

export interface TaskOut extends TaskBrief {
  project_id: number
  project_name: string
  quota: Record<string, unknown> | null
}

export interface LogEntry {
  id: number
  stage: StageKey | null
  level: 'info' | 'warn' | 'error'
  message: string
  created_at: string
}

export interface TechStack {
  primary_language: string | null
  languages: { name: string; files: number; loc: number }[]
  frameworks: { name: string; version: string | null; ecosystem: string }[]
  manifests: string[]
  dependency_count: number
}

export interface ProjectOut {
  id: number
  name: string
  source_type: 'git' | 'zip'
  source_url: string | null
  tech_stack: TechStack | null
  loc: number | null
  created_at: string
  last_assessed_at: string | null
  latest_task: TaskBrief | null
}

export interface ProjectDetail extends ProjectOut {
  tasks: TaskBrief[]
}

/** 新建评估：三选一，已有项目、Git 地址或 zip 包 */
export type NewTaskSource =
  | { kind: 'project'; projectId: number }
  | { kind: 'git'; url: string; name?: string }
  | { kind: 'zip'; file: File; name?: string }

export function listProjects(): Promise<ProjectOut[]> {
  return request('GET', '/api/projects')
}

export function getProject(id: number): Promise<ProjectDetail> {
  return request('GET', `/api/projects/${id}`)
}

export function createTask(source: NewTaskSource): Promise<TaskOut> {
  const form = new FormData()
  if (source.kind === 'project') {
    form.append('project_id', String(source.projectId))
  } else {
    if (source.name) form.append('name', source.name)
    if (source.kind === 'git') form.append('git_url', source.url)
    else form.append('file', source.file, source.file.name)
  }
  return request('POST', '/api/tasks', { form })
}

export function getTask(id: number): Promise<TaskOut> {
  return request('GET', `/api/tasks/${id}`)
}

export function listLogs(id: number, after = 0): Promise<LogEntry[]> {
  return request('GET', `/api/tasks/${id}/logs`, { query: { after } })
}

export function stopTask(id: number): Promise<TaskOut> {
  return request('POST', `/api/tasks/${id}/stop`)
}
