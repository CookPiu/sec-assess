import { request } from './http'

export interface RuntimeConfig {
  sandbox_image: string
  cpus: number
  memory_mb: number
  pids: number
  task_timeout_min: number
  probe_timeout_s: number
  max_concurrent: number
  /** 固定为无网络，只展示 */
  network_policy: 'none'
  pypi_index_url: string
  llm_enabled: boolean
  llm_model: string
  llm_base_url: string
  llm_timeout_seconds: number
  llm_concurrency: number
}

export type SettingKey = keyof RuntimeConfig
export type EditableKey = Exclude<SettingKey, 'network_policy'>

export interface SandboxImage {
  tag: string
  size_mb: number
  created: string | null
}

export interface SettingsOut {
  values: RuntimeConfig
  defaults: RuntimeConfig
  /** 本机以 sec-assess/ 开头的镜像；Docker 未启动时为空 */
  images: SandboxImage[]
  docker_available: boolean
  /** 大模型密钥只在 .env 中配置，这里只说明是否已配置 */
  llm_key_configured: boolean
  updated_at: string | null
  updated_by: string | null
}

export function getSettings(): Promise<SettingsOut> {
  return request<SettingsOut>('GET', '/api/settings')
}

/** 只需提交改动过的项；修改会写入审计日志 */
export function updateSettings(changes: Partial<Pick<RuntimeConfig, EditableKey>>): Promise<SettingsOut> {
  return request<SettingsOut>('PUT', '/api/settings', { body: changes })
}
