import { download, request } from './http'

export interface PatchOut {
  finding_id: number
  finding_code: string
  file: string
  /** unified diff，在工程根目录执行 git apply 即可应用 */
  diff: string
  added: number
  removed: number
  adopted: boolean
  adopted_by: string | null
  adopted_at: string | null
  created_at: string
  /** 修复前后的整个文件；源码已变化、补丁对不上时为空 */
  original: string | null
  patched: string | null
}

export function getPatch(findingId: number): Promise<PatchOut> {
  return request<PatchOut>('GET', `/api/findings/${findingId}/patch`)
}

export function adoptPatch(findingId: number): Promise<PatchOut> {
  return request<PatchOut>('POST', `/api/findings/${findingId}/patch/adopt`)
}

export function downloadPatch(findingId: number, code: string): Promise<void> {
  return download(`/api/findings/${findingId}/patch/download`, {}, `${code}.patch`)
}
