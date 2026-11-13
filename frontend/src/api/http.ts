import { getToken } from './token'

export class ApiError extends Error {
  readonly status: number

  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

type UnauthorizedHandler = () => void
let onUnauthorized: UnauthorizedHandler | null = null

/** 注册令牌失效时的处理（清除登录状态并跳转登录页），由 main.ts 设置 */
export function setUnauthorizedHandler(handler: UnauthorizedHandler): void {
  onUnauthorized = handler
}

/** 令牌失效时由请求层调用，SSE 等不经过 request 的连接也用它 */
export function notifyUnauthorized(): void {
  onUnauthorized?.()
}

function detailOf(body: unknown, fallback: string): string {
  if (body && typeof body === 'object' && 'detail' in body) {
    const detail = (body as { detail: unknown }).detail
    if (typeof detail === 'string') return detail
    if (Array.isArray(detail)) return '请求参数不合法'
  }
  return fallback
}

/** 携带登录令牌发起请求；返回解析后的 JSON，失败时抛出 ApiError */
export async function request<T>(
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE',
  path: string,
  options: { body?: unknown; query?: Record<string, string | number | undefined>; form?: FormData } = {},
): Promise<T> {
  const url = new URL(path, window.location.origin)
  for (const [key, value] of Object.entries(options.query ?? {})) {
    if (value !== undefined && value !== '') url.searchParams.set(key, String(value))
  }

  const headers: Record<string, string> = { Accept: 'application/json' }
  const token = getToken()
  if (token) headers.Authorization = `Bearer ${token}`

  let body: BodyInit | undefined
  if (options.form) {
    body = options.form
  } else if (options.body !== undefined) {
    headers['Content-Type'] = 'application/json'
    body = JSON.stringify(options.body)
  }

  let resp: Response
  try {
    resp = await fetch(url, { method, headers, body })
  } catch {
    throw new ApiError(0, '无法连接后端服务，请确认后端已启动')
  }

  const text = await resp.text()
  let data: unknown = undefined
  if (text) {
    try {
      data = JSON.parse(text)
    } catch {
      data = text
    }
  }

  if (!resp.ok) {
    if (resp.status === 401 && token && onUnauthorized) onUnauthorized()
    throw new ApiError(resp.status, detailOf(data, `请求失败（${resp.status}）`))
  }
  return data as T
}

function filenameOf(header: string | null): string | null {
  if (!header) return null
  const encoded = /filename\*=UTF-8''([^;]+)/i.exec(header)
  if (encoded) {
    try {
      return decodeURIComponent(encoded[1])
    } catch {
      // 编码不合法时退回普通文件名
    }
  }
  const plain = /filename="([^"]+)"/i.exec(header)
  return plain ? plain[1] : null
}

/** 携带登录令牌下载文件，按响应头 Content-Disposition 里的文件名保存；失败时抛出 ApiError */
export async function download(
  path: string,
  query: Record<string, string> = {},
  fallbackName = 'download',
): Promise<void> {
  const url = new URL(path, window.location.origin)
  for (const [key, value] of Object.entries(query)) url.searchParams.set(key, value)
  const headers: Record<string, string> = {}
  const token = getToken()
  if (token) headers.Authorization = `Bearer ${token}`

  let resp: Response
  try {
    resp = await fetch(url, { headers })
  } catch {
    throw new ApiError(0, '无法连接后端服务，请确认后端已启动')
  }
  if (!resp.ok) {
    let data: unknown = undefined
    try {
      data = await resp.json()
    } catch {
      data = undefined
    }
    if (resp.status === 401 && token && onUnauthorized) onUnauthorized()
    throw new ApiError(resp.status, detailOf(data, `请求失败（${resp.status}）`))
  }

  const href = URL.createObjectURL(await resp.blob())
  const link = document.createElement('a')
  link.href = href
  link.download = filenameOf(resp.headers.get('Content-Disposition')) ?? fallbackName
  document.body.appendChild(link)
  link.click()
  link.remove()
  window.setTimeout(() => URL.revokeObjectURL(href), 1000)
}
