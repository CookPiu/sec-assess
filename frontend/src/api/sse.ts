import { notifyUnauthorized } from './http'
import { getToken } from './token'

export interface ServerEvent {
  event: string
  data: unknown
  ts: string
}

export interface StreamHandlers {
  onEvent: (event: ServerEvent) => void
  /** 每次（重新）连上时调用，用于补拉断线期间漏掉的数据 */
  onOpen?: () => void
}

const MAX_RETRY_MS = 10_000

function parseBlock(block: string): ServerEvent | null {
  let event = 'message'
  const data: string[] = []
  for (const line of block.split('\n')) {
    if (!line || line.startsWith(':')) continue
    const sep = line.indexOf(':')
    const field = sep === -1 ? line : line.slice(0, sep)
    const value = sep === -1 ? '' : line.slice(sep + 1).replace(/^ /, '')
    if (field === 'event') event = value
    else if (field === 'data') data.push(value)
  }
  if (data.length === 0) return null
  try {
    const payload = JSON.parse(data.join('\n')) as { data: unknown; ts: string }
    return { event, data: payload.data, ts: payload.ts }
  } catch {
    return null
  }
}

/**
 * 用 fetch 读取 SSE，以便携带 Authorization 头，令牌不出现在 URL 中。
 * 断线后按 1、2、4…10 秒退避重连；返回的函数用于关闭连接。
 */
export function openEventStream(path: string, handlers: StreamHandlers): () => void {
  const controller = new AbortController()

  async function loop(): Promise<void> {
    let retry = 1000
    while (!controller.signal.aborted) {
      try {
        const token = getToken()
        const resp = await fetch(path, {
          headers: { Accept: 'text/event-stream', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
          signal: controller.signal,
        })
        if (resp.status === 401) {
          notifyUnauthorized()
          return
        }
        if (resp.status === 404) return
        if (!resp.ok || !resp.body) throw new Error(`HTTP ${resp.status}`)

        retry = 1000
        handlers.onOpen?.()
        const reader = resp.body.pipeThrough(new TextDecoderStream()).getReader()
        let buffer = ''
        for (;;) {
          const { value, done } = await reader.read()
          if (done) break
          buffer += value.replace(/\r\n/g, '\n')
          let idx: number
          while ((idx = buffer.indexOf('\n\n')) >= 0) {
            const parsed = parseBlock(buffer.slice(0, idx))
            buffer = buffer.slice(idx + 2)
            if (parsed) handlers.onEvent(parsed)
          }
        }
      } catch {
        if (controller.signal.aborted) return
      }
      await new Promise((resolve) => setTimeout(resolve, retry))
      retry = Math.min(retry * 2, MAX_RETRY_MS)
    }
  }

  void loop()
  return () => controller.abort()
}
