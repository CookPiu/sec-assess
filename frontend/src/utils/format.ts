/** 后端时间是不带时区的 UTC，补上 Z 再按本地时区显示 */
export function parseServerTime(value: string): Date {
  return new Date(/[zZ]|[+-]\d\d:\d\d$/.test(value) ? value : `${value}Z`)
}

const pad = (n: number) => String(n).padStart(2, '0')

export function formatTime(value: string | null | undefined): string {
  if (!value) return '—'
  const d = parseServerTime(value)
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`
}

export function formatClock(value: string): string {
  const d = parseServerTime(value)
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
}

/** 两个时间之间的时长；end 为空时算到 now（毫秒时间戳） */
export function formatDuration(start: string | null, end: string | null, now: number = Date.now()): string {
  if (!start) return '—'
  const ms = (end ? parseServerTime(end).getTime() : now) - parseServerTime(start).getTime()
  const total = Math.max(0, Math.round(ms / 1000))
  const h = Math.floor(total / 3600)
  const m = Math.floor((total % 3600) / 60)
  const s = total % 60
  return h ? `${h} 时 ${m} 分` : m ? `${m} 分 ${s} 秒` : `${s} 秒`
}
