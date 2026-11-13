/** CVSS 3.x 基础向量的指标名称与取值说明，用于把向量拆成可读的标签 */
const METRICS: Record<string, { label: string; values: Record<string, string>; risky: string[] }> = {
  AV: { label: '攻击途径', values: { N: '网络', A: '相邻网络', L: '本地', P: '物理接触' }, risky: ['N'] },
  AC: { label: '攻击复杂度', values: { L: '低', H: '高' }, risky: ['L'] },
  PR: { label: '所需权限', values: { N: '无', L: '低', H: '高' }, risky: ['N'] },
  UI: { label: '用户交互', values: { N: '不需要', R: '需要' }, risky: ['N'] },
  S: { label: '影响范围', values: { U: '不变', C: '改变' }, risky: ['C'] },
  C: { label: '机密性', values: { H: '高', L: '低', N: '无' }, risky: ['H'] },
  I: { label: '完整性', values: { H: '高', L: '低', N: '无' }, risky: ['H'] },
  A: { label: '可用性', values: { H: '高', L: '低', N: '无' }, risky: ['H'] },
}

export interface CvssMetric {
  key: string
  label: string
  value: string
  text: string
  /** 取值使风险升高（例如网络可达、无需权限、影响为高） */
  risky: boolean
}

/** 解析向量；格式不对时返回空数组，界面退回显示原文 */
export function describeVector(vector: string | null | undefined): CvssMetric[] {
  if (!vector) return []
  const parts = vector.trim().split('/')
  if (!/^CVSS:3\.[01]$/.test(parts[0] ?? '')) return []
  const result: CvssMetric[] = []
  for (const part of parts.slice(1)) {
    const [key, value] = part.split(':')
    const meta = METRICS[key]
    if (!meta || !value) continue
    result.push({
      key,
      label: meta.label,
      value,
      text: meta.values[value] ?? value,
      risky: meta.risky.includes(value),
    })
  }
  return result
}
