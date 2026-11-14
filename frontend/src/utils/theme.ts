import { computed, ref, watch } from 'vue'

/** 主题模式：跟随系统、浅色、深色；选择保存在本机浏览器 */
export type ThemeMode = 'system' | 'light' | 'dark'

const STORAGE_KEY = 'sec-assess.theme'

function readMode(): ThemeMode {
  try {
    const value = localStorage.getItem(STORAGE_KEY)
    if (value === 'light' || value === 'dark' || value === 'system') return value
  } catch {
    // 隐私模式等情况下读不到本地存储，按跟随系统处理
  }
  return 'system'
}

const media = window.matchMedia('(prefers-color-scheme: dark)')
const systemDark = ref(media.matches)
media.addEventListener('change', (e) => (systemDark.value = e.matches))

export const themeMode = ref<ThemeMode>(readMode())
export const isDark = computed(() => themeMode.value === 'dark' || (themeMode.value === 'system' && systemDark.value))

export function setThemeMode(mode: ThemeMode): void {
  themeMode.value = mode
  try {
    localStorage.setItem(STORAGE_KEY, mode)
  } catch {
    // 保存失败只影响下次打开时的默认值
  }
}

// Element Plus 的暗色变量挂在 html.dark 上；同步切换，避免首屏闪烁
watch(isDark, (dark) => document.documentElement.classList.toggle('dark', dark), { immediate: true, flush: 'sync' })

/** 图表与拓扑图用的颜色，与 styles.css 中的同名变量保持一致 */
export interface Palette {
  text: string
  textSecondary: string
  muted: string
  border: string
  grid: string
  surface: string
  surfaceAlt: string
  primary: string
  success: string
  warning: string
  danger: string
  severity: Record<'critical' | 'high' | 'medium' | 'low' | 'info', string>
  series: string[]
}

const LIGHT: Palette = {
  text: '#141414',
  textSecondary: '#4d4d4a',
  muted: '#8a8984',
  border: '#e4e3df',
  grid: '#efeeeb',
  surface: '#ffffff',
  surfaceAlt: '#fafaf9',
  primary: '#2f55f4',
  success: '#14855d',
  warning: '#c97f00',
  danger: '#d12c45',
  severity: { critical: '#b0123b', high: '#e04a2f', medium: '#d99000', low: '#2f6fdb', info: '#8a8984' },
  series: ['#141414', '#2f55f4', '#d99000'],
}

const DARK: Palette = {
  text: '#ededea',
  textSecondary: '#b5b5b0',
  muted: '#7d7d78',
  border: '#29292c',
  grid: '#202022',
  surface: '#151516',
  surfaceAlt: '#19191b',
  primary: '#7f95ff',
  success: '#3fcb8f',
  warning: '#f0b440',
  danger: '#ff6b80',
  severity: { critical: '#ff4f78', high: '#ff7e5c', medium: '#f2b33d', low: '#6aa2ff', info: '#7d7d78' },
  series: ['#ededea', '#7f95ff', '#f2b33d'],
}

export const palette = computed<Palette>(() => (isDark.value ? DARK : LIGHT))
