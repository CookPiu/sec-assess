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
  text: '#1b2232',
  textSecondary: '#4b566b',
  muted: '#8590a6',
  border: '#e2e6ef',
  grid: '#edf0f6',
  surface: '#ffffff',
  surfaceAlt: '#f6f8fc',
  primary: '#3f5bf6',
  success: '#17946a',
  warning: '#d98a0b',
  danger: '#d6334a',
  severity: { critical: '#b3123a', high: '#e2513c', medium: '#e09a16', low: '#3a78d8', info: '#8590a6' },
  series: ['#3f5bf6', '#17946a', '#d98a0b'],
}

const DARK: Palette = {
  text: '#e7eaf3',
  textSecondary: '#b4bccd',
  muted: '#7f89a1',
  border: '#283149',
  grid: '#1f2739',
  surface: '#151b2b',
  surfaceAlt: '#1a2134',
  primary: '#7489ff',
  success: '#3fcf95',
  warning: '#f2b544',
  danger: '#ff6680',
  severity: { critical: '#ff5277', high: '#ff7d5e', medium: '#f4b740', low: '#64a0ff', info: '#7f89a1' },
  series: ['#7489ff', '#3fcf95', '#f2b544'],
}

export const palette = computed<Palette>(() => (isDark.value ? DARK : LIGHT))
