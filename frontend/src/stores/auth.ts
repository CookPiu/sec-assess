import { defineStore } from 'pinia'
import { computed, ref } from 'vue'

import { fetchMe, login as loginApi, type Role, type User } from '@/api/auth'
import { getToken, setToken } from '@/api/token'

export const ROLE_LABELS: Record<Role, string> = {
  engineer: '安全工程师',
  developer: '研发人员',
  admin: '系统管理员',
}

export const useAuthStore = defineStore('auth', () => {
  const token = ref<string | null>(getToken())
  const user = ref<User | null>(null)

  const isLoggedIn = computed(() => token.value !== null)
  const roleLabel = computed(() => (user.value ? ROLE_LABELS[user.value.role] : ''))

  function hasRole(...roles: Role[]): boolean {
    return user.value !== null && roles.includes(user.value.role)
  }

  async function login(username: string, password: string): Promise<void> {
    const result = await loginApi(username, password)
    token.value = result.token
    user.value = result.user
    setToken(result.token)
  }

  /** 页面刷新后用已保存的令牌取回当前用户；令牌失效时清除登录状态 */
  async function ensureUser(): Promise<User | null> {
    if (!token.value) return null
    if (user.value) return user.value
    try {
      user.value = await fetchMe()
    } catch {
      logout()
    }
    return user.value
  }

  function logout(): void {
    token.value = null
    user.value = null
    setToken(null)
  }

  return { token, user, isLoggedIn, roleLabel, hasRole, login, ensureUser, logout }
})
