// 登录令牌存放在 localStorage；隐私模式或禁用存储时退化为只在内存中保存
const KEY = 'sec-assess.token'
let memoryToken: string | null = null

export function getToken(): string | null {
  try {
    return localStorage.getItem(KEY) ?? memoryToken
  } catch {
    return memoryToken
  }
}

export function setToken(token: string | null): void {
  memoryToken = token
  try {
    if (token) localStorage.setItem(KEY, token)
    else localStorage.removeItem(KEY)
  } catch {
    // 存储不可用时只保留内存中的令牌
  }
}
