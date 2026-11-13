import { request } from './http'

export type Role = 'engineer' | 'developer' | 'admin'

export interface User {
  id: number
  username: string
  display_name: string
  role: Role
}

export interface LoginResult {
  token: string
  user: User
}

export function login(username: string, password: string): Promise<LoginResult> {
  return request<LoginResult>('POST', '/api/auth/login', { body: { username, password } })
}

export function fetchMe(): Promise<User> {
  return request<User>('GET', '/api/auth/me')
}
