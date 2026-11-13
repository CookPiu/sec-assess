import { ElMessage } from 'element-plus'
import { createRouter, createWebHistory, type RouteRecordRaw } from 'vue-router'

import type { Role } from '@/api/auth'
import { ApiError } from '@/api/http'
import MainLayout from '@/layouts/MainLayout.vue'
import { useAuthStore } from '@/stores/auth'

declare module 'vue-router' {
  interface RouteMeta {
    title?: string
    /** 为 true 时不需要登录 */
    public?: boolean
    /** 允许访问的角色；不写表示所有登录用户 */
    roles?: Role[]
    /** 出现在顶部菜单中 */
    menu?: boolean
    icon?: string
  }
}

const routes: RouteRecordRaw[] = [
  {
    path: '/login',
    name: 'login',
    component: () => import('@/views/LoginView.vue'),
    meta: { title: '登录', public: true },
  },
  {
    path: '/',
    component: MainLayout,
    children: [
      {
        path: '',
        name: 'dashboard',
        component: () => import('@/views/DashboardView.vue'),
        meta: { title: '项目概览', menu: true, icon: 'DataBoard' },
      },
      {
        path: 'tasks/:taskId',
        name: 'workbench',
        component: () => import('@/views/WorkbenchView.vue'),
        meta: { title: '评估工作台' },
      },
      {
        path: 'reports',
        name: 'reports',
        component: () => import('@/views/ReportCenterView.vue'),
        meta: { title: '报告中心', menu: true, icon: 'Document' },
      },
      {
        path: 'admin/settings',
        name: 'admin-settings',
        component: () => import('@/views/admin/SettingsView.vue'),
        meta: { title: '沙箱与环境配置', menu: true, icon: 'Setting', roles: ['admin'] },
      },
      {
        path: 'admin/audit-logs',
        name: 'admin-audit-logs',
        component: () => import('@/views/admin/AuditLogsView.vue'),
        meta: { title: '审计日志', menu: true, icon: 'Tickets', roles: ['admin'] },
      },
    ],
  },
  { path: '/:pathMatch(.*)*', redirect: '/' },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

router.beforeEach(async (to) => {
  const auth = useAuthStore()
  if (to.meta.public) {
    // 只有确认过身份才跳过登录页；令牌还在但后端连不上时停留在登录页
    return auth.user && to.name === 'login' ? { name: 'dashboard' } : true
  }
  const toLogin = { name: 'login', query: to.fullPath !== '/' ? { redirect: to.fullPath } : {} }
  let user
  try {
    user = await auth.ensureUser()
  } catch (err) {
    ElMessage.error(err instanceof ApiError ? err.message : '无法获取登录状态')
    return toLogin
  }
  if (!user) return toLogin
  if (to.meta.roles && !to.meta.roles.includes(user.role)) {
    ElMessage.warning('当前角色无权访问该页面')
    return { name: 'dashboard' }
  }
  return true
})

router.afterEach((to, _from, failure) => {
  // 导航被取消（例如配置页有未保存的修改时选择留下）时标题保持不变
  if (failure) return
  document.title = to.meta.title ? `${to.meta.title} - 自动化安全评估系统` : '自动化安全评估系统'
})

export default router
