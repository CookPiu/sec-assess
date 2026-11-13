import { ElMessage } from 'element-plus'
import { createRouter, createWebHistory, type RouteRecordRaw } from 'vue-router'

import type { Role } from '@/api/auth'
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
    return auth.isLoggedIn && to.name === 'login' ? { name: 'dashboard' } : true
  }
  const user = await auth.ensureUser()
  if (!user) {
    return { name: 'login', query: to.fullPath !== '/' ? { redirect: to.fullPath } : {} }
  }
  if (to.meta.roles && !to.meta.roles.includes(user.role)) {
    ElMessage.warning('当前角色无权访问该页面')
    return { name: 'dashboard' }
  }
  return true
})

router.afterEach((to) => {
  document.title = to.meta.title ? `${to.meta.title} - 自动化安全评估系统` : '自动化安全评估系统'
})

export default router
