<script setup lang="ts">
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import { useAuthStore } from '@/stores/auth'

const auth = useAuthStore()
const route = useRoute()
const router = useRouter()

// 顶部菜单：只列出当前角色有权访问的页面
const menuItems = computed(() => {
  const layout = router.options.routes.find((r) => r.path === '/')
  return (layout?.children ?? [])
    .filter((r) => r.meta?.menu)
    .filter((r) => !r.meta?.roles || (auth.user && r.meta.roles.includes(auth.user.role)))
    .map((r) => ({ path: r.path ? `/${r.path}` : '/', title: r.meta?.title ?? '', icon: r.meta?.icon }))
})

const activePath = computed(() => {
  const matched = menuItems.value.find((item) => item.path !== '/' && route.path.startsWith(item.path))
  return matched ? matched.path : '/'
})

function logout(): void {
  auth.logout()
  void router.replace({ name: 'login' })
}
</script>

<template>
  <el-container class="layout">
    <el-header class="header">
      <div class="brand">自动化安全评估系统</div>
      <el-menu :default-active="activePath" mode="horizontal" router class="menu">
        <el-menu-item v-for="item in menuItems" :key="item.path" :index="item.path">
          <el-icon v-if="item.icon"><component :is="item.icon" /></el-icon>
          <span>{{ item.title }}</span>
        </el-menu-item>
      </el-menu>
      <div v-if="auth.user" class="user">
        <el-tag size="small" effect="plain">{{ auth.roleLabel }}</el-tag>
        <span class="user-name">{{ auth.user.username }}</span>
        <el-button link type="primary" @click="logout">
          <el-icon><SwitchButton /></el-icon>
          <span>退出</span>
        </el-button>
      </div>
    </el-header>
    <el-main class="main">
      <RouterView />
    </el-main>
  </el-container>
</template>

<style scoped>
.layout {
  min-height: 100%;
}

.header {
  display: flex;
  align-items: center;
  gap: 24px;
  background: var(--app-header-bg);
  border-bottom: 1px solid var(--app-border);
  padding: 0 24px;
}

.brand {
  font-size: 17px;
  font-weight: 600;
  white-space: nowrap;
}

.menu {
  flex: 1;
  border-bottom: none;
  min-width: 0;
}

.user {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-shrink: 0;
  white-space: nowrap;
}

.user-name {
  font-size: 14px;
}

.main {
  padding: 0;
}
</style>
