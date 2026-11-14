<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import BrandMark from '@/components/BrandMark.vue'
import { useAuthStore } from '@/stores/auth'
import { setThemeMode, themeMode, type ThemeMode } from '@/utils/theme'

const auth = useAuthStore()
const route = useRoute()
const router = useRouter()
const drawerOpen = ref(false)

const THEMES: { key: ThemeMode; label: string; icon: string }[] = [
  { key: 'system', label: '跟随系统', icon: 'Monitor' },
  { key: 'light', label: '浅色', icon: 'Sunny' },
  { key: 'dark', label: '深色', icon: 'Moon' },
]

// 侧栏菜单：只列出当前角色有权访问的页面，管理页单独成组
const menuItems = computed(() => {
  const layout = router.options.routes.find((r) => r.path === '/')
  return (layout?.children ?? [])
    .filter((r) => r.meta?.menu)
    .filter((r) => !r.meta?.roles || (auth.user && r.meta.roles.includes(auth.user.role)))
    .map((r) => ({
      path: r.path ? `/${r.path}` : '/',
      title: r.meta?.title ?? '',
      icon: r.meta?.icon,
      admin: r.path.startsWith('admin/'),
    }))
})

const groups = computed(() => [
  { title: '评估', items: menuItems.value.filter((i) => !i.admin) },
  { title: '系统管理', items: menuItems.value.filter((i) => i.admin) },
].filter((g) => g.items.length))

// 工作台不在菜单里，归到“项目概览”
const activePath = computed(() => {
  const matched = menuItems.value.find((item) => item.path !== '/' && route.path.startsWith(item.path))
  return matched ? matched.path : '/'
})

const initial = computed(() => (auth.user?.username ?? '?').slice(0, 1).toUpperCase())

watch(() => route.fullPath, () => (drawerOpen.value = false))

function logout(): void {
  auth.logout()
  void router.replace({ name: 'login' })
}
</script>

<template>
  <div class="shell">
    <aside :class="['nav', { open: drawerOpen }]">
      <RouterLink to="/" class="brand">
        <BrandMark :size="28" />
        <span class="brand-text">
          <b>自动化安全评估</b>
        </span>
      </RouterLink>

      <nav class="menu">
        <div v-for="g in groups" :key="g.title" class="group">
          <div class="group-title">{{ g.title }}</div>
          <RouterLink
            v-for="item in g.items"
            :key="item.path"
            :to="item.path"
            :class="['item', { active: activePath === item.path }]"
          >
            <el-icon v-if="item.icon"><component :is="item.icon" /></el-icon>
            <span>{{ item.title }}</span>
          </RouterLink>
        </div>
      </nav>

      <div class="foot">
        <div class="theme" role="radiogroup" aria-label="界面主题">
          <button
            v-for="t in THEMES"
            :key="t.key"
            type="button"
            role="radio"
            :aria-checked="themeMode === t.key"
            :title="t.label"
            :class="{ on: themeMode === t.key }"
            @click="setThemeMode(t.key)"
          >
            <el-icon><component :is="t.icon" /></el-icon>
          </button>
        </div>
        <div v-if="auth.user" class="user">
          <span class="avatar">{{ initial }}</span>
          <span class="who">
            <b>{{ auth.user.username }}</b>
            <small>{{ auth.roleLabel }}</small>
          </span>
          <el-tooltip content="退出登录" placement="top">
            <button type="button" class="logout" aria-label="退出登录" @click="logout">
              <el-icon><SwitchButton /></el-icon>
            </button>
          </el-tooltip>
        </div>
      </div>
    </aside>

    <div v-if="drawerOpen" class="scrim" @click="drawerOpen = false" />

    <div class="content">
      <header class="topbar">
        <button type="button" class="burger" aria-label="打开菜单" @click="drawerOpen = true">
          <el-icon><Menu /></el-icon>
        </button>
        <RouterLink to="/" class="topbar-brand">
          <BrandMark :size="24" />
          <b>自动化安全评估</b>
        </RouterLink>
      </header>
      <main class="main">
        <RouterView />
      </main>
    </div>
  </div>
</template>

<style scoped>
.shell {
  --nav-width: 236px;
  min-height: 100%;
}

.nav {
  position: fixed;
  inset: 0 auto 0 0;
  z-index: 30;
  display: flex;
  flex-direction: column;
  width: var(--nav-width);
  padding: 20px 14px 14px;
  box-sizing: border-box;
  background: var(--app-bg);
  border-right: 1px solid var(--app-border);
  color: var(--app-text-secondary);
}

.brand {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 0 8px 26px;
  color: var(--app-text);
  text-decoration: none;
}

.brand-text b {
  font-size: 14.5px;
  font-weight: 600;
  letter-spacing: 0.01em;
}

.menu {
  flex: 1;
  overflow-y: auto;
}

.group + .group {
  margin-top: 22px;
}

.group-title {
  padding: 0 10px 8px;
  font-size: 11.5px;
  font-weight: 500;
  letter-spacing: 0.04em;
  color: var(--app-text-muted);
}

.item {
  position: relative;
  display: flex;
  align-items: center;
  gap: 10px;
  height: 36px;
  padding: 0 10px;
  margin-bottom: 2px;
  border-radius: 6px;
  color: var(--app-text-secondary);
  font-size: 14px;
  text-decoration: none;
  transition: background-color 0.15s, color 0.15s;
}

.item .el-icon {
  font-size: 16px;
  color: var(--app-text-muted);
  transition: color 0.15s;
}

.item:hover {
  background: var(--app-ink-soft);
  color: var(--app-text);
}

.item.active {
  color: var(--app-text);
  background: var(--app-surface);
  box-shadow: inset 0 0 0 1px var(--app-border);
  font-weight: 600;
}

.item.active .el-icon {
  color: var(--app-text);
}

.foot {
  display: flex;
  flex-direction: column;
  gap: 14px;
  padding-top: 14px;
  border-top: 1px solid var(--app-border);
}

.theme {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 2px;
  padding: 2px;
  border-radius: 7px;
  box-shadow: inset 0 0 0 1px var(--app-border);
}

.theme button {
  display: grid;
  place-items: center;
  height: 26px;
  border: 0;
  border-radius: 5px;
  background: transparent;
  color: var(--app-text-muted);
  font-size: 14px;
  cursor: pointer;
}

.theme button:hover {
  color: var(--app-text);
}

.theme button.on {
  background: var(--app-ink);
  color: var(--app-ink-contrast);
}

.user {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 0 4px;
}

.avatar {
  display: grid;
  place-items: center;
  width: 30px;
  height: 30px;
  flex-shrink: 0;
  border-radius: 50%;
  background: var(--app-surface-sunken);
  color: var(--app-text);
  font-weight: 600;
  font-size: 13px;
}

.who {
  flex: 1;
  display: flex;
  flex-direction: column;
  min-width: 0;
  line-height: 1.3;
}

.who b {
  color: var(--app-text);
  font-size: 13.5px;
  font-weight: 600;
  overflow: hidden;
  text-overflow: ellipsis;
}

.who small {
  font-size: 12px;
  color: var(--app-text-muted);
}

.logout {
  display: grid;
  place-items: center;
  width: 30px;
  height: 30px;
  border: 0;
  border-radius: 6px;
  background: transparent;
  color: var(--app-text-muted);
  font-size: 15px;
  cursor: pointer;
}

.logout:hover {
  background: var(--app-ink-soft);
  color: var(--app-danger);
}

.theme button:focus-visible,
.logout:focus-visible,
.item:focus-visible,
.burger:focus-visible {
  outline: 2px solid var(--app-ink);
  outline-offset: 1px;
}

.content {
  margin-left: var(--nav-width);
  min-height: 100%;
}

.topbar {
  display: none;
}

.main {
  min-width: 0;
}

/* 窄屏：侧栏收进抽屉，顶部显示菜单按钮 */
@media (max-width: 1023px) {
  .nav {
    transform: translateX(-100%);
    transition: transform 0.22s ease;
    background: var(--app-surface);
  }

  .nav.open {
    transform: none;
    box-shadow: var(--app-shadow-pop);
  }

  .scrim {
    position: fixed;
    inset: 0;
    z-index: 29;
    background: rgba(10, 10, 10, 0.35);
  }

  .content {
    margin-left: 0;
  }

  .topbar {
    position: sticky;
    top: 0;
    z-index: 20;
    display: flex;
    align-items: center;
    gap: 10px;
    height: 52px;
    padding: 0 12px;
    background: color-mix(in srgb, var(--app-bg) 88%, transparent);
    backdrop-filter: blur(10px);
    border-bottom: 1px solid var(--app-border);
    color: var(--app-text);
  }

  .topbar-brand {
    display: flex;
    align-items: center;
    gap: 8px;
    color: inherit;
    text-decoration: none;
    font-size: 14.5px;
  }

  .topbar-brand b {
    font-weight: 600;
  }

  .burger {
    display: grid;
    place-items: center;
    width: 36px;
    height: 36px;
    border: 0;
    border-radius: 6px;
    background: transparent;
    box-shadow: inset 0 0 0 1px var(--app-border);
    color: var(--app-text);
    font-size: 18px;
    cursor: pointer;
  }
}
</style>
