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
        <BrandMark :size="34" />
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
          <BrandMark :size="26" />
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
  --nav-width: 232px;
  min-height: 100%;
}

.nav {
  position: fixed;
  inset: 0 auto 0 0;
  z-index: 30;
  display: flex;
  flex-direction: column;
  width: var(--nav-width);
  padding: 18px 14px 14px;
  box-sizing: border-box;
  background: var(--app-nav-bg);
  color: var(--app-nav-text);
  /* 顶部一层淡淡的主色光晕 */
  background-image: radial-gradient(120% 40% at 0% 0%, rgba(99, 120, 255, 0.18), transparent 70%);
}

.brand {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 2px 6px 18px;
  color: inherit;
  text-decoration: none;
}

.brand-text {
  display: flex;
  flex-direction: column;
  line-height: 1.25;
}

.brand-text b {
  font-size: 15.5px;
  color: #fff;
  letter-spacing: 0.04em;
}

.menu {
  flex: 1;
  overflow-y: auto;
}

.group + .group {
  margin-top: 18px;
}

.group-title {
  padding: 0 10px 6px;
  font-size: 11px;
  letter-spacing: 0.08em;
  color: var(--app-nav-text);
  opacity: 0.6;
}

.item {
  position: relative;
  display: flex;
  align-items: center;
  gap: 10px;
  height: 40px;
  padding: 0 12px;
  margin-bottom: 2px;
  border-radius: 9px;
  color: var(--app-nav-text);
  font-size: 14px;
  text-decoration: none;
  transition: background-color 0.15s, color 0.15s;
}

.item .el-icon {
  font-size: 17px;
}

.item:hover {
  background: var(--app-nav-hover);
  color: #fff;
}

.item.active {
  color: var(--app-nav-active);
  background: linear-gradient(90deg, rgba(99, 120, 255, 0.32), rgba(99, 120, 255, 0.08));
  font-weight: 600;
}

.item.active::before {
  content: '';
  position: absolute;
  left: -14px;
  top: 10px;
  bottom: 10px;
  width: 3px;
  border-radius: 0 3px 3px 0;
  background: #8b9bff;
}

.foot {
  display: flex;
  flex-direction: column;
  gap: 12px;
  padding-top: 14px;
  border-top: 1px solid var(--app-nav-border);
}

.theme {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 2px;
  padding: 3px;
  border-radius: 9px;
  background: rgba(255, 255, 255, 0.05);
}

.theme button {
  display: grid;
  place-items: center;
  height: 28px;
  border: 0;
  border-radius: 7px;
  background: transparent;
  color: var(--app-nav-text);
  font-size: 15px;
  cursor: pointer;
}

.theme button:hover {
  color: #fff;
}

.theme button.on {
  background: rgba(255, 255, 255, 0.12);
  color: #fff;
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
  width: 32px;
  height: 32px;
  flex-shrink: 0;
  border-radius: 50%;
  background: linear-gradient(135deg, #7c8dff, #3fcf95);
  color: #fff;
  font-weight: 700;
  font-size: 14px;
}

.who {
  flex: 1;
  display: flex;
  flex-direction: column;
  min-width: 0;
  line-height: 1.3;
}

.who b {
  color: #fff;
  font-size: 13.5px;
  overflow: hidden;
  text-overflow: ellipsis;
}

.who small {
  font-size: 11.5px;
}

.logout {
  display: grid;
  place-items: center;
  width: 30px;
  height: 30px;
  border: 0;
  border-radius: 8px;
  background: transparent;
  color: var(--app-nav-text);
  font-size: 16px;
  cursor: pointer;
}

.logout:hover {
  background: var(--app-nav-hover);
  color: #fff;
}

.theme button:focus-visible,
.logout:focus-visible,
.item:focus-visible,
.burger:focus-visible {
  outline: 2px solid #8b9bff;
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
    box-shadow: none;
  }

  .nav.open {
    transform: none;
    box-shadow: 0 0 40px rgba(0, 0, 0, 0.35);
  }

  .scrim {
    position: fixed;
    inset: 0;
    z-index: 29;
    background: rgba(8, 12, 24, 0.45);
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
    background: var(--app-nav-bg);
    color: #fff;
  }

  .topbar-brand {
    display: flex;
    align-items: center;
    gap: 8px;
    color: inherit;
    text-decoration: none;
    font-size: 15px;
  }

  .burger {
    display: grid;
    place-items: center;
    width: 36px;
    height: 36px;
    border: 0;
    border-radius: 8px;
    background: rgba(255, 255, 255, 0.08);
    color: #fff;
    font-size: 18px;
    cursor: pointer;
  }
}
</style>
