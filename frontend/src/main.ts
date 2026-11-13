import 'element-plus/dist/index.css'
import './styles.css'

import * as ElementPlusIcons from '@element-plus/icons-vue'
import ElementPlus from 'element-plus'
import zhCn from 'element-plus/es/locale/lang/zh-cn'
import { createPinia } from 'pinia'
import { createApp } from 'vue'

import { setUnauthorizedHandler } from '@/api/http'
import App from '@/App.vue'
import router from '@/router'
import { useAuthStore } from '@/stores/auth'

const app = createApp(App)
const pinia = createPinia()

app.use(pinia)
app.use(router)
app.use(ElementPlus, { locale: zhCn })
for (const [name, component] of Object.entries(ElementPlusIcons)) {
  app.component(name, component)
}

// 令牌过期或被拒绝时回到登录页，并记住原来要去的页面
setUnauthorizedHandler(() => {
  useAuthStore(pinia).logout()
  const current = router.currentRoute.value
  if (current.name !== 'login') {
    void router.replace({ name: 'login', query: { redirect: current.fullPath } })
  }
})

app.mount('#app')
