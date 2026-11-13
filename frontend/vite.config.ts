import { fileURLToPath, URL } from 'node:url'

import vue from '@vitejs/plugin-vue'
import { defineConfig, loadEnv } from 'vite'

// 开发服务器只监听本机；/api 转发到后端（默认 127.0.0.1:8010，可用 VITE_API_TARGET 覆盖）
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), 'VITE_')
  return {
    plugins: [vue()],
    resolve: {
      alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) },
    },
    server: {
      host: '127.0.0.1',
      port: 5173,
      strictPort: true,
      proxy: {
        '/api': { target: env.VITE_API_TARGET || 'http://127.0.0.1:8010', changeOrigin: true },
      },
    },
    preview: { host: '127.0.0.1', port: 4173 },
  }
})
