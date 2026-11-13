<script setup lang="ts">
import type { FormInstance, FormRules } from 'element-plus'
import { reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import { ApiError } from '@/api/http'
import { useAuthStore } from '@/stores/auth'

const auth = useAuthStore()
const route = useRoute()
const router = useRouter()

const formRef = ref<FormInstance>()
const form = reactive({ username: '', password: '' })
const loading = ref(false)
const errorMessage = ref('')

const rules: FormRules = {
  username: [{ required: true, message: '请输入用户名', trigger: 'blur' }],
  password: [{ required: true, message: '请输入密码', trigger: 'blur' }],
}

async function submit(): Promise<void> {
  errorMessage.value = ''
  const valid = await formRef.value?.validate().catch(() => false)
  if (!valid) return
  loading.value = true
  try {
    await auth.login(form.username.trim(), form.password)
    const redirect = typeof route.query.redirect === 'string' ? route.query.redirect : '/'
    await router.replace(redirect.startsWith('/') && !redirect.startsWith('//') ? redirect : '/')
  } catch (err) {
    errorMessage.value = err instanceof ApiError ? err.message : '登录失败，请稍后重试'
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <div class="login-page">
    <el-card class="login-card" shadow="never">
      <h1 class="title">自动化安全评估系统</h1>
      <p class="subtitle">源码审计、沙箱验证与攻击路径推演</p>
      <el-form ref="formRef" :model="form" :rules="rules" label-position="top" @submit.prevent="submit">
        <el-form-item label="用户名" prop="username">
          <el-input v-model="form.username" autocomplete="username" placeholder="engineer / developer / admin" />
        </el-form-item>
        <el-form-item label="密码" prop="password">
          <el-input v-model="form.password" type="password" autocomplete="current-password" show-password />
        </el-form-item>
        <el-alert v-if="errorMessage" :title="errorMessage" type="error" :closable="false" show-icon class="error" />
        <el-button type="primary" native-type="submit" :loading="loading" class="submit">登录</el-button>
      </el-form>
    </el-card>
  </div>
</template>

<style scoped>
.login-page {
  min-height: 100%;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 16px;
  box-sizing: border-box;
}

.login-card {
  width: 100%;
  max-width: 380px;
}

.title {
  margin: 0;
  font-size: 22px;
  font-weight: 600;
  text-align: center;
}

.subtitle {
  margin: 8px 0 24px;
  color: var(--app-text-muted);
  font-size: 13px;
  text-align: center;
}

.error {
  margin-bottom: 16px;
}

.submit {
  width: 100%;
}
</style>
