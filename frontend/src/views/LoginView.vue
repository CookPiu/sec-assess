<script setup lang="ts">
import type { FormInstance, FormRules } from 'element-plus'
import { reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import { ApiError } from '@/api/http'
import BrandMark from '@/components/BrandMark.vue'
import { useAuthStore } from '@/stores/auth'
import { STAGES } from '@/utils/labels'

const STAGE_HINTS: Record<string, string> = {
  recon: '识别技术栈、依赖与 Flask 路由，在隔离容器内准备依赖',
  code_audit: '跨文件污点分析与鉴权规则，大模型逐条研判',
  poc_verify: '在断网沙箱内启动工程副本，发送无害探针确认漏洞',
  exploit_chain: '把已验证漏洞按获得的能力串成多步攻击路径',
  report_gen: '为已验证漏洞生成补丁，输出结构化评估报告',
}

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
    <section class="intro">
      <div class="intro-brand">
        <BrandMark :size="30" />
        <span>自动化安全评估系统</span>
      </div>
      <div>
        <h1>源码审计、沙箱验证与攻击路径推演</h1>
        <ol class="stages">
          <li v-for="(s, i) in STAGES" :key="s.key">
            <span class="idx">{{ String(i + 1).padStart(2, '0') }}</span>
            <div>
              <b>{{ s.label }}</b>
              <p>{{ STAGE_HINTS[s.key] }}</p>
            </div>
          </li>
        </ol>
      </div>
    </section>

    <section class="form-side">
      <div class="form-card">
        <div class="mobile-brand">
          <BrandMark :size="30" />
          <span>自动化安全评估系统</span>
        </div>
        <h2>登录</h2>
        <p class="hint">使用分配给你的账号登录，权限按角色划分</p>
        <el-form
          ref="formRef"
          :model="form"
          :rules="rules"
          label-position="top"
          size="large"
          @submit.prevent="submit"
        >
          <el-form-item label="用户名" prop="username">
            <el-input v-model="form.username" autocomplete="username" placeholder="engineer / developer / admin">
              <template #prefix>
                <el-icon><User /></el-icon>
              </template>
            </el-input>
          </el-form-item>
          <el-form-item label="密码" prop="password">
            <el-input v-model="form.password" type="password" autocomplete="current-password" show-password>
              <template #prefix>
                <el-icon><Lock /></el-icon>
              </template>
            </el-input>
          </el-form-item>
          <el-alert v-if="errorMessage" :title="errorMessage" type="error" :closable="false" show-icon class="error" />
          <el-button type="primary" native-type="submit" :loading="loading" class="submit">登录</el-button>
        </el-form>
      </div>
    </section>
  </div>
</template>

<style scoped>
.login-page {
  display: grid;
  grid-template-columns: minmax(0, 1.1fr) minmax(0, 1fr);
  min-height: 100%;
}

/* 左侧固定为深色，图标与文字按深色底取色 */
.intro {
  --app-ink: #f2f2ef;
  --app-ink-contrast: #111111;
  display: flex;
  flex-direction: column;
  justify-content: space-between;
  gap: 48px;
  padding: 48px clamp(32px, 6vw, 88px);
  color: #a3a39e;
  background: #111111;
}

.intro-brand {
  display: flex;
  align-items: center;
  gap: 12px;
  font-size: 15px;
  font-weight: 600;
  color: #f2f2ef;
  letter-spacing: 0.01em;
}

.intro h1 {
  margin: 0 0 40px;
  max-width: 540px;
  font-family: var(--app-font-display);
  font-size: clamp(30px, 3vw, 44px);
  line-height: 1.25;
  font-weight: 600;
  letter-spacing: -0.02em;
  color: #f2f2ef;
}

.stages {
  list-style: none;
  margin: 0;
  padding: 0;
  max-width: 540px;
  border-top: 1px solid #2a2a2a;
}

.stages li {
  display: grid;
  grid-template-columns: 40px minmax(0, 1fr);
  gap: 12px;
  padding: 14px 0;
  border-bottom: 1px solid #2a2a2a;
}

.idx {
  font-family: var(--app-font-mono);
  font-size: 12.5px;
  line-height: 22px;
  color: #6f6f6a;
}

.stages b {
  display: block;
  font-size: 14.5px;
  font-weight: 600;
  line-height: 22px;
  color: #f2f2ef;
}

.stages p {
  margin: 2px 0 0;
  font-size: 13px;
  line-height: 1.6;
  color: #8f8f8a;
}

.form-side {
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 32px 24px;
  background: var(--app-bg);
}

.form-card {
  width: 100%;
  max-width: 360px;
}

.mobile-brand {
  display: none;
}

.form-card h2 {
  margin: 0;
  font-family: var(--app-font-display);
  font-size: 30px;
  font-weight: 600;
  letter-spacing: -0.02em;
}

.hint {
  margin: 8px 0 32px;
  font-size: 13.5px;
  color: var(--app-text-muted);
}

.form-card :deep(.el-form-item__label) {
  font-weight: 500;
  color: var(--app-text);
}

.error {
  margin-bottom: 16px;
}

.submit {
  width: 100%;
  height: 44px;
  margin-top: 8px;
  font-size: 15px;
}

@media (max-width: 899px) {
  .login-page {
    grid-template-columns: minmax(0, 1fr);
  }

  .intro {
    display: none;
  }

  .mobile-brand {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 32px;
    font-weight: 600;
  }
}
</style>
