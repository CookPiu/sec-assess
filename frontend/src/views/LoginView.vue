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
        <BrandMark :size="40" />
        <span>自动化安全评估系统</span>
      </div>
      <h1>源码审计、沙箱验证与攻击路径推演</h1>
      <ol class="stages">
        <li v-for="(s, i) in STAGES" :key="s.key">
          <span class="idx">{{ i + 1 }}</span>
          <div>
            <b>{{ s.label }}</b>
            <p>{{ STAGE_HINTS[s.key] }}</p>
          </div>
        </li>
      </ol>
    </section>

    <section class="form-side">
      <div class="form-card">
        <div class="mobile-brand">
          <BrandMark :size="36" />
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

.intro {
  position: relative;
  display: flex;
  flex-direction: column;
  justify-content: center;
  gap: 28px;
  padding: 56px clamp(32px, 6vw, 88px);
  overflow: hidden;
  color: #c9d1e4;
  background-color: #0d1426;
  /* 网格底纹加左上角的主色光晕 */
  background-image:
    radial-gradient(70% 60% at 0% 0%, rgba(99, 120, 255, 0.35), transparent 70%),
    radial-gradient(50% 50% at 100% 100%, rgba(63, 207, 149, 0.16), transparent 70%),
    linear-gradient(rgba(255, 255, 255, 0.04) 1px, transparent 1px),
    linear-gradient(90deg, rgba(255, 255, 255, 0.04) 1px, transparent 1px);
  background-size:
    auto,
    auto,
    32px 32px,
    32px 32px;
}

.intro-brand {
  display: flex;
  align-items: center;
  gap: 12px;
  font-size: 16px;
  font-weight: 600;
  color: #fff;
  letter-spacing: 0.04em;
}

.intro h1 {
  margin: 0;
  max-width: 520px;
  font-size: clamp(26px, 2.6vw, 36px);
  line-height: 1.35;
  font-weight: 700;
  color: #fff;
}

.stages {
  list-style: none;
  margin: 0;
  padding: 0;
  max-width: 520px;
}

.stages li {
  position: relative;
  display: flex;
  gap: 14px;
  padding-bottom: 18px;
}

.stages li:not(:last-child)::after {
  content: '';
  position: absolute;
  left: 13px;
  top: 30px;
  bottom: 2px;
  width: 2px;
  background: linear-gradient(rgba(139, 155, 255, 0.5), rgba(139, 155, 255, 0.1));
}

.idx {
  flex-shrink: 0;
  display: grid;
  place-items: center;
  width: 28px;
  height: 28px;
  border-radius: 50%;
  font-size: 13px;
  font-weight: 700;
  color: #fff;
  background: rgba(99, 120, 255, 0.25);
  box-shadow: inset 0 0 0 1.5px rgba(139, 155, 255, 0.7);
}

.stages b {
  display: block;
  font-size: 15px;
  color: #fff;
  line-height: 28px;
}

.stages p {
  margin: 0;
  font-size: 13px;
  line-height: 1.6;
  color: #9aa5bf;
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
  max-width: 380px;
}

.mobile-brand {
  display: none;
}

.form-card h2 {
  margin: 0;
  font-size: 26px;
  font-weight: 700;
}

.hint {
  margin: 6px 0 28px;
  font-size: 13.5px;
  color: var(--app-text-muted);
}

.error {
  margin-bottom: 16px;
}

.submit {
  width: 100%;
  height: 44px;
  margin-top: 6px;
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
    margin-bottom: 28px;
    font-weight: 600;
  }
}
</style>
