<script setup lang="ts">
import { ElMessage, ElMessageBox, type FormInstance, type FormRules } from 'element-plus'
import { computed, onMounted, ref, useTemplateRef } from 'vue'
import { onBeforeRouteLeave } from 'vue-router'

import { ApiError } from '@/api/http'
import { getSettings, updateSettings, type EditableKey, type RuntimeConfig, type SettingsOut } from '@/api/settings'
import { formatTime } from '@/utils/format'
import { SETTING_META, formatSettingValue } from '@/utils/labels'

type NumberKey = { [K in EditableKey]: RuntimeConfig[K] extends number ? K : never }[EditableKey]

interface NumberField {
  key: NumberKey
  min: number
  max: number
  step: number
  precision?: number
  help?: string
}

const EDITABLE_KEYS = (Object.keys(SETTING_META) as (keyof RuntimeConfig)[]).filter(
  (key): key is EditableKey => key !== 'network_policy',
)

const SANDBOX_FIELDS: NumberField[] = [
  { key: 'cpus', min: 0.5, max: 8, step: 0.5, precision: 1 },
  { key: 'memory_mb', min: 256, max: 8192, step: 256, help: '内存与交换分区合计不超过该值。' },
  { key: 'pids', min: 64, max: 4096, step: 64, help: '容器内进程与线程的总数上限。' },
]
const SCHEDULE_FIELDS: NumberField[] = [
  { key: 'task_timeout_min', min: 1, max: 240, step: 1, help: '评估总时长超过上限时销毁容器，任务标记为失败。' },
  { key: 'probe_timeout_s', min: 3, max: 60, step: 1, help: '动态验证中每次 PoC 请求的等待上限。' },
  { key: 'max_concurrent', min: 1, max: 4, step: 1, help: '超出的评估排队等待；调大后排队中的评估立即开始。' },
]
const LLM_FIELDS: NumberField[] = [
  { key: 'llm_timeout_seconds', min: 5, max: 300, step: 5, help: '单次请求的等待上限，生成补丁时至少等 60 秒。' },
  { key: 'llm_concurrency', min: 1, max: 16, step: 1, help: '同一评估内同时发出的请求数。' },
]

const data = ref<SettingsOut | null>(null)
// 表单对象始终存在，页面在 data 到达后才渲染，避免模板后半段丢失空值收窄
const form = ref<RuntimeConfig>({
  sandbox_image: '',
  cpus: 1,
  memory_mb: 1024,
  pids: 256,
  task_timeout_min: 30,
  probe_timeout_s: 10,
  max_concurrent: 1,
  network_policy: 'none',
  pypi_index_url: 'https://pypi.org/simple',
  llm_enabled: true,
  llm_model: '',
  llm_base_url: 'https://api.deepseek.com',
  llm_timeout_seconds: 20,
  llm_concurrency: 4,
})
const dockerAvailable = ref(false)
const llmKeyConfigured = ref(false)
const loading = ref(false)
const loadError = ref('')
const saving = ref(false)
const formRef = useTemplateRef<FormInstance>('formRef')

const urlRule = { pattern: /^https?:\/\/\S+$/, message: '必须是 http:// 或 https:// 开头的地址', trigger: 'blur' }
const rules: FormRules = {
  sandbox_image: [{ required: true, message: '请选择沙箱镜像', trigger: 'change' }],
  pypi_index_url: [{ required: true, message: '请填写 PyPI 地址', trigger: 'blur' }, urlRule],
  llm_base_url: [{ required: true, message: '请填写接口地址', trigger: 'blur' }, urlRule],
  ...Object.fromEntries(
    [...SANDBOX_FIELDS, ...SCHEDULE_FIELDS, ...LLM_FIELDS].map((f) => [
      f.key,
      [{ required: true, message: `请填写${SETTING_META[f.key].label}`, trigger: 'blur' }],
    ]),
  ),
}

function normalized(value: unknown): unknown {
  return typeof value === 'string' ? value.trim() : value
}

const dirtyKeys = computed<EditableKey[]>(() => {
  const saved = data.value?.values
  if (!saved) return []
  return EDITABLE_KEYS.filter((key) => normalized(form.value[key]) !== saved[key])
})

const atDefaults = computed(() => {
  const defaults = data.value?.defaults
  return !defaults || EDITABLE_KEYS.every((key) => normalized(form.value[key]) === defaults[key])
})

interface ImageOption {
  tag: string
  size_mb: number | null
  created: string | null
}

const imageOptions = computed((): ImageOption[] => {
  const images = data.value?.images ?? []
  const current = data.value?.values.sandbox_image
  // 已保存的镜像不在本机列表里时也列出来，避免下拉框显示空白
  if (!current || images.some((image) => image.tag === current)) return images
  return [{ tag: current, size_mb: null, created: null }, ...images]
})

function isDirty(key: EditableKey): boolean {
  return dirtyKeys.value.includes(key)
}

function defaultHint(key: EditableKey): string {
  const value = data.value?.defaults[key]
  return value === undefined || value === '' ? '' : `默认 ${formatSettingValue(key, value)}。`
}

function apply(out: SettingsOut): void {
  data.value = out
  form.value = { ...out.values }
  dockerAvailable.value = out.docker_available
  llmKeyConfigured.value = out.llm_key_configured
}

async function load(): Promise<void> {
  loading.value = true
  loadError.value = ''
  try {
    apply(await getSettings())
  } catch (err) {
    loadError.value = err instanceof ApiError ? err.message : '配置加载失败'
  } finally {
    loading.value = false
  }
}

onMounted(load)

async function save(): Promise<void> {
  if (!data.value || !dirtyKeys.value.length) return
  const valid = await formRef.value?.validate().catch(() => false)
  if (!valid) return
  const changes = Object.fromEntries(dirtyKeys.value.map((key) => [key, normalized(form.value[key])]))
  saving.value = true
  try {
    apply(await updateSettings(changes))
    ElMessage.success(`已保存 ${Object.keys(changes).length} 项修改`)
  } catch (err) {
    ElMessage.error(err instanceof ApiError ? err.message : '保存失败')
  } finally {
    saving.value = false
  }
}

function discard(): void {
  if (data.value) form.value = { ...data.value.values }
  formRef.value?.clearValidate()
}

function fillDefaults(): void {
  if (data.value) form.value = { ...data.value.defaults }
  formRef.value?.clearValidate()
}

onBeforeRouteLeave(async () => {
  if (!dirtyKeys.value.length) return true
  try {
    await ElMessageBox.confirm(`有 ${dirtyKeys.value.length} 项修改还没保存，离开后会丢失。`, '离开配置页', {
      confirmButtonText: '离开',
      cancelButtonText: '留在本页',
      type: 'warning',
    })
    return true
  } catch {
    return false
  }
})
</script>

<template>
  <div class="page">
    <div class="head">
      <div>
        <h2 class="page-title">沙箱与环境配置</h2>
        <div v-if="data" class="meta">
          <template v-if="data.updated_at">
            上次修改 {{ formatTime(data.updated_at) }} · {{ data.updated_by ?? '—' }}
          </template>
          <template v-else>全部为默认值</template>
          <router-link :to="{ name: 'admin-audit-logs', query: { action: 'setting_update' } }">修改记录</router-link>
        </div>
      </div>
      <div v-if="data" class="actions">
        <span v-if="dirtyKeys.length" class="dirty-count">{{ dirtyKeys.length }} 项未保存</span>
        <el-button :disabled="atDefaults || saving" @click="fillDefaults">恢复默认值</el-button>
        <el-button :disabled="!dirtyKeys.length || saving" @click="discard">放弃修改</el-button>
        <el-button type="primary" :loading="saving" :disabled="!dirtyKeys.length" @click="save">保存</el-button>
      </div>
    </div>

    <div v-loading="loading" class="body">
      <el-alert v-if="loadError" type="error" :title="loadError" show-icon :closable="false">
        <el-button size="small" @click="load">重试</el-button>
      </el-alert>

      <template v-else-if="data">
        <el-alert
          type="info"
          title="保存后对之后开始的评估生效，运行中的评估沿用开始时的配置。"
          show-icon
          :closable="false"
          class="notice"
        />

        <el-form ref="formRef" :model="form" :rules="rules" label-position="top" @submit.prevent="save">
          <el-card shadow="never" class="section">
            <template #header>沙箱</template>
            <el-alert
              v-if="!dockerAvailable"
              type="warning"
              title="Docker 未启动，读不到本机镜像，暂时不能更换沙箱镜像。"
              show-icon
              :closable="false"
              class="notice"
            />
            <el-row :gutter="24">
              <el-col :xs="24" :lg="16">
                <el-form-item label="沙箱镜像" prop="sandbox_image" :class="{ dirty: isDirty('sandbox_image') }">
                  <el-select v-model="form.sandbox_image" :disabled="!dockerAvailable" filterable>
                    <el-option v-for="image in imageOptions" :key="image.tag" :value="image.tag" :label="image.tag">
                      <span class="option">
                        <span>{{ image.tag }}</span>
                        <span class="option-sub">
                          {{ image.size_mb === null ? '本机未找到' : `${image.size_mb} MB` }}
                        </span>
                      </span>
                    </el-option>
                  </el-select>
                  <div class="hint">
                    列出本机以 sec-assess/ 开头的镜像，新镜像用 sandbox-images/build.ps1 构建。{{ defaultHint('sandbox_image') }}
                  </div>
                </el-form-item>
              </el-col>
              <el-col :xs="24" :lg="8">
                <el-form-item label="网络隔离策略">
                  <div class="readonly">
                    <el-icon><Lock /></el-icon>
                    <span>无网络</span>
                  </div>
                  <div class="hint">评估容器不接入任何网络，固定不可修改。</div>
                </el-form-item>
              </el-col>
              <el-col v-for="f in SANDBOX_FIELDS" :key="f.key" :xs="24" :sm="12" :lg="8">
                <el-form-item :label="SETTING_META[f.key].label" :prop="f.key" :class="{ dirty: isDirty(f.key) }">
                  <div class="number">
                    <el-input-number
                      v-model="form[f.key]"
                      :min="f.min"
                      :max="f.max"
                      :step="f.step"
                      :precision="f.precision"
                      controls-position="right"
                    />
                    <span class="unit">{{ SETTING_META[f.key].unit }}</span>
                  </div>
                  <div class="hint">{{ f.help }}{{ defaultHint(f.key) }}</div>
                </el-form-item>
              </el-col>
            </el-row>
          </el-card>

          <el-card shadow="never" class="section">
            <template #header>任务调度</template>
            <el-row :gutter="24">
              <el-col v-for="f in SCHEDULE_FIELDS" :key="f.key" :xs="24" :sm="12" :lg="8">
                <el-form-item :label="SETTING_META[f.key].label" :prop="f.key" :class="{ dirty: isDirty(f.key) }">
                  <div class="number">
                    <el-input-number v-model="form[f.key]" :min="f.min" :max="f.max" :step="f.step" controls-position="right" />
                    <span class="unit">{{ SETTING_META[f.key].unit }}</span>
                  </div>
                  <div class="hint">{{ f.help }}{{ defaultHint(f.key) }}</div>
                </el-form-item>
              </el-col>
            </el-row>
          </el-card>

          <el-card shadow="never" class="section">
            <template #header>依赖准备</template>
            <el-row :gutter="24">
              <el-col :xs="24" :lg="16">
                <el-form-item label="PyPI 地址" prop="pypi_index_url" :class="{ dirty: isDirty('pypi_index_url') }">
                  <el-input v-model="form.pypi_index_url" placeholder="https://pypi.org/simple" />
                  <div class="hint">宿主机下载依赖 wheel 时使用的索引地址，可改为镜像源。{{ defaultHint('pypi_index_url') }}</div>
                </el-form-item>
              </el-col>
            </el-row>
          </el-card>

          <el-card shadow="never" class="section">
            <template #header>大模型</template>
            <el-row :gutter="24">
              <el-col :xs="24" :sm="12" :lg="8">
                <el-form-item label="启用大模型" :class="{ dirty: isDirty('llm_enabled') }">
                  <el-switch v-model="form.llm_enabled" />
                  <div class="hint">
                    关闭后源码审计按漏洞类别的默认向量计分，路径说明、评估结论和整改行动按规则生成，不生成修复补丁。
                  </div>
                </el-form-item>
              </el-col>
              <el-col :xs="24" :sm="12" :lg="8">
                <el-form-item label="密钥">
                  <el-tag :type="llmKeyConfigured ? 'success' : 'warning'">
                    {{ llmKeyConfigured ? '已配置' : '未配置' }}
                  </el-tag>
                  <div class="hint">在仓库根目录 .env 的 LLM_API_KEY 中配置。</div>
                </el-form-item>
              </el-col>
              <el-col :xs="24" :lg="8" class="spacer" />
              <el-col :xs="24" :sm="12" :lg="8">
                <el-form-item label="模型名称" prop="llm_model" :class="{ dirty: isDirty('llm_model') }">
                  <el-input v-model="form.llm_model" maxlength="64" />
                  <div class="hint">{{ defaultHint('llm_model') }}</div>
                </el-form-item>
              </el-col>
              <el-col :xs="24" :sm="12" :lg="16">
                <el-form-item label="接口地址" prop="llm_base_url" :class="{ dirty: isDirty('llm_base_url') }">
                  <el-input v-model="form.llm_base_url" />
                  <div class="hint">OpenAI 兼容接口的地址。{{ defaultHint('llm_base_url') }}</div>
                </el-form-item>
              </el-col>
              <el-col v-for="f in LLM_FIELDS" :key="f.key" :xs="24" :sm="12" :lg="8">
                <el-form-item :label="SETTING_META[f.key].label" :prop="f.key" :class="{ dirty: isDirty(f.key) }">
                  <div class="number">
                    <el-input-number v-model="form[f.key]" :min="f.min" :max="f.max" :step="f.step" controls-position="right" />
                    <span class="unit">{{ SETTING_META[f.key].unit }}</span>
                  </div>
                  <div class="hint">{{ f.help }}{{ defaultHint(f.key) }}</div>
                </el-form-item>
              </el-col>
            </el-row>
          </el-card>
        </el-form>
      </template>
    </div>
  </div>
</template>

<style scoped>
.head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 8px 16px;
  margin-bottom: 16px;
}

.head .page-title {
  margin-bottom: 4px;
}

.meta {
  display: flex;
  flex-wrap: wrap;
  gap: 4px 12px;
  font-size: 13px;
  color: var(--app-text-muted);
}

.meta a {
  color: var(--el-color-primary);
  text-decoration: none;
}

.actions {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 8px;
}

.actions .el-button + .el-button {
  margin-left: 0;
}

.dirty-count {
  font-size: 13px;
  color: var(--el-color-warning);
}

.body {
  min-height: 200px;
}

.notice {
  margin-bottom: 16px;
}

.section {
  margin-bottom: 16px;
}

.section :deep(.el-form-item__content) {
  flex-direction: column;
  align-items: flex-start;
}

.section :deep(.el-select),
.section :deep(.el-input) {
  width: 100%;
}

.dirty :deep(.el-form-item__label) {
  color: var(--el-color-warning);
}

.dirty :deep(.el-form-item__label)::after {
  content: '（未保存）';
  font-size: 12px;
}

.number {
  display: flex;
  align-items: center;
  gap: 8px;
}

.unit {
  color: var(--app-text-muted);
  font-size: 13px;
}

.readonly {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  height: 32px;
}

.hint {
  margin-top: 4px;
  font-size: 12px;
  line-height: 1.6;
  color: var(--app-text-muted);
}

.option {
  display: flex;
  justify-content: space-between;
  gap: 16px;
}

.option-sub {
  color: var(--app-text-muted);
  font-size: 12px;
}

@media (max-width: 1199px) {
  .spacer {
    display: none;
  }
}
</style>
