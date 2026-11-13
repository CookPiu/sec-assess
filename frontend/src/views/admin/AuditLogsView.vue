<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import { listAuditLogs, type AuditAction, type AuditLogEntry } from '@/api/audit'
import { ApiError } from '@/api/http'
import type { SettingKey } from '@/api/settings'
import { formatTime } from '@/utils/format'
import { AUDIT_ACTIONS, AUDIT_ACTION_META, SETTING_META, formatSettingValue } from '@/utils/labels'

const PAGE_SIZE = 20
const SOURCE_LABELS: Record<string, string> = { git: 'Git 仓库', zip: '压缩包' }
const FORMAT_LABELS: Record<string, string> = { md: 'Markdown', html: 'HTML', pdf: 'PDF' }

interface LogRow {
  id: number
  time: string
  username: string
  actionLabel: string
  actionTag: 'primary' | 'success' | 'info' | 'warning' | 'danger'
  /** 任务编号；有值时对象列链到工作台 */
  taskId: string | null
  targetText: string
  lines: string[]
}

const route = useRoute()
const router = useRouter()

const items = ref<AuditLogEntry[]>([])
const total = ref(0)
const loading = ref(false)
const error = ref('')
const page = ref(1)
const usernameInput = ref('')
let seq = 0

function queryText(value: unknown): string {
  if (typeof value === 'string') return value
  if (Array.isArray(value) && typeof value[0] === 'string') return value[0]
  return ''
}

function actionFromQuery(value: unknown): AuditAction | '' {
  const text = queryText(value)
  return AUDIT_ACTIONS.some((item) => item.key === text) ? (text as AuditAction) : ''
}

const action = computed(() => actionFromQuery(route.query.action))
const username = computed(() => queryText(route.query.username))

watch(username, (value) => {
  usernameInput.value = value
}, { immediate: true })

function replaceQuery(nextAction: AuditAction | '', nextUsername: string): void {
  const query: Record<string, string> = {}
  if (nextAction) query.action = nextAction
  if (nextUsername) query.username = nextUsername
  if (nextAction === action.value && nextUsername === username.value) return
  page.value = 1
  void router.replace({ query })
}

function onAction(value: AuditAction | undefined): void {
  replaceQuery(value ?? '', username.value)
}

function applyUsername(): void {
  const value = usernameInput.value.trim()
  usernameInput.value = value
  replaceQuery(action.value, value)
}

function textOf(value: unknown): string {
  return typeof value === 'string' ? value : ''
}

function settingLabel(key: string): string {
  return key in SETTING_META ? SETTING_META[key as SettingKey].label : key
}

function settingLines(changes: unknown): string[] {
  if (!changes || typeof changes !== 'object' || Array.isArray(changes)) return []
  return Object.entries(changes).flatMap(([key, value]) => {
    if (!Array.isArray(value) || value.length < 2) return []
    return [`${settingLabel(key)}：${formatSettingValue(key, value[0])} → ${formatSettingValue(key, value[1])}`]
  })
}

function detailLines(entry: AuditLogEntry): string[] {
  const detail = entry.detail ?? {}
  switch (entry.action) {
    case 'task_create': {
      const name = textOf(detail.project_name)
      const source = SOURCE_LABELS[textOf(detail.source_type)] ?? ''
      if (!name && !source) return []
      return [name ? `项目 ${name}${source ? `（${source}）` : ''}` : source]
    }
    case 'patch_adopt': {
      const file = textOf(detail.file)
      return file ? [file] : []
    }
    case 'report_export': {
      const format = FORMAT_LABELS[textOf(detail.format)] ?? textOf(detail.format).toUpperCase()
      const name = textOf(detail.project_name)
      const text = [format && `导出 ${format}`, name].filter(Boolean).join(' · ')
      return text ? [text] : []
    }
    case 'setting_update':
      return settingLines(detail.changes)
    default:
      return []
  }
}

function targetOf(entry: AuditLogEntry): { taskId: string | null; text: string } {
  if (entry.target_type === 'task' && entry.target_id) {
    return { taskId: entry.target_id, text: `任务 #${entry.target_id}` }
  }
  if (entry.target_type === 'finding') {
    const code = textOf(entry.detail?.finding_code)
    return { taskId: null, text: code || (entry.target_id ? `漏洞 #${entry.target_id}` : '漏洞') }
  }
  if (entry.target_type === 'setting') {
    const keys = (entry.target_id ?? '').split(',').filter(Boolean)
    return { taskId: null, text: keys.map(settingLabel).join('、') || '系统配置' }
  }
  return { taskId: null, text: '' }
}

const rows = computed<LogRow[]>(() =>
  items.value.map((entry) => {
    const meta = AUDIT_ACTION_META[entry.action] ?? { label: entry.action, tag: 'info' as const }
    const target = targetOf(entry)
    return {
      id: entry.id,
      time: formatTime(entry.created_at, true),
      username: entry.username,
      actionLabel: meta.label,
      actionTag: meta.tag,
      taskId: target.taskId,
      targetText: target.text,
      lines: detailLines(entry),
    }
  }),
)

const emptyText = computed(() => {
  if (loading.value) return ' '
  if (!action.value && !username.value) return '还没有操作记录'
  return '没有符合条件的记录'
})

async function load(): Promise<void> {
  const current = ++seq
  loading.value = true
  error.value = ''
  try {
    const data = await listAuditLogs({
      action: action.value || undefined,
      username: username.value || undefined,
      limit: PAGE_SIZE,
      offset: (page.value - 1) * PAGE_SIZE,
    })
    if (current !== seq) return
    items.value = data.items
    total.value = data.total
    const lastPage = Math.max(1, Math.ceil(data.total / PAGE_SIZE))
    if (data.total > 0 && data.items.length === 0 && page.value > lastPage) page.value = lastPage
  } catch (err) {
    if (current !== seq) return
    error.value = err instanceof ApiError ? err.message : '审计日志加载失败'
    items.value = []
    total.value = 0
  } finally {
    if (current === seq) loading.value = false
  }
}

watch([action, username, page], () => void load(), { immediate: true })
</script>

<template>
  <div class="page">
    <div class="page-head">
      <div>
        <h2 class="page-title">审计日志</h2>
        <p class="page-desc">记录登录、新建与停止评估、采纳补丁、导出报告和修改配置</p>
      </div>
    </div>
    <el-card shadow="never">
      <div class="toolbar">
        <el-select
          :model-value="action || undefined"
          clearable
          placeholder="全部操作"
          class="action"
          @change="onAction"
        >
          <el-option v-for="item in AUDIT_ACTIONS" :key="item.key" :label="item.label" :value="item.key" />
        </el-select>
        <el-input
          v-model="usernameInput"
          clearable
          placeholder="用户名，精确匹配"
          class="username"
          @change="applyUsername"
          @clear="applyUsername"
          @keyup.enter="applyUsername"
        />
        <span v-if="!error" class="count">共 {{ total }} 条</span>
      </div>

      <el-alert v-if="error" type="error" :title="error" show-icon :closable="false">
        <el-button size="small" @click="load">重试</el-button>
      </el-alert>

      <template v-else>
        <el-table v-loading="loading" :data="rows" :empty-text="emptyText">
          <el-table-column prop="time" label="时间" width="176" />
          <el-table-column prop="username" label="操作人" width="120" />
          <el-table-column label="操作" width="120">
            <template #default="{ row }">
              <el-tag size="small" :type="row.actionTag">{{ row.actionLabel }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column label="对象" min-width="160">
            <template #default="{ row }">
              <router-link v-if="row.taskId" class="link" :to="{ name: 'workbench', params: { taskId: row.taskId } }">
                {{ row.targetText }}
              </router-link>
              <span v-else>{{ row.targetText || '—' }}</span>
            </template>
          </el-table-column>
          <el-table-column label="详情" min-width="240">
            <template #default="{ row }">
              <div v-if="row.lines.length" class="lines">
                <div v-for="(line, index) in row.lines" :key="index">{{ line }}</div>
              </div>
              <span v-else class="muted">—</span>
            </template>
          </el-table-column>
        </el-table>
        <div v-if="total > PAGE_SIZE" class="pager">
          <el-pagination
            background
            layout="prev, pager, next"
            :total="total"
            :page-size="PAGE_SIZE"
            :current-page="page"
            @current-change="page = $event"
          />
        </div>
      </template>
    </el-card>
  </div>
</template>

<style scoped>
.toolbar {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
  margin-bottom: 16px;
}

.action {
  width: 160px;
}

.username {
  width: 220px;
}

.count {
  margin-left: auto;
  font-size: 13px;
  color: var(--app-text-muted);
}

.link {
  color: var(--el-color-primary);
  text-decoration: none;
}

.lines {
  line-height: 1.6;
}

.muted {
  color: var(--app-text-muted);
}

.pager {
  display: flex;
  justify-content: flex-end;
  margin-top: 16px;
}
</style>
