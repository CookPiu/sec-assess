<script setup lang="ts">
import { computed, ref, watch } from 'vue'

import { listFindings, type FindingBrief } from '@/api/findings'
import { ApiError } from '@/api/http'
import type { TaskOut } from '@/api/tasks'
import SeverityBadge from '@/components/SeverityBadge.vue'
import { CATEGORY_LABELS, FINDING_GROUPS, findingGroup, type FindingGroup } from '@/utils/labels'

const props = defineProps<{ taskId: number; task: TaskOut | null }>()
const selected = defineModel<number | null>('selected', { required: true })
/** 各分组的漏洞数，供工作台标签页显示 */
const summary = defineModel<Record<FindingGroup, number> | null>('summary', { default: null })

const findings = ref<FindingBrief[]>([])
const loading = ref(false)
const loaded = ref(false)
const error = ref('')
const group = ref<FindingGroup>('verified')
let groupPicked = false
let seq = 0

const grouped = computed(() => {
  const result: Record<FindingGroup, FindingBrief[]> = { verified: [], unverified: [], false_positive: [] }
  for (const f of findings.value) result[findingGroup(f)].push(f)
  return result
})

const rows = computed(() => grouped.value[group.value])

watch(
  grouped,
  (g) => {
    summary.value = loaded.value
      ? { verified: g.verified.length, unverified: g.unverified.length, false_positive: g.false_positive.length }
      : null
  },
)

function onKey(e: KeyboardEvent, index: number): void {
  const next = e.key === 'ArrowDown' ? index + 1 : e.key === 'ArrowUp' ? index - 1 : -1
  if (next < 0 || next >= rows.value.length) return
  e.preventDefault()
  selected.value = rows.value[next].id
  const items = (e.currentTarget as HTMLElement).parentElement?.children
  ;(items?.[next] as HTMLElement | undefined)?.focus()
}

async function load(): Promise<void> {
  const current = ++seq
  loading.value = !loaded.value
  try {
    const items = await listFindings(props.taskId)
    if (current !== seq) return
    findings.value = items
    loaded.value = true
    error.value = ''
    // 用户还没手动切换分组时，停在第一个有内容的分组
    if (!groupPicked) group.value = FINDING_GROUPS.find((g) => grouped.value[g.key].length)?.key ?? 'verified'
    if (selected.value === null || !items.some((f) => f.id === selected.value)) {
      selected.value = rows.value[0]?.id ?? null
    }
  } catch (err) {
    if (current === seq) error.value = err instanceof ApiError ? err.message : '漏洞列表加载失败'
  } finally {
    if (current === seq) loading.value = false
  }
}

watch(
  () => props.taskId,
  () => {
    findings.value = []
    loaded.value = false
    groupPicked = false
    selected.value = null
  },
)

// 审计阶段结束后出现漏洞、验证阶段结束后状态变化，阶段或任务状态变化时重新拉取
watch(() => [props.taskId, props.task?.current_stage, props.task?.status], load, { immediate: true })

function pickGroup(key: FindingGroup): void {
  groupPicked = true
  group.value = key
}

const emptyText = computed(() => {
  if (error.value) return error.value
  const t = props.task
  if (!findings.value.length) {
    if (t && (t.status === 'created' || (t.status === 'running' && ['recon', 'code_audit'].includes(t.current_stage ?? ''))))
      return '源码审计完成后显示漏洞'
    return '未发现漏洞'
  }
  return '该分组没有漏洞'
})
</script>

<template>
  <div class="finding-list">
    <div class="groups" role="tablist" aria-label="漏洞分组">
      <button
        v-for="g in FINDING_GROUPS"
        :key="g.key"
        type="button"
        role="tab"
        :aria-selected="group === g.key"
        :class="['group', g.key, { on: group === g.key }]"
        @click="pickGroup(g.key)"
      >
        <span>{{ g.label }}</span>
        <b class="num">{{ grouped[g.key].length }}</b>
      </button>
    </div>

    <div v-loading="loading" class="rows">
      <div v-if="!rows.length && !loading" class="empty">{{ emptyText }}</div>
      <div v-else role="listbox" aria-label="漏洞列表">
        <div
          v-for="(row, i) in rows"
          :key="row.id"
          role="option"
          :aria-selected="selected === row.id"
          :tabindex="selected === row.id || (selected === null && i === 0) ? 0 : -1"
          :class="['row', `sev-${row.severity}`, { on: selected === row.id }]"
          @click="selected = row.id"
          @keydown.enter="selected = row.id"
          @keydown.up="onKey($event, i)"
          @keydown.down="onKey($event, i)"
        >
          <div class="row-top">
            <span class="code mono">{{ row.code }}</span>
            <SeverityBadge :severity="row.severity" :score="row.cvss_score" />
          </div>
          <div class="title">{{ row.title }}</div>
          <div class="sub">
            <span>{{ CATEGORY_LABELS[row.category] ?? row.category }}</span>
            <span class="mono">{{ row.file }}:{{ row.line }}</span>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.finding-list {
  display: flex;
  flex-direction: column;
  min-height: 0;
}

/* 分组：面板顶部的下划线标签 */
.groups {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  border-bottom: 1px solid var(--app-border);
}

.group {
  --c: var(--app-text-muted);
  position: relative;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  height: 46px;
  padding: 0 6px;
  border: 0;
  background: transparent;
  color: var(--app-text-muted);
  font: inherit;
  font-size: 13px;
  white-space: nowrap;
  cursor: pointer;
}

.group.verified {
  --c: var(--app-danger);
}

.group.unverified {
  --c: var(--app-warning);
}

.group b {
  min-width: 18px;
  padding: 0 5px;
  border-radius: 4px;
  font-size: 11.5px;
  font-weight: 600;
  line-height: 18px;
  color: var(--c);
  background: color-mix(in srgb, var(--c) 11%, transparent);
}

.group:hover {
  color: var(--app-text);
}

.group.on {
  color: var(--app-text);
  font-weight: 600;
}

.group.on::after {
  content: '';
  position: absolute;
  left: 12px;
  right: 12px;
  bottom: -1px;
  height: 2px;
  background: var(--app-ink);
}

.group:focus-visible,
.row:focus-visible {
  outline: 2px solid var(--app-ink);
  outline-offset: -2px;
}

.rows {
  flex: 1;
  min-height: 120px;
  overflow-y: auto;
}

/* 列表行：细线分隔，左侧短竖条表示等级 */
.row {
  --c: var(--sev-info);
  position: relative;
  padding: 14px 18px 14px 20px;
  border-bottom: 1px solid var(--app-border);
  cursor: pointer;
  transition: background-color 0.15s;
}

.row::before {
  content: '';
  position: absolute;
  left: 0;
  top: 16px;
  height: 14px;
  width: 3px;
  border-radius: 0 2px 2px 0;
  background: var(--c);
}

.row.sev-critical {
  --c: var(--sev-critical);
}

.row.sev-high {
  --c: var(--sev-high);
}

.row.sev-medium {
  --c: var(--sev-medium);
}

.row.sev-low {
  --c: var(--sev-low);
}

.row:hover {
  background: var(--app-surface-alt);
}

.row.on {
  background: var(--app-ink-soft);
  box-shadow: inset -2px 0 0 var(--app-ink);
}

.row-top {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
}

.code {
  font-size: 11.5px;
  color: var(--app-text-muted);
}

.title {
  margin: 6px 0 4px;
  font-size: 13.5px;
  font-weight: 600;
  line-height: 1.5;
  color: var(--app-text);
  word-break: break-all;
}

.sub {
  display: flex;
  flex-wrap: wrap;
  gap: 2px 10px;
  font-size: 12px;
  color: var(--app-text-muted);
  word-break: break-all;
}

.empty {
  padding: 48px 12px;
  text-align: center;
  font-size: 13px;
  color: var(--app-text-muted);
}
</style>
