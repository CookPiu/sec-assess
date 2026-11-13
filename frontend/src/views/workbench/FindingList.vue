<script setup lang="ts">
import { computed, ref, watch } from 'vue'

import { listFindings, type FindingBrief } from '@/api/findings'
import { ApiError } from '@/api/http'
import type { TaskOut } from '@/api/tasks'
import {
  CATEGORY_LABELS,
  FINDING_GROUPS,
  findingGroup,
  type FindingGroup,
  SEVERITY_META,
} from '@/utils/labels'

const props = defineProps<{ taskId: number; task: TaskOut | null }>()
const selected = defineModel<number | null>('selected', { required: true })

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
    <el-radio-group :model-value="group" size="small" class="groups" @update:model-value="pickGroup($event as FindingGroup)">
      <el-radio-button v-for="g in FINDING_GROUPS" :key="g.key" :value="g.key">
        {{ g.label }} {{ grouped[g.key].length }}
      </el-radio-button>
    </el-radio-group>

    <el-table
      v-loading="loading"
      :data="rows"
      row-key="id"
      :current-row-key="selected ?? undefined"
      highlight-current-row
      max-height="560"
      :empty-text="emptyText"
      class="table"
      @row-click="(row: FindingBrief) => (selected = row.id)"
    >
      <el-table-column label="编号" prop="code" width="104" />
      <el-table-column label="漏洞" min-width="200">
        <template #default="{ row }: { row: FindingBrief }">
          <div class="title">{{ row.title }}</div>
          <div class="sub">{{ CATEGORY_LABELS[row.category] ?? row.category }} · {{ row.file }}:{{ row.line }}</div>
        </template>
      </el-table-column>
      <el-table-column label="等级" width="112">
        <template #default="{ row }: { row: FindingBrief }">
          <el-tag :type="SEVERITY_META[row.severity].tag" size="small" effect="dark" disable-transitions>
            {{ SEVERITY_META[row.severity].label }}
          </el-tag>
          <span class="score">{{ row.cvss_score?.toFixed(1) ?? '—' }}</span>
        </template>
      </el-table-column>
    </el-table>
  </div>
</template>

<style scoped>
.groups {
  margin-bottom: 12px;
}

.table :deep(.el-table__row) {
  cursor: pointer;
}

.title {
  line-height: 1.4;
}

.sub {
  font-size: 12px;
  color: var(--app-text-muted);
  word-break: break-all;
}

.score {
  margin-left: 6px;
  font-variant-numeric: tabular-nums;
}
</style>
