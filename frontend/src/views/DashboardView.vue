<script setup lang="ts">
import type { EChartsCoreOption } from 'echarts/core'
import { ElMessage, ElMessageBox } from 'element-plus'
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'

import { ApiError } from '@/api/http'
import { createTask, listProjects, type ProjectOut, type TaskOut, type TaskStatus } from '@/api/tasks'
import EChart from '@/components/EChart.vue'
import { useAuthStore } from '@/stores/auth'
import { formatTime } from '@/utils/format'
import { ACTIVE_STATUSES, SEVERITIES, STAGE_LABELS, STATUS_META } from '@/utils/labels'
import NewTaskDialog from '@/views/dashboard/NewTaskDialog.vue'

const POLL_MS = 5000

const auth = useAuthStore()
const router = useRouter()
const projects = ref<ProjectOut[]>([])
const loading = ref(true)
const loadError = ref('')
const dialogVisible = ref(false)
const canCreate = computed(() => auth.hasRole('engineer'))
let timer: number | undefined

const hasActive = computed(() =>
  projects.value.some((p) => p.latest_task && ACTIVE_STATUSES.includes(p.latest_task.status)),
)

async function load(): Promise<void> {
  try {
    projects.value = await listProjects()
    loadError.value = ''
  } catch (err) {
    loadError.value = err instanceof ApiError ? err.message : '加载项目列表失败'
  } finally {
    loading.value = false
  }
}

// 有排队或评估中的任务时定时刷新
function schedule(): void {
  timer = window.setTimeout(async () => {
    if (hasActive.value && document.visibilityState === 'visible') await load()
    schedule()
  }, POLL_MS)
}

onMounted(async () => {
  await load()
  schedule()
})
onBeforeUnmount(() => window.clearTimeout(timer))

const stats = computed(() => {
  const latest = projects.value.map((p) => p.latest_task).filter((t) => t !== null)
  return [
    { label: '项目数', value: projects.value.length },
    { label: '进行中的评估', value: latest.filter((t) => ACTIVE_STATUSES.includes(t.status)).length },
    { label: '最近一次评估：严重与高危', value: latest.reduce((n, t) => n + t.counts.critical + t.counts.high, 0) },
    { label: '最近一次评估：中低危', value: latest.reduce((n, t) => n + t.counts.medium + t.counts.low, 0) },
  ]
})

const severityOption = computed<EChartsCoreOption>(() => {
  const totals = SEVERITIES.map((s) =>
    projects.value.reduce((n, p) => n + (p.latest_task ? p.latest_task.counts[s.key] : 0), 0),
  )
  return {
    tooltip: { trigger: 'axis' },
    grid: { left: 40, right: 16, top: 16, bottom: 28 },
    xAxis: { type: 'category', data: SEVERITIES.map((s) => s.label) },
    yAxis: { type: 'value', minInterval: 1 },
    series: [
      {
        type: 'bar',
        name: '漏洞数',
        barMaxWidth: 36,
        data: totals.map((value, i) => ({ value, itemStyle: { color: SEVERITIES[i].color } })),
      },
    ],
  }
})

const statusOption = computed<EChartsCoreOption>(() => {
  const counts = new Map<TaskStatus, number>()
  for (const p of projects.value) {
    if (p.latest_task) counts.set(p.latest_task.status, (counts.get(p.latest_task.status) ?? 0) + 1)
  }
  return {
    tooltip: { trigger: 'item' },
    legend: { bottom: 0 },
    series: [
      {
        type: 'pie',
        radius: ['45%', '70%'],
        center: ['50%', '45%'],
        label: { formatter: '{b} {c}' },
        data: [...counts].map(([status, value]) => ({ name: STATUS_META[status].label, value })),
      },
    ],
  }
})

function techLabel(p: ProjectOut): string {
  const stack = p.tech_stack
  if (!stack) return '—'
  const fw = stack.frameworks.map((f) => (f.version ? `${f.name} ${f.version}` : f.name))
  return [stack.primary_language, ...fw].filter(Boolean).join(' · ') || '—'
}

function openTask(task: TaskOut): void {
  void router.push({ name: 'workbench', params: { taskId: task.id } })
}

async function reassess(p: ProjectOut): Promise<void> {
  try {
    await ElMessageBox.confirm(`对「${p.name}」重新发起一次评估？`, '重新评估', { type: 'info' })
  } catch {
    return
  }
  try {
    openTask(await createTask({ kind: 'project', projectId: p.id }))
  } catch (err) {
    ElMessage.error(err instanceof ApiError ? err.message : '创建失败')
  }
}
</script>

<template>
  <div class="page">
    <div class="header">
      <h2 class="page-title">项目概览</h2>
      <el-button v-if="canCreate" type="primary" @click="dialogVisible = true">
        <el-icon><Plus /></el-icon>
        <span>新建评估</span>
      </el-button>
    </div>

    <el-alert v-if="loadError" :title="loadError" type="error" show-icon :closable="false" class="block" />

    <el-row :gutter="16" class="block">
      <el-col v-for="s in stats" :key="s.label" :xs="12" :sm="6">
        <el-card shadow="never" class="stat">
          <div class="stat-value">{{ s.value }}</div>
          <div class="stat-label">{{ s.label }}</div>
        </el-card>
      </el-col>
    </el-row>

    <el-row :gutter="16" class="block">
      <el-col :xs="24" :md="14">
        <el-card shadow="never" header="最近一次评估的漏洞分布">
          <EChart :option="severityOption" height="240px" />
        </el-card>
      </el-col>
      <el-col :xs="24" :md="10">
        <el-card shadow="never" header="最近一次评估的状态">
          <EChart v-if="projects.length" :option="statusOption" height="240px" />
          <el-empty v-else description="暂无评估" :image-size="80" />
        </el-card>
      </el-col>
    </el-row>

    <el-card shadow="never" header="项目列表">
      <el-table v-loading="loading" :data="projects" empty-text="还没有项目，点击右上角新建评估">
        <el-table-column label="项目" min-width="180">
          <template #default="{ row }: { row: ProjectOut }">
            <div class="name">{{ row.name }}</div>
            <div class="sub">{{ row.source_type === 'git' ? row.source_url : 'zip 上传' }}</div>
          </template>
        </el-table-column>
        <el-table-column label="技术栈" min-width="160">
          <template #default="{ row }: { row: ProjectOut }">{{ techLabel(row) }}</template>
        </el-table-column>
        <el-table-column label="代码行数" width="100" align="right">
          <template #default="{ row }: { row: ProjectOut }">{{ row.loc?.toLocaleString() ?? '—' }}</template>
        </el-table-column>
        <el-table-column label="最新评估时间" width="150">
          <template #default="{ row }: { row: ProjectOut }">{{ formatTime(row.last_assessed_at) }}</template>
        </el-table-column>
        <el-table-column label="最近一次评估" min-width="200">
          <template #default="{ row }: { row: ProjectOut }">
            <template v-if="row.latest_task">
              <el-tag :type="STATUS_META[row.latest_task.status].tag" size="small">
                {{ STATUS_META[row.latest_task.status].label }}
              </el-tag>
              <span v-if="row.latest_task.status === 'running' && row.latest_task.current_stage" class="sub stage">
                {{ STAGE_LABELS[row.latest_task.current_stage] }}
              </span>
              <span class="severity">
                <span v-for="s in SEVERITIES" :key="s.key" :style="{ color: s.color }" :title="s.label">
                  {{ s.label }} {{ row.latest_task.counts[s.key] }}
                </span>
              </span>
            </template>
            <span v-else class="sub">—</span>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="170" fixed="right">
          <template #default="{ row }: { row: ProjectOut }">
            <el-button
              v-if="row.latest_task"
              link
              type="primary"
              @click="router.push({ name: 'workbench', params: { taskId: row.latest_task.id } })"
            >
              工作台
            </el-button>
            <el-button
              v-if="canCreate"
              link
              type="primary"
              :disabled="!!row.latest_task && ACTIVE_STATUSES.includes(row.latest_task.status)"
              @click="reassess(row)"
            >
              重新评估
            </el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <NewTaskDialog v-model="dialogVisible" @created="openTask" />
  </div>
</template>

<style scoped>
.header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 16px;
}

.header .page-title {
  margin: 0;
}

.block {
  margin-bottom: 16px;
}

.stat-value {
  font-size: 26px;
  font-weight: 600;
}

.stat-label {
  margin-top: 4px;
  font-size: 13px;
  color: var(--app-text-muted);
}

.name {
  font-weight: 500;
}

.sub {
  font-size: 12px;
  color: var(--app-text-muted);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.stage {
  margin-left: 6px;
}

.severity {
  display: inline-flex;
  gap: 8px;
  margin-left: 8px;
  font-size: 12px;
}

.el-col {
  margin-bottom: 0;
}

@media (max-width: 768px) {
  .el-col {
    margin-bottom: 12px;
  }
}
</style>
