<script setup lang="ts">
import { ElMessage, ElMessageBox } from 'element-plus'
import { computed, defineAsyncComponent, onBeforeUnmount, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import { ApiError } from '@/api/http'
import { type StageKey, stopTask, type TaskOut } from '@/api/tasks'
import SeverityBar from '@/components/SeverityBar.vue'
import StageTrack from '@/components/StageTrack.vue'
import StatusPill from '@/components/StatusPill.vue'
import { useAuthStore } from '@/stores/auth'
import { formatDuration, formatTime } from '@/utils/format'
import type { FindingGroup } from '@/utils/labels'
import FindingDetail from '@/views/workbench/FindingDetail.vue'
import FindingList from '@/views/workbench/FindingList.vue'
import MonitorPanel from '@/views/workbench/MonitorPanel.vue'

// G6 体积大，单独分包，页面框架先渲染
const AttackGraph = defineAsyncComponent(() => import('@/views/workbench/AttackGraph.vue'))

const route = useRoute()
const router = useRouter()
const auth = useAuthStore()
const task = ref<TaskOut | null>(null)
const stopping = ref(false)
const selectedFinding = ref<number | null>(null)
const doneStages = ref(new Set<StageKey>())
const findingSummary = ref<Record<FindingGroup, number> | null>(null)
// 阶段或任务状态变化时漏洞数据可能已更新，用于通知详情面板重新拉取
const revision = computed(() => `${task.value?.status}:${task.value?.current_stage}`)
// 拓扑图上点击漏洞节点时在侧栏打开的漏洞
const drawerFinding = ref<number | null>(null)
const drawerOpen = computed({
  get: () => drawerFinding.value !== null,
  set: (open: boolean) => {
    if (!open) drawerFinding.value = null
  },
})

const taskId = computed(() => Number(route.params.taskId))
const canStop = computed(
  () => auth.hasRole('engineer') && (task.value?.status === 'running' || task.value?.status === 'created'),
)

watch(taskId, () => (task.value = null))

type Tab = 'monitor' | 'findings' | 'graph'
const TABS: Tab[] = ['monitor', 'findings', 'graph']

// 当前标签放在地址栏；没有指定时，运行中的任务看监控，结束的任务看漏洞
const tab = computed<Tab>({
  get: () => {
    const q = route.query.tab
    if (typeof q === 'string' && (TABS as string[]).includes(q)) return q as Tab
    const status = task.value?.status
    return !status || status === 'running' || status === 'created' ? 'monitor' : 'findings'
  },
  set: (value) => {
    void router.replace({ query: { ...route.query, tab: value } })
  },
})

// 运行中的任务每秒刷新一次用时
const now = ref(Date.now())
const clock = window.setInterval(() => {
  if (task.value?.status === 'running') now.value = Date.now()
}, 1000)
onBeforeUnmount(() => window.clearInterval(clock))

async function stop(): Promise<void> {
  try {
    await ElMessageBox.confirm('停止后会立即销毁沙箱容器，已产出的阶段数据保留。确定停止？', '停止评估', {
      type: 'warning',
      confirmButtonText: '停止',
    })
  } catch {
    return
  }
  stopping.value = true
  try {
    task.value = await stopTask(taskId.value)
    ElMessage.success('评估已停止')
  } catch (err) {
    ElMessage.error(err instanceof ApiError ? err.message : '停止失败')
  } finally {
    stopping.value = false
  }
}
</script>

<template>
  <div class="page workbench">
    <section class="hero">
      <div class="hero-top">
        <div class="hero-title">
          <RouterLink :to="{ name: 'dashboard' }" class="back">
            <el-icon><ArrowLeft /></el-icon>
            项目概览
          </RouterLink>
          <h2 class="page-title">
            <span>{{ task?.project_name ?? '…' }}</span>
            <span class="task-no mono">#{{ taskId }}</span>
            <StatusPill v-if="task" :status="task.status" />
          </h2>
          <div v-if="task" class="meta">
            <span><el-icon><Calendar /></el-icon>创建于 {{ formatTime(task.created_at) }}</span>
            <span v-if="task.started_at">
              <el-icon><Timer /></el-icon>用时 {{ formatDuration(task.started_at, task.finished_at, now) }}
            </span>
          </div>
        </div>
        <div class="hero-side">
          <div v-if="task" class="hero-sev">
            <SeverityBar :counts="task.counts" legend />
          </div>
          <div class="hero-actions">
            <el-button
              v-if="task?.status === 'completed'"
              @click="router.push({ name: 'reports', query: { task: String(taskId) } })"
            >
              <el-icon><Document /></el-icon>
              <span>查看报告</span>
            </el-button>
            <el-button v-if="canStop" type="danger" plain :loading="stopping" @click="stop">
              <el-icon><VideoPause /></el-icon>
              <span>停止评估</span>
            </el-button>
          </div>
        </div>
      </div>
      <StageTrack
        class="hero-track"
        :status="task?.status ?? null"
        :current-stage="task?.current_stage ?? null"
        :done-stages="doneStages"
      />
      <el-alert v-if="task?.error" :title="task.error" type="error" show-icon :closable="false" class="hero-error" />
    </section>

    <el-tabs v-model="tab" class="wb-tabs">
      <el-tab-pane name="monitor">
        <template #label>
          <span class="tab-label"><el-icon><Monitor /></el-icon>运行监控</span>
        </template>
        <MonitorPanel v-model:task="task" v-model:done-stages="doneStages" :task-id="taskId" />
      </el-tab-pane>

      <el-tab-pane name="findings">
        <template #label>
          <span class="tab-label">
            <el-icon><Warning /></el-icon>漏洞
            <span v-if="findingSummary" class="count-chip">
              {{ findingSummary.verified + findingSummary.unverified }}
            </span>
          </span>
        </template>
        <div class="split">
          <section class="panel list-panel">
            <FindingList
              v-model:selected="selectedFinding"
              v-model:summary="findingSummary"
              :task-id="taskId"
              :task="task"
            />
          </section>
          <section class="panel detail-panel">
            <FindingDetail :task-id="taskId" :finding-id="selectedFinding" :revision="revision" />
          </section>
        </div>
      </el-tab-pane>

      <el-tab-pane name="graph" lazy>
        <template #label>
          <span class="tab-label"><el-icon><Share /></el-icon>攻击路径</span>
        </template>
        <section class="panel graph-panel">
          <AttackGraph :task-id="taskId" :task="task" @open-finding="drawerFinding = $event" />
        </section>
      </el-tab-pane>
    </el-tabs>

    <el-drawer v-model="drawerOpen" title="漏洞详情" size="min(960px, 92vw)" destroy-on-close>
      <FindingDetail :task-id="taskId" :finding-id="drawerFinding" :revision="revision" />
    </el-drawer>
  </div>
</template>

<style scoped>
.hero {
  margin-bottom: 12px;
}

.hero-top {
  display: flex;
  justify-content: space-between;
  align-items: flex-end;
  flex-wrap: wrap;
  gap: 16px 32px;
}

.hero-title {
  min-width: 0;
}

.back {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  font-size: 12.5px;
  color: var(--app-text-muted);
  text-decoration: none;
}

.back:hover {
  color: var(--app-text);
}

.hero .page-title {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 6px 12px;
  margin: 10px 0 8px;
  word-break: break-all;
}

.task-no {
  font-size: 15px;
  font-weight: 400;
  letter-spacing: 0;
  color: var(--app-text-muted);
}

.meta {
  display: flex;
  flex-wrap: wrap;
  gap: 4px 18px;
  font-size: 12.5px;
  color: var(--app-text-muted);
}

.meta span {
  display: inline-flex;
  align-items: center;
  gap: 5px;
}

.hero-side {
  display: flex;
  flex-direction: column;
  align-items: flex-end;
  gap: 14px;
}

.hero-sev {
  width: 320px;
  max-width: 100%;
}

.hero-actions {
  display: flex;
  gap: 8px;
}

.hero-actions .el-button + .el-button {
  margin-left: 0;
}

.hero-track {
  margin-top: 28px;
}

.hero-error {
  margin-top: 16px;
}

.wb-tabs :deep(.el-tabs__header) {
  margin-bottom: 20px;
}

/* 标签内容区默认 overflow: hidden，会让漏洞列表的吸顶失效 */
.wb-tabs :deep(.el-tabs__content) {
  overflow: visible;
}

.wb-tabs :deep(.el-tabs__item) {
  height: 48px;
  font-size: 14.5px;
}

.tab-label {
  display: inline-flex;
  align-items: center;
  gap: 7px;
}

.split {
  display: grid;
  grid-template-columns: minmax(300px, 380px) minmax(0, 1fr);
  gap: 20px;
  align-items: start;
}

.list-panel {
  position: sticky;
  top: 16px;
  display: flex;
  flex-direction: column;
  max-height: calc(100vh - 32px);
  box-sizing: border-box;
  overflow: hidden;
}

.list-panel > * {
  flex: 1;
  min-height: 0;
}

.detail-panel {
  min-width: 0;
  padding: 24px 28px 28px;
}

.graph-panel {
  padding: 20px;
}

@media (max-width: 1023px) {
  .split {
    grid-template-columns: minmax(0, 1fr);
  }

  .list-panel {
    position: static;
    max-height: 460px;
  }

  .hero-side {
    align-items: stretch;
    width: 100%;
  }

  .hero-sev {
    width: auto;
  }
}

@media (max-width: 767px) {
  .detail-panel {
    padding: 16px;
  }

  .graph-panel {
    padding: 14px;
  }
}
</style>
