<script setup lang="ts">
import { ElMessage, ElMessageBox } from 'element-plus'
import { computed, defineAsyncComponent, onBeforeUnmount, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import { ApiError } from '@/api/http'
import { stopTask, type TaskOut } from '@/api/tasks'
import { useAuthStore } from '@/stores/auth'
import { formatDuration, formatTime } from '@/utils/format'
import { STATUS_META } from '@/utils/labels'
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
  <div class="page">
    <div class="header">
      <div>
        <el-breadcrumb separator="/">
          <el-breadcrumb-item :to="{ name: 'dashboard' }">项目概览</el-breadcrumb-item>
          <el-breadcrumb-item>{{ task?.project_name ?? '…' }}</el-breadcrumb-item>
        </el-breadcrumb>
        <h2 class="page-title">
          评估任务 #{{ taskId }}
          <el-tag v-if="task" :type="STATUS_META[task.status].tag" class="status">
            {{ STATUS_META[task.status].label }}
          </el-tag>
        </h2>
        <div v-if="task" class="meta">
          创建于 {{ formatTime(task.created_at) }}
          <template v-if="task.started_at">
            · 用时 {{ formatDuration(task.started_at, task.finished_at, now) }}
          </template>
        </div>
      </div>
      <div class="header-actions">
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

    <MonitorPanel v-model:task="task" :task-id="taskId" />

    <el-row :gutter="16">
      <el-col :xs="24" :lg="9" class="block">
        <el-card shadow="never" class="fill">
          <template #header>漏洞列表</template>
          <FindingList v-model:selected="selectedFinding" :task-id="taskId" :task="task" />
        </el-card>
      </el-col>
      <el-col :xs="24" :lg="15" class="block">
        <el-card shadow="never" class="fill">
          <template #header>漏洞详情</template>
          <FindingDetail :task-id="taskId" :finding-id="selectedFinding" :revision="revision" />
        </el-card>
      </el-col>
    </el-row>

    <el-card shadow="never" class="block">
      <template #header>攻击路径</template>
      <AttackGraph :task-id="taskId" :task="task" @open-finding="drawerFinding = $event" />
    </el-card>

    <el-drawer v-model="drawerOpen" title="漏洞详情" size="min(960px, 92vw)" destroy-on-close>
      <FindingDetail :task-id="taskId" :finding-id="drawerFinding" :revision="revision" />
    </el-drawer>
  </div>
</template>

<style scoped>
.header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 16px;
  margin-bottom: 16px;
}

.header .page-title {
  margin: 10px 0 4px;
  display: flex;
  align-items: center;
  gap: 10px;
}

.header-actions {
  display: flex;
  gap: 8px;
  flex-shrink: 0;
}

.meta {
  font-size: 13px;
  color: var(--app-text-muted);
}

.block {
  margin-bottom: 16px;
}

.fill {
  height: 100%;
}
</style>
