<script setup lang="ts">
import type { EChartsCoreOption } from 'echarts/core'
import { computed, nextTick, onBeforeUnmount, onMounted, ref, useTemplateRef, watch } from 'vue'

import { openEventStream, type ServerEvent } from '@/api/sse'
import { getTask, listLogs, type LogEntry, type StageKey, type TaskOut, type TaskStatus } from '@/api/tasks'
import EChart from '@/components/EChart.vue'
import { formatClock } from '@/utils/format'
import { STAGE_LABELS, STAGES } from '@/utils/labels'

interface Metrics {
  cpu_percent: number
  memory_mb: number
  memory_limit_mb: number
  pids: number
}

const MAX_LOGS = 3000
const MAX_POINTS = 150 // 2 秒一个点，约 5 分钟

const props = defineProps<{ taskId: number }>()
const task = defineModel<TaskOut | null>('task', { required: true })

const logs = ref<LogEntry[]>([])
const doneStages = ref(new Set<StageKey>())
const samples = ref<{ t: string; m: Metrics }[]>([])
const connected = ref(false)
const follow = ref(true)
const logBox = useTemplateRef<HTMLDivElement>('logBox')
let lastLogId = 0
let closeStream: (() => void) | null = null

function appendLogs(entries: LogEntry[]): void {
  const fresh = entries.filter((e) => e.id > lastLogId)
  if (!fresh.length) return
  lastLogId = fresh[fresh.length - 1].id
  logs.value = [...logs.value, ...fresh].slice(-MAX_LOGS)
  for (const e of fresh) {
    if (e.stage && e.message.startsWith('阶段结束')) doneStages.value.add(e.stage)
  }
  if (follow.value) void nextTick(() => logBox.value?.scrollTo({ top: logBox.value.scrollHeight }))
}

async function refresh(): Promise<void> {
  const [t, entries] = await Promise.all([getTask(props.taskId), listLogs(props.taskId, lastLogId)])
  task.value = t
  appendLogs(entries)
}

function onEvent(ev: ServerEvent): void {
  const data = ev.data as Record<string, unknown>
  if (ev.event === 'log') {
    appendLogs([data as unknown as LogEntry])
  } else if (ev.event === 'stage' && task.value) {
    const stage = data.stage as StageKey
    task.value = { ...task.value, current_stage: stage }
    if (data.state === 'done') doneStages.value.add(stage)
  } else if (ev.event === 'status') {
    const status = data.status as TaskStatus
    if (task.value) task.value = { ...task.value, status, error: (data.error as string | null) ?? null }
    // 结束后再取一次，拿到结束时间和漏洞统计
    if (status !== 'running' && status !== 'created') void refresh()
  } else if (ev.event === 'metrics') {
    samples.value = [...samples.value, { t: ev.ts, m: data as unknown as Metrics }].slice(-MAX_POINTS)
  }
}

function onScroll(): void {
  const box = logBox.value
  if (box) follow.value = box.scrollHeight - box.scrollTop - box.clientHeight < 24
}

function connect(): void {
  closeStream?.()
  logs.value = []
  samples.value = []
  doneStages.value = new Set()
  lastLogId = 0
  connected.value = false
  closeStream = openEventStream(`/api/tasks/${props.taskId}/events`, {
    onEvent,
    onOpen: () => {
      connected.value = true
      void refresh().catch(() => undefined)
    },
  })
}

onMounted(connect)
watch(() => props.taskId, connect)
onBeforeUnmount(() => closeStream?.())

const isActive = computed(() => task.value?.status === 'running' || task.value?.status === 'created')

type StepStatus = 'wait' | 'process' | 'finish' | 'error' | 'success'

const steps = computed(() => {
  const t = task.value
  const currentIdx = t?.current_stage ? STAGES.findIndex((s) => s.key === t.current_stage) : -1
  return STAGES.map((s, i) => {
    let status: StepStatus = 'wait'
    let description = ''
    if (t?.status === 'completed') {
      status = 'success'
    } else if (i < currentIdx || doneStages.value.has(s.key)) {
      status = 'finish'
    } else if (i === currentIdx) {
      if (t?.status === 'running') {
        status = 'process'
        description = '进行中'
      } else if (t?.status === 'failed') {
        status = 'error'
        description = '失败'
      } else if (t?.status === 'stopped') {
        status = 'error'
        description = '已停止'
      }
    } else if (i === 0 && t?.status === 'created') {
      description = '排队中'
    }
    return { ...s, status, description }
  })
})

const latest = computed(() => samples.value[samples.value.length - 1]?.m ?? null)

const metricsOption = computed<EChartsCoreOption>(() => ({
  animation: false,
  tooltip: { trigger: 'axis' },
  legend: { top: 0 },
  grid: { left: 48, right: 56, top: 32, bottom: 28 },
  xAxis: { type: 'category', boundaryGap: false, data: samples.value.map((s) => formatClock(s.t)) },
  yAxis: [
    { type: 'value', name: 'CPU %', min: 0 },
    { type: 'value', name: '内存 MB', min: 0, max: latest.value?.memory_limit_mb || undefined },
  ],
  series: [
    { name: 'CPU', type: 'line', showSymbol: false, data: samples.value.map((s) => s.m.cpu_percent) },
    { name: '内存', type: 'line', showSymbol: false, yAxisIndex: 1, data: samples.value.map((s) => s.m.memory_mb) },
    { name: '进程数', type: 'line', showSymbol: false, data: samples.value.map((s) => s.m.pids) },
  ],
}))
</script>

<template>
  <div class="monitor">
    <el-card shadow="never" class="block">
      <el-steps :active="-1" align-center>
        <el-step v-for="s in steps" :key="s.key" :title="s.label" :status="s.status" :description="s.description" />
      </el-steps>
      <el-alert
        v-if="task?.error"
        :title="task.error"
        type="error"
        show-icon
        :closable="false"
        class="error"
      />
    </el-card>

    <el-row :gutter="16">
      <el-col :xs="24" :lg="14" class="block">
        <el-card shadow="never" class="fill">
          <template #header>
            <div class="card-header">
              <span>运行日志</span>
              <span class="muted">
                <el-tag v-if="isActive" :type="connected ? 'success' : 'info'" size="small" effect="plain">
                  {{ connected ? '实时' : '连接中' }}
                </el-tag>
                {{ logs.length }} 行
              </span>
            </div>
          </template>
          <div ref="logBox" class="logs" @scroll="onScroll">
            <div v-for="line in logs" :key="line.id" :class="['line', line.level]">
              <span class="time">{{ formatClock(line.created_at) }}</span>
              <span class="stage">{{ line.stage ? STAGE_LABELS[line.stage] : '任务' }}</span>
              <span class="msg">{{ line.message }}</span>
            </div>
            <div v-if="!logs.length" class="empty">{{ task?.status === 'created' ? '任务排队中，等待前面的评估结束' : '暂无日志' }}</div>
          </div>
        </el-card>
      </el-col>
      <el-col :xs="24" :lg="10" class="block">
        <el-card shadow="never" class="fill">
          <template #header>
            <div class="card-header">
              <span>沙箱资源</span>
              <span v-if="latest" class="muted">
                CPU {{ latest.cpu_percent }}% · 内存 {{ latest.memory_mb }} / {{ latest.memory_limit_mb }} MB · 进程
                {{ latest.pids }}
              </span>
            </div>
          </template>
          <EChart v-if="samples.length" :option="metricsOption" height="300px" />
          <el-empty
            v-else
            :image-size="70"
            :description="isActive ? '等待沙箱容器启动后的第一组采样' : '资源曲线只在任务运行时实时显示，不保存历史'"
          />
        </el-card>
      </el-col>
    </el-row>
  </div>
</template>

<style scoped>
.block {
  margin-bottom: 16px;
}

.error {
  margin-top: 16px;
}

.fill {
  height: 100%;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
}

.muted {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  font-size: 12px;
  color: var(--app-text-muted);
}

.logs {
  height: 300px;
  overflow-y: auto;
  background: #1e1e1e;
  color: #d4d4d4;
  border-radius: 4px;
  padding: 8px 12px;
  font-family: Consolas, 'Cascadia Mono', 'Courier New', monospace;
  font-size: 12.5px;
  line-height: 1.7;
}

.line {
  display: flex;
  gap: 10px;
  white-space: pre-wrap;
  word-break: break-all;
}

.line.warn .msg {
  color: #e5c07b;
}

.line.error .msg {
  color: #f48771;
}

.time {
  color: #7f848e;
  flex-shrink: 0;
}

.stage {
  color: #61afef;
  flex-shrink: 0;
  min-width: 6em;
}

.empty {
  color: #7f848e;
}
</style>
