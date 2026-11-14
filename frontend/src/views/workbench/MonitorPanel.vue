<script setup lang="ts">
import type { EChartsCoreOption } from 'echarts/core'
import { computed, nextTick, onBeforeUnmount, onMounted, ref, useTemplateRef, watch } from 'vue'

import { openEventStream, type ServerEvent } from '@/api/sse'
import { getTask, listLogs, type LogEntry, type StageKey, type TaskOut, type TaskStatus } from '@/api/tasks'
import EChart from '@/components/EChart.vue'
import { formatClock } from '@/utils/format'
import { STAGE_LABELS } from '@/utils/labels'
import { palette } from '@/utils/theme'

interface Metrics {
  cpu_percent: number
  memory_mb: number
  memory_limit_mb: number
  pids: number
}

const MAX_LOGS = 3000
const MAX_POINTS = 300 // 约 1 秒一个点，约 5 分钟

const props = defineProps<{ taskId: number }>()
const task = defineModel<TaskOut | null>('task', { required: true })
/** 日志里出现“阶段结束”的阶段，供页头的阶段进度使用 */
const doneStages = defineModel<Set<StageKey>>('doneStages', { required: true })

const logs = ref<LogEntry[]>([])
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
    if (e.stage && e.message.startsWith('阶段结束')) doneStages.value = new Set(doneStages.value).add(e.stage)
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
    if (data.state === 'done') doneStages.value = new Set(doneStages.value).add(stage)
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

const latest = computed(() => samples.value[samples.value.length - 1]?.m ?? null)

const memoryRatio = computed(() => {
  const m = latest.value
  return m && m.memory_limit_mb ? Math.min(100, (m.memory_mb / m.memory_limit_mb) * 100) : 0
})

function backToBottom(): void {
  follow.value = true
  void nextTick(() => logBox.value?.scrollTo({ top: logBox.value.scrollHeight }))
}

const metricsOption = computed<EChartsCoreOption>(() => {
  const c = palette.value
  const axis = {
    axisLine: { lineStyle: { color: c.border } },
    axisLabel: { color: c.muted },
    splitLine: { lineStyle: { color: c.grid } },
    nameTextStyle: { color: c.muted },
  }
  return {
    animation: false,
    color: c.series,
    tooltip: {
      trigger: 'axis',
      backgroundColor: c.surface,
      borderColor: c.border,
      textStyle: { color: c.text },
    },
    legend: { top: 0, textStyle: { color: c.textSecondary }, icon: 'roundRect', itemWidth: 12, itemHeight: 4 },
    grid: { left: 48, right: 56, top: 36, bottom: 28 },
    xAxis: { type: 'category', boundaryGap: false, data: samples.value.map((s) => formatClock(s.t)), ...axis },
    yAxis: [
      { type: 'value', name: 'CPU %', min: 0, ...axis },
      { type: 'value', name: '内存 MB', min: 0, max: latest.value?.memory_limit_mb || undefined, ...axis },
    ],
    series: [
      {
        name: 'CPU',
        type: 'line',
        showSymbol: false,
        lineStyle: { width: 2 },
        areaStyle: { opacity: 0.08 },
        data: samples.value.map((s) => s.m.cpu_percent),
      },
      {
        name: '内存',
        type: 'line',
        showSymbol: false,
        yAxisIndex: 1,
        lineStyle: { width: 2 },
        data: samples.value.map((s) => s.m.memory_mb),
      },
      {
        name: '进程数',
        type: 'line',
        showSymbol: false,
        lineStyle: { width: 2 },
        data: samples.value.map((s) => s.m.pids),
      },
    ],
  }
})
</script>

<template>
  <div class="monitor">
    <section class="panel logs-panel">
      <div class="panel-head">
        <span class="panel-title">
          <el-icon><Tickets /></el-icon>
          运行日志
        </span>
        <span class="muted head-meta">
          <span v-if="isActive" :class="['live', { on: connected }]">
            <i />{{ connected ? '实时' : '连接中' }}
          </span>
          <span class="num">{{ logs.length }} 行</span>
          <el-button v-if="!follow" size="small" link type="primary" @click="backToBottom">回到底部</el-button>
        </span>
      </div>
      <div ref="logBox" class="logs" @scroll="onScroll">
        <div v-for="line in logs" :key="line.id" :class="['line', line.level]">
          <span class="time">{{ formatClock(line.created_at) }}</span>
          <span class="stage">{{ line.stage ? STAGE_LABELS[line.stage] : '任务' }}</span>
          <span class="msg">{{ line.message }}</span>
        </div>
        <div v-if="!logs.length" class="empty">
          {{ task?.status === 'created' ? '任务排队中，等待前面的评估结束' : '暂无日志' }}
        </div>
      </div>
    </section>

    <section class="panel res-panel">
      <div class="panel-head">
        <span class="panel-title">
          <el-icon><Odometer /></el-icon>
          沙箱资源
        </span>
        <span v-if="isActive && samples.length" class="muted">约每秒刷新</span>
      </div>
      <div class="panel-body">
        <div v-if="samples.length" class="gauges">
          <div class="gauge">
            <span class="g-label">CPU</span>
            <b class="num">{{ latest ? `${latest.cpu_percent}%` : '—' }}</b>
          </div>
          <div class="gauge">
            <span class="g-label">内存</span>
            <b class="num">
              {{ latest ? latest.memory_mb : '—' }}<small v-if="latest"> / {{ latest.memory_limit_mb }} MB</small>
            </b>
            <span class="meter"><i :style="{ width: `${memoryRatio}%` }" /></span>
          </div>
          <div class="gauge">
            <span class="g-label">进程</span>
            <b class="num">{{ latest ? latest.pids : '—' }}</b>
          </div>
        </div>
        <EChart v-if="samples.length" :option="metricsOption" height="268px" />
        <el-empty
          v-else
          :image-size="64"
          :description="isActive ? '等待沙箱容器启动后的第一组采样' : '资源曲线只在任务运行时实时显示，不保存历史'"
        />
      </div>
    </section>
  </div>
</template>

<style scoped>
.monitor {
  display: grid;
  grid-template-columns: minmax(0, 1.45fr) minmax(0, 1fr);
  gap: 20px;
}

.head-meta {
  display: inline-flex;
  align-items: center;
  gap: 12px;
}

.live {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  color: var(--app-text-muted);
}

.live i {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--app-text-muted);
}

.live.on {
  color: var(--app-success);
}

.live.on i {
  background: var(--app-success);
  box-shadow: 0 0 0 3px color-mix(in srgb, var(--app-success) 22%, transparent);
}

.logs-panel {
  display: flex;
  flex-direction: column;
  min-width: 0;
  overflow: hidden;
}

.logs {
  height: 420px;
  overflow-y: auto;
  background: var(--app-term-bg);
  color: var(--app-term-text);
  padding: 12px 16px;
  font-family: var(--app-font-mono);
  font-size: 12.5px;
  line-height: 1.8;
}

.line {
  display: flex;
  gap: 14px;
  white-space: pre-wrap;
  word-break: break-all;
}

.line.warn .msg {
  color: #f2c167;
}

.line.error .msg {
  color: #ff8a8a;
}

.time {
  color: var(--app-term-muted);
  flex-shrink: 0;
}

.stage {
  color: var(--app-term-accent);
  flex-shrink: 0;
  min-width: 6.5em;
}

.empty {
  color: var(--app-term-muted);
}

/* 三项读数：细线分隔的一行 */
.gauges {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  margin-bottom: 16px;
  border: 1px solid var(--app-border);
  border-radius: var(--app-radius-sm);
}

.gauge {
  display: flex;
  flex-direction: column;
  gap: 4px;
  padding: 12px 14px;
}

.gauge + .gauge {
  border-left: 1px solid var(--app-border);
}

.g-label {
  font-size: 12px;
  color: var(--app-text-muted);
}

.gauge b {
  font-family: var(--app-font-display);
  font-size: 22px;
  font-weight: 500;
  letter-spacing: -0.02em;
  white-space: nowrap;
}

.gauge small {
  font-size: 12px;
  font-weight: 400;
  letter-spacing: 0;
  color: var(--app-text-muted);
}

.meter {
  height: 3px;
  margin-top: 4px;
  border-radius: 1px;
  background: var(--app-surface-sunken);
  overflow: hidden;
}

.meter i {
  display: block;
  height: 100%;
  background: var(--app-ink);
  transition: width 0.4s;
}

@media (max-width: 1100px) {
  .monitor {
    grid-template-columns: minmax(0, 1fr);
  }
}

@media (max-width: 767px) {
  .logs {
    height: 320px;
  }

  .stage {
    display: none;
  }
}
</style>
