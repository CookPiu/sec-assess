<script setup lang="ts">
import { computed } from 'vue'

import type { StageKey, TaskStatus } from '@/api/tasks'
import { STAGES } from '@/utils/labels'

type StageState = 'done' | 'active' | 'failed' | 'stopped' | 'wait'

/**
 * 五阶段进度。compact 为 true 时只画五段进度条（用于项目卡片），否则画带名称的轨道。
 * doneStages 来自运行日志里的“阶段结束”，没有时按当前阶段之前的都已完成推断。
 */
const props = withDefaults(
  defineProps<{
    status: TaskStatus | null
    currentStage: StageKey | null
    doneStages?: Set<StageKey>
    compact?: boolean
  }>(),
  { doneStages: undefined, compact: false },
)

const STATE_TEXT: Record<StageState, string> = {
  done: '已完成',
  active: '进行中',
  failed: '失败',
  stopped: '已停止',
  wait: '',
}

const items = computed(() => {
  const status = props.status
  const currentIdx = props.currentStage ? STAGES.findIndex((s) => s.key === props.currentStage) : -1
  return STAGES.map((s, i) => {
    let state: StageState = 'wait'
    if (status === 'completed') state = 'done'
    else if (i < currentIdx || props.doneStages?.has(s.key)) state = 'done'
    else if (i === currentIdx) {
      if (status === 'running') state = 'active'
      else if (status === 'failed') state = 'failed'
      else if (status === 'stopped') state = 'stopped'
    }
    let text = STATE_TEXT[state]
    if (i === 0 && status === 'created') text = '排队中'
    return { ...s, state, text, index: i + 1 }
  })
})

const summary = computed(() => items.value.map((s) => `${s.label}${s.text ? `：${s.text}` : ''}`).join('，'))
</script>

<template>
  <div v-if="compact" class="track-compact" role="img" :aria-label="summary" :title="summary">
    <span v-for="s in items" :key="s.key" :class="['bar', s.state]" />
  </div>
  <ol v-else class="track" :aria-label="summary">
    <li v-for="s in items" :key="s.key" :class="['stage', s.state]">
      <span class="node">
        <el-icon v-if="s.state === 'done'"><Check /></el-icon>
        <el-icon v-else-if="s.state === 'failed'"><Close /></el-icon>
        <el-icon v-else-if="s.state === 'stopped'"><VideoPause /></el-icon>
        <span v-else>{{ s.index }}</span>
      </span>
      <span class="text">
        <span class="label">{{ s.label }}</span>
        <span class="state">{{ s.text || '等待' }}</span>
      </span>
    </li>
  </ol>
</template>

<style scoped>
.track-compact {
  display: flex;
  gap: 3px;
}

.track-compact .bar {
  flex: 1;
  height: 4px;
  border-radius: 2px;
  background: var(--app-surface-sunken);
}

.track-compact .bar.done {
  background: var(--app-success);
}

.track-compact .bar.active {
  background: linear-gradient(90deg, var(--app-primary) 0%, var(--app-primary-soft) 50%, var(--app-primary) 100%);
  background-size: 200% 100%;
  animation: flow 1.6s linear infinite;
}

.track-compact .bar.failed {
  background: var(--app-danger);
}

.track-compact .bar.stopped {
  background: var(--app-warning);
}

.track {
  display: flex;
  margin: 0;
  padding: 0;
  list-style: none;
}

.stage {
  --c: var(--app-border-strong);
  position: relative;
  flex: 1;
  display: flex;
  align-items: center;
  gap: 10px;
  min-width: 0;
  padding-right: 12px;
}

/* 阶段之间的连接线，已完成的阶段之后为绿色 */
.stage::after {
  content: '';
  flex: 1;
  height: 2px;
  min-width: 8px;
  border-radius: 1px;
  background: var(--app-border);
}

.stage:last-child::after {
  display: none;
}

.stage.done {
  --c: var(--app-success);
}

.stage.done::after {
  background: var(--app-success);
}

.stage.active {
  --c: var(--app-primary);
}

.stage.failed {
  --c: var(--app-danger);
}

.stage.stopped {
  --c: var(--app-warning);
}

.node {
  position: relative;
  flex-shrink: 0;
  display: grid;
  place-items: center;
  width: 30px;
  height: 30px;
  border-radius: 50%;
  font-size: 13px;
  font-weight: 600;
  color: var(--c);
  background: color-mix(in srgb, var(--c) 12%, var(--app-surface));
  box-shadow: inset 0 0 0 1.5px var(--c);
}

.stage.wait .node {
  color: var(--app-text-muted);
  background: var(--app-surface);
}

.stage.active .node::after {
  content: '';
  position: absolute;
  inset: -4px;
  border-radius: 50%;
  border: 2px solid var(--app-primary);
  opacity: 0;
  animation: pulse 1.8s ease-out infinite;
}

.text {
  display: flex;
  flex-direction: column;
  min-width: 0;
  white-space: nowrap;
}

.label {
  font-size: 13.5px;
  font-weight: 600;
  color: var(--app-text);
}

.stage.wait .label {
  color: var(--app-text-secondary);
  font-weight: 500;
}

.state {
  font-size: 12px;
  color: var(--c);
}

.stage.wait .state {
  color: var(--app-text-muted);
}

@keyframes pulse {
  0% {
    transform: scale(0.85);
    opacity: 0.7;
  }
  100% {
    transform: scale(1.35);
    opacity: 0;
  }
}

@keyframes flow {
  to {
    background-position: -200% 0;
  }
}

/* 窄屏改为纵向列表，阶段名不再被挤成一两个字一行 */
@media (max-width: 900px) {
  .track {
    flex-direction: column;
    gap: 0;
  }

  .stage {
    padding: 0 0 14px;
  }

  .stage::after {
    display: none;
  }

  .stage + .stage::before {
    content: '';
    position: absolute;
    top: -14px;
    left: 14px;
    width: 2px;
    height: 14px;
    background: var(--app-border);
  }

  .stage.done + .stage::before {
    background: var(--app-success);
  }

  .stage:last-child {
    padding-bottom: 0;
  }

  .text {
    flex-direction: row;
    align-items: baseline;
    gap: 8px;
  }
}
</style>
