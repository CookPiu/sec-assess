<script setup lang="ts">
import { computed } from 'vue'

import type { SeverityCounts } from '@/api/tasks'
import { SEVERITIES } from '@/utils/labels'

/** 按严重等级堆叠的横条；legend 为 true 时在下方列出各等级数量 */
const props = withDefaults(defineProps<{ counts: SeverityCounts; legend?: boolean; height?: number }>(), {
  legend: false,
  height: 8,
})

const total = computed(() => SEVERITIES.reduce((n, s) => n + (props.counts[s.key] ?? 0), 0))
const segments = computed(() => SEVERITIES.filter((s) => props.counts[s.key] > 0))
const title = computed(() => SEVERITIES.map((s) => `${s.label} ${props.counts[s.key] ?? 0}`).join('，'))
</script>

<template>
  <div class="sev-bar">
    <div class="track" :style="{ height: `${height}px` }" role="img" :aria-label="title" :title="title">
      <span
        v-for="s in segments"
        :key="s.key"
        class="seg"
        :style="{ flexGrow: counts[s.key], background: s.color }"
      />
      <span v-if="!total" class="seg empty" />
    </div>
    <div v-if="legend" class="legend">
      <span v-for="s in SEVERITIES" :key="s.key" class="item">
        <i :style="{ background: s.color }" />
        <span class="name">{{ s.label }}</span>
        <b class="num">{{ counts[s.key] ?? 0 }}</b>
      </span>
    </div>
  </div>
</template>

<style scoped>
.track {
  display: flex;
  gap: 2px;
  overflow: hidden;
  border-radius: 999px;
}

.seg {
  flex-basis: 0;
  min-width: 4px;
}

.seg.empty {
  flex-grow: 1;
  background: var(--app-surface-sunken);
}

.legend {
  display: flex;
  flex-wrap: wrap;
  gap: 6px 16px;
  margin-top: 10px;
  font-size: 12.5px;
  color: var(--app-text-secondary);
}

.item {
  display: inline-flex;
  align-items: center;
  gap: 6px;
}

.item i {
  width: 8px;
  height: 8px;
  border-radius: 2px;
}

.item b {
  color: var(--app-text);
}
</style>
