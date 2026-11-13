<script setup lang="ts">
import { computed } from 'vue'

import type { Severity } from '@/api/tasks'
import { SEVERITY_META } from '@/utils/labels'

/** 严重等级徽章；传入 score 时在等级后显示 CVSS 分数 */
const props = withDefaults(
  defineProps<{ severity: Severity; score?: number | null; size?: 'small' | 'default' }>(),
  { score: undefined, size: 'small' },
)

const label = computed(() => SEVERITY_META[props.severity]?.label ?? props.severity)
</script>

<template>
  <span :class="['sev-badge', `sev-${severity}`, size]">
    <i class="dot" />
    <span>{{ label }}</span>
    <b v-if="score !== undefined" class="score">{{ score === null ? '—' : score.toFixed(1) }}</b>
  </span>
</template>

<style scoped>
.sev-badge {
  --c: var(--sev-info);
  display: inline-flex;
  align-items: center;
  gap: 5px;
  height: 22px;
  padding: 0 8px;
  border-radius: 999px;
  font-size: 12px;
  font-weight: 600;
  line-height: 1;
  white-space: nowrap;
  color: var(--c);
  background: color-mix(in srgb, var(--c) 12%, transparent);
  box-shadow: inset 0 0 0 1px color-mix(in srgb, var(--c) 28%, transparent);
}

.sev-badge.default {
  height: 26px;
  padding: 0 10px;
  font-size: 13px;
}

.sev-critical {
  --c: var(--sev-critical);
}

.sev-high {
  --c: var(--sev-high);
}

.sev-medium {
  --c: var(--sev-medium);
}

.sev-low {
  --c: var(--sev-low);
}

.dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--c);
}

.score {
  padding-left: 5px;
  margin-left: 1px;
  border-left: 1px solid color-mix(in srgb, var(--c) 35%, transparent);
  font-variant-numeric: tabular-nums;
}
</style>
