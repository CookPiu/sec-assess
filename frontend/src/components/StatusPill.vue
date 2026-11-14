<script setup lang="ts">
import type { TaskStatus } from '@/api/tasks'
import { STATUS_META } from '@/utils/labels'

defineProps<{ status: TaskStatus }>()
</script>

<template>
  <span :class="['status-pill', status]">
    <i class="dot" />
    {{ STATUS_META[status].label }}
  </span>
</template>

<style scoped>
.status-pill {
  --c: var(--app-text-muted);
  display: inline-flex;
  align-items: center;
  gap: 7px;
  height: 24px;
  padding: 0 9px;
  border-radius: 999px;
  font-size: 12.5px;
  font-weight: 500;
  white-space: nowrap;
  color: var(--app-text-secondary);
  box-shadow: inset 0 0 0 1px var(--app-border);
}

.running {
  --c: var(--app-primary);
  color: var(--app-primary);
  box-shadow: inset 0 0 0 1px color-mix(in srgb, var(--app-primary) 35%, transparent);
}

.completed {
  --c: var(--app-success);
}

.failed {
  --c: var(--app-danger);
  color: var(--app-danger);
}

.stopped {
  --c: var(--app-warning);
}

.dot {
  position: relative;
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--c);
}

.running .dot::after {
  content: '';
  position: absolute;
  inset: -3px;
  border-radius: 50%;
  border: 1.5px solid var(--c);
  animation: ping 1.4s ease-out infinite;
}

@keyframes ping {
  from {
    transform: scale(0.6);
    opacity: 0.9;
  }
  to {
    transform: scale(1.6);
    opacity: 0;
  }
}
</style>
