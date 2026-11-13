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
  gap: 6px;
  height: 24px;
  padding: 0 10px;
  border-radius: 999px;
  font-size: 12.5px;
  font-weight: 600;
  white-space: nowrap;
  color: var(--c);
  background: color-mix(in srgb, var(--c) 12%, transparent);
}

.running {
  --c: var(--app-primary);
}

.completed {
  --c: var(--app-success);
}

.failed {
  --c: var(--app-danger);
}

.stopped {
  --c: var(--app-warning);
}

.dot {
  position: relative;
  width: 7px;
  height: 7px;
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
