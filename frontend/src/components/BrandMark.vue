<script setup lang="ts">
withDefaults(defineProps<{ size?: number }>(), { size: 32 })
</script>

<template>
  <!-- 盾牌轮廓加一条扫描线，对应“审计 + 验证”；颜色跟随墨色，深浅主题自动反相 -->
  <svg class="brand-mark" :width="size" :height="size" viewBox="0 0 32 32" aria-hidden="true">
    <rect width="32" height="32" rx="8" class="bg" />
    <path
      d="M16 6.5 23.5 9.4v6.1c0 4.6-3.1 8.3-7.5 9.9-4.4-1.6-7.5-5.3-7.5-9.9V9.4L16 6.5Z"
      fill="none"
      class="fg-stroke"
      stroke-width="1.8"
      stroke-linejoin="round"
    />
    <path d="M10.5 15.5h11" class="fg-stroke" stroke-width="1.8" stroke-linecap="round" />
    <circle cx="16" cy="15.5" r="2.2" class="fg-fill" />
  </svg>
</template>

<style scoped>
.brand-mark {
  flex-shrink: 0;
  display: block;
}

.bg {
  fill: var(--app-ink);
}

.fg-stroke {
  stroke: var(--app-ink-contrast);
}

.fg-fill {
  fill: var(--app-ink-contrast);
}
</style>
