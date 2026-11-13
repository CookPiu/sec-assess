<script setup lang="ts">
import { useId } from 'vue'

withDefaults(defineProps<{ size?: number }>(), { size: 32 })

// 同一页面可能同时有多个图标（其中一个被隐藏），渐变 id 需逐个实例区分
const fillId = `brand-mark-fill-${useId()}`
</script>

<template>
  <!-- 盾牌轮廓加一条扫描线，对应“审计 + 验证” -->
  <svg class="brand-mark" :width="size" :height="size" viewBox="0 0 32 32" aria-hidden="true">
    <defs>
      <linearGradient :id="fillId" x1="0" y1="0" x2="1" y2="1">
        <stop offset="0" stop-color="#7c8dff" />
        <stop offset="1" stop-color="#3f5bf6" />
      </linearGradient>
    </defs>
    <rect width="32" height="32" rx="9" :fill="`url(#${fillId})`" />
    <path
      d="M16 6.5 23.5 9.4v6.1c0 4.6-3.1 8.3-7.5 9.9-4.4-1.6-7.5-5.3-7.5-9.9V9.4L16 6.5Z"
      fill="none"
      stroke="#fff"
      stroke-width="1.8"
      stroke-linejoin="round"
    />
    <path d="M10.5 15.5h11" stroke="#fff" stroke-width="1.8" stroke-linecap="round" opacity="0.9" />
    <circle cx="16" cy="15.5" r="2.2" fill="#fff" />
  </svg>
</template>

<style scoped>
.brand-mark {
  flex-shrink: 0;
  display: block;
}
</style>
