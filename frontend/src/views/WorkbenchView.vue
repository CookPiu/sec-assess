<script setup lang="ts">
import { useRoute } from 'vue-router'

const route = useRoute()
</script>

<template>
  <div class="page">
    <h2 class="page-title">评估工作台 · 任务 {{ route.params.taskId }}</h2>
    <el-card shadow="never">
      <el-empty />
    </el-card>
  </div>
</template>
