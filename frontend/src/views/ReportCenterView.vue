<script setup lang="ts">
import { ElMessage } from 'element-plus'
import { computed, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import { ApiError } from '@/api/http'
import { exportReport, getReport, listReports, type ReportBrief, type ReportFormat, type ReportOut } from '@/api/reports'
import { useAuthStore } from '@/stores/auth'
import { formatTime } from '@/utils/format'
import { LEVEL_META } from '@/utils/labels'

const FORMATS: { key: ReportFormat; label: string }[] = [
  { key: 'md', label: 'Markdown' },
  { key: 'html', label: 'HTML' },
  { key: 'pdf', label: 'PDF' },
]

const route = useRoute()
const router = useRouter()
const auth = useAuthStore()

const reports = ref<ReportBrief[]>([])
const listLoading = ref(false)
const listError = ref('')
const report = ref<ReportOut | null>(null)
const previewLoading = ref(false)
const previewError = ref('')
const exporting = ref<ReportFormat | null>(null)

// 选中的任务放在地址栏，工作台的“查看报告”可直接定位
const selectedId = computed(() => {
  const id = Number(route.query.task)
  return Number.isInteger(id) && id > 0 ? id : null
})
const canExport = computed(() => auth.hasRole('engineer', 'developer'))

function select(taskId: number): void {
  void router.replace({ query: { task: String(taskId) } })
}

async function loadList(): Promise<void> {
  listLoading.value = true
  listError.value = ''
  try {
    reports.value = await listReports()
    if (selectedId.value === null && reports.value.length) select(reports.value[0].task_id)
  } catch (err) {
    listError.value = err instanceof ApiError ? err.message : '报告列表加载失败'
  } finally {
    listLoading.value = false
  }
}

async function loadPreview(taskId: number): Promise<void> {
  previewLoading.value = true
  previewError.value = ''
  try {
    const data = await getReport(taskId)
    if (selectedId.value === taskId) report.value = data
  } catch (err) {
    if (selectedId.value === taskId) previewError.value = err instanceof ApiError ? err.message : '报告加载失败'
  } finally {
    if (selectedId.value === taskId) previewLoading.value = false
  }
}

watch(
  selectedId,
  (taskId) => {
    report.value = null
    previewError.value = ''
    if (taskId !== null) void loadPreview(taskId)
  },
  { immediate: true },
)
onMounted(loadList)

async function doExport(format: ReportFormat): Promise<void> {
  if (selectedId.value === null) return
  exporting.value = format
  try {
    await exportReport(selectedId.value, format)
    ElMessage.success('报告已导出')
  } catch (err) {
    ElMessage.error(err instanceof ApiError ? err.message : '导出失败')
  } finally {
    exporting.value = null
  }
}
</script>

<template>
  <div class="page">
    <h2 class="page-title">报告中心</h2>
    <el-row :gutter="16">
      <el-col :xs="24" :lg="7" class="block">
        <el-card shadow="never" class="fill">
          <template #header>已完成的评估</template>
          <div v-loading="listLoading" class="list-wrap">
            <el-alert v-if="listError" type="error" :title="listError" show-icon :closable="false" />
            <el-empty v-else-if="!listLoading && !reports.length" description="还没有已完成的评估" :image-size="80" />
            <ul v-else class="list">
              <li
                v-for="item in reports"
                :key="item.task_id"
                :class="{ active: item.task_id === selectedId }"
                tabindex="0"
                @click="select(item.task_id)"
                @keydown.enter="select(item.task_id)"
              >
                <div class="row">
                  <span class="name">{{ item.project_name }}</span>
                  <el-tag size="small" :type="LEVEL_META[item.level].tag" :effect="LEVEL_META[item.level].effect">
                    {{ item.level }}
                  </el-tag>
                </div>
                <div class="sub">任务 #{{ item.task_id }} · {{ formatTime(item.finished_at) }} · 评分 {{ item.score }}</div>
              </li>
            </ul>
          </div>
        </el-card>
      </el-col>
      <el-col :xs="24" :lg="17" class="block">
        <el-card shadow="never">
          <template #header>
            <div class="preview-header">
              <span class="title">{{ report?.title ?? '报告预览' }}</span>
              <div v-if="canExport && report" class="actions">
                <el-button
                  v-for="f in FORMATS"
                  :key="f.key"
                  size="small"
                  :loading="exporting === f.key"
                  :disabled="exporting !== null && exporting !== f.key"
                  @click="doExport(f.key)"
                >
                  <el-icon v-if="exporting !== f.key"><Download /></el-icon>
                  <span>{{ f.label }}</span>
                </el-button>
              </div>
            </div>
          </template>
          <div v-loading="previewLoading" class="preview">
            <el-alert v-if="previewError" type="error" :title="previewError" show-icon :closable="false" />
            <el-empty v-else-if="selectedId === null" description="选择左侧的评估查看报告" :image-size="80" />
            <!-- 报告内容来自被评估工程，iframe 不授予脚本与同源权限 -->
            <iframe v-else-if="report" class="frame" :srcdoc="report.html" sandbox="" title="报告预览" />
          </div>
        </el-card>
      </el-col>
    </el-row>
  </div>
</template>

<style scoped>
.block {
  margin-bottom: 16px;
}

.fill {
  height: 100%;
}

.list-wrap {
  min-height: 120px;
}

.list {
  list-style: none;
  margin: 0;
  padding: 0;
}

.list li {
  padding: 10px 12px;
  border-radius: 6px;
  cursor: pointer;
  outline: none;
}

.list li + li {
  margin-top: 4px;
}

.list li:hover,
.list li:focus-visible {
  background: var(--el-fill-color-light);
}

.list li.active {
  background: var(--el-color-primary-light-9);
}

.row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
}

.name {
  font-weight: 600;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.sub {
  margin-top: 4px;
  font-size: 12px;
  color: var(--app-text-muted);
}

.preview-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 8px 16px;
}

.preview-header .title {
  font-weight: 600;
}

.actions {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.actions .el-button + .el-button {
  margin-left: 0;
}

.preview {
  min-height: 240px;
}

.frame {
  display: block;
  width: 100%;
  height: max(480px, calc(100vh - 260px));
  border: 1px solid var(--app-border);
  border-radius: 6px;
  background: #ffffff;
}
</style>
