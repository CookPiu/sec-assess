<script setup lang="ts">
import { ElMessage } from 'element-plus'
import { computed, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import { ApiError } from '@/api/http'
import { exportReport, getReport, listReports, type ReportBrief, type ReportFormat, type ReportOut } from '@/api/reports'
import { useAuthStore } from '@/stores/auth'
import { formatTime } from '@/utils/format'

/** 综合安全等级对应的颜色类名 */
const LEVEL_CLASS: Record<string, string> = { 极高危: 'critical', 高危: 'high', 中危: 'medium', 安全: 'safe' }

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
    <div class="page-head">
      <div>
        <h2 class="page-title">报告中心</h2>
        <p class="page-desc">已完成评估的结构化报告，可导出 Markdown、HTML 与 PDF</p>
      </div>
    </div>
    <div class="layout">
      <section class="panel list-panel">
        <div class="panel-head">
          <span class="panel-title">
            已完成的评估
            <span v-if="reports.length" class="count-chip">{{ reports.length }}</span>
          </span>
        </div>
        <div v-loading="listLoading" class="list-wrap">
          <el-alert v-if="listError" type="error" :title="listError" show-icon :closable="false" class="list-alert" />
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
              <span :class="['score', LEVEL_CLASS[item.level]]" :title="`安全评分 ${item.score}`">
                <b class="num">{{ item.score }}</b>
              </span>
              <div class="info">
                <div class="row">
                  <span class="name">{{ item.project_name }}</span>
                  <span :class="['level', LEVEL_CLASS[item.level]]">{{ item.level }}</span>
                </div>
                <div class="sub">任务 #{{ item.task_id }} · {{ formatTime(item.finished_at) }}</div>
              </div>
            </li>
          </ul>
        </div>
      </section>

      <section class="panel preview-panel">
        <div class="panel-head">
          <span class="panel-title title">{{ report?.title ?? '报告预览' }}</span>
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
        <div v-loading="previewLoading" class="preview">
          <el-alert v-if="previewError" type="error" :title="previewError" show-icon :closable="false" />
          <el-empty v-else-if="selectedId === null" description="选择左侧的评估查看报告" :image-size="80" />
          <!-- 报告内容来自被评估工程，iframe 不授予脚本与同源权限 -->
          <iframe v-else-if="report" class="frame" :srcdoc="report.html" sandbox="" title="报告预览" />
        </div>
      </section>
    </div>
  </div>
</template>

<style scoped>
.layout {
  display: grid;
  grid-template-columns: minmax(280px, 340px) minmax(0, 1fr);
  gap: 20px;
  align-items: start;
}

.list-panel {
  position: sticky;
  top: 16px;
  overflow: hidden;
}

.list-wrap {
  min-height: 120px;
  max-height: calc(100vh - 120px);
  overflow-y: auto;
}

.list-alert {
  margin: 14px;
  width: auto;
}

.list {
  list-style: none;
  margin: 0;
  padding: 0;
}

.list li {
  position: relative;
  display: flex;
  align-items: center;
  gap: 14px;
  padding: 14px 18px;
  border-bottom: 1px solid var(--app-border);
  cursor: pointer;
  outline: none;
  transition: background-color 0.15s;
}

.list li:hover,
.list li:focus-visible {
  background: var(--app-surface-alt);
}

.list li.active {
  background: var(--app-ink-soft);
  box-shadow: inset 2px 0 0 var(--app-ink);
}

/* 安全评分：数字按综合等级着色 */
.score {
  flex-shrink: 0;
  width: 40px;
  text-align: right;
  color: var(--c, var(--app-text-muted));
}

.score b {
  font-family: var(--app-font-display);
  font-size: 24px;
  font-weight: 500;
  letter-spacing: -0.02em;
}

.critical {
  --c: var(--sev-critical);
}

.high {
  --c: var(--sev-high);
}

.medium {
  --c: var(--sev-medium);
}

.safe {
  --c: var(--app-success);
}

.info {
  flex: 1;
  min-width: 0;
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

.level {
  flex-shrink: 0;
  padding: 0 7px;
  border-radius: 4px;
  font-size: 12px;
  font-weight: 600;
  line-height: 20px;
  color: var(--c, var(--app-text-muted));
  background: color-mix(in srgb, var(--c, var(--app-text-muted)) 10%, transparent);
}

/* 极高危用实心底色与高危区分 */
.level.critical {
  color: #ffffff;
  background: var(--sev-critical);
}

.sub {
  margin-top: 4px;
  font-size: 12px;
  color: var(--app-text-muted);
}

.preview-panel {
  min-width: 0;
}

.preview-panel .panel-head {
  flex-wrap: wrap;
  padding-top: 10px;
  padding-bottom: 10px;
}

.title {
  min-width: 0;
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
  padding: 16px;
}

.frame {
  display: block;
  width: 100%;
  height: max(480px, calc(100vh - 240px));
  border: 1px solid var(--app-border);
  border-radius: var(--app-radius-sm);
  /* 报告按打印版式渲染，在深色界面下也保持白底 */
  background: #ffffff;
}

@media (max-width: 1023px) {
  .layout {
    grid-template-columns: minmax(0, 1fr);
  }

  .list-panel {
    position: static;
  }

  .list-wrap {
    max-height: 360px;
  }
}

@media (max-width: 767px) {
  .preview {
    padding: 10px;
  }
}
</style>
