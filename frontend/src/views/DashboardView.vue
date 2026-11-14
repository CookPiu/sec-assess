<script setup lang="ts">
import { ElMessage, ElMessageBox } from 'element-plus'
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useRouter } from 'vue-router'

import { ApiError } from '@/api/http'
import {
  createTask,
  listProjects,
  type ProjectOut,
  type SeverityCounts,
  type TaskOut,
  type TaskStatus,
} from '@/api/tasks'
import SeverityBar from '@/components/SeverityBar.vue'
import StageTrack from '@/components/StageTrack.vue'
import StatusPill from '@/components/StatusPill.vue'
import { useAuthStore } from '@/stores/auth'
import { formatTime } from '@/utils/format'
import { ACTIVE_STATUSES, SEVERITIES, STAGE_LABELS, STATUS_META } from '@/utils/labels'
import NewTaskDialog from '@/views/dashboard/NewTaskDialog.vue'

const POLL_MS = 5000
const VIEW_KEY = 'sec-assess.dashboard-view'

const auth = useAuthStore()
const router = useRouter()
const projects = ref<ProjectOut[]>([])
const loading = ref(true)
const loadError = ref('')
const dialogVisible = ref(false)
const keyword = ref('')
const view = ref<'cards' | 'table'>(readView())
const canCreate = computed(() => auth.hasRole('engineer'))
let timer: number | undefined

function readView(): 'cards' | 'table' {
  try {
    return localStorage.getItem(VIEW_KEY) === 'table' ? 'table' : 'cards'
  } catch {
    return 'cards'
  }
}

watch(view, (value) => {
  try {
    localStorage.setItem(VIEW_KEY, value)
  } catch {
    // 记不住视图只影响下次打开时的默认值
  }
})

const hasActive = computed(() =>
  projects.value.some((p) => p.latest_task && ACTIVE_STATUSES.includes(p.latest_task.status)),
)

async function load(): Promise<void> {
  try {
    projects.value = await listProjects()
    loadError.value = ''
  } catch (err) {
    loadError.value = err instanceof ApiError ? err.message : '加载项目列表失败'
  } finally {
    loading.value = false
  }
}

// 有排队或评估中的任务时定时刷新
function schedule(): void {
  timer = window.setTimeout(async () => {
    if (hasActive.value && document.visibilityState === 'visible') await load()
    schedule()
  }, POLL_MS)
}

onMounted(async () => {
  await load()
  schedule()
})
onBeforeUnmount(() => window.clearTimeout(timer))

const latestTasks = computed(() => projects.value.map((p) => p.latest_task).filter((t) => t !== null))

const totals = computed<SeverityCounts>(() => {
  const sum: SeverityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  for (const t of latestTasks.value) for (const s of SEVERITIES) sum[s.key] += t.counts[s.key]
  return sum
})

const severeTotal = computed(() => totals.value.critical + totals.value.high)
const allTotal = computed(() => SEVERITIES.reduce((n, s) => n + totals.value[s.key], 0))

const STATUS_ORDER: TaskStatus[] = ['running', 'created', 'completed', 'failed', 'stopped']
const statusCounts = computed(() =>
  STATUS_ORDER.map((status) => ({
    status,
    label: STATUS_META[status].label,
    count: latestTasks.value.filter((t) => t.status === status).length,
  })),
)

const totalLoc = computed(() => projects.value.reduce((n, p) => n + (p.loc ?? 0), 0))
const riskyProjects = computed(
  () => projects.value.filter((p) => p.latest_task && p.latest_task.counts.critical + p.latest_task.counts.high > 0).length,
)

const sourceCounts = computed(() => ({
  git: projects.value.filter((p) => p.source_type === 'git').length,
  zip: projects.value.filter((p) => p.source_type === 'zip').length,
}))

const filtered = computed(() => {
  const word = keyword.value.trim().toLowerCase()
  if (!word) return projects.value
  return projects.value.filter((p) => `${p.name} ${p.source_url ?? ''} ${techLabel(p)}`.toLowerCase().includes(word))
})

function techLabel(p: ProjectOut): string {
  const stack = p.tech_stack
  if (!stack) return '—'
  const fw = stack.frameworks.map((f) => (f.version ? `${f.name} ${f.version}` : f.name))
  return [stack.primary_language, ...fw].filter(Boolean).join(' · ') || '—'
}

function sourceText(p: ProjectOut): string {
  return p.source_type === 'git' ? (p.source_url ?? 'Git 仓库') : 'zip 上传'
}

function openTask(task: Pick<TaskOut, 'id'>): void {
  void router.push({ name: 'workbench', params: { taskId: task.id } })
}

function isActive(p: ProjectOut): boolean {
  return !!p.latest_task && ACTIVE_STATUSES.includes(p.latest_task.status)
}

async function reassess(p: ProjectOut): Promise<void> {
  try {
    await ElMessageBox.confirm(`对「${p.name}」重新发起一次评估？`, '重新评估', { type: 'info' })
  } catch {
    return
  }
  try {
    openTask(await createTask({ kind: 'project', projectId: p.id }))
  } catch (err) {
    ElMessage.error(err instanceof ApiError ? err.message : '创建失败')
  }
}
</script>

<template>
  <div class="page">
    <div class="page-head">
      <div>
        <h2 class="page-title">项目概览</h2>
        <p class="page-desc">风险数字取各项目最近一次评估的结果</p>
      </div>
      <el-button v-if="canCreate" type="primary" size="large" @click="dialogVisible = true">
        <el-icon><Plus /></el-icon>
        <span>新建评估</span>
      </el-button>
    </div>

    <el-alert v-if="loadError" :title="loadError" type="error" show-icon :closable="false" class="block" />

    <section class="overview panel">
      <div class="cell risk">
        <div class="eyebrow">严重与高危漏洞</div>
        <div class="big num">
          {{ severeTotal }}<small>/ {{ allTotal }}</small>
        </div>
        <div class="risk-note">{{ riskyProjects }} 个项目存在严重或高危问题</div>
        <SeverityBar :counts="totals" legend :height="6" class="risk-bar" />
      </div>

      <div class="cell states">
        <div class="eyebrow">评估状态</div>
        <ul>
          <li v-for="s in statusCounts" :key="s.status" :class="[s.status, { zero: !s.count }]">
            <i class="dot" />
            <span>{{ s.label }}</span>
            <b class="num">{{ s.count }}</b>
          </li>
        </ul>
      </div>

      <div class="cell scale">
        <div class="eyebrow">项目规模</div>
        <dl class="scale-row">
          <div>
            <dt>项目</dt>
            <dd class="num">{{ projects.length }}</dd>
          </div>
          <div>
            <dt>代码行</dt>
            <dd class="num">{{ totalLoc.toLocaleString() }}</dd>
          </div>
        </dl>
        <div class="sources">
          <span>Git 仓库 <b class="num">{{ sourceCounts.git }}</b></span>
          <span>zip 上传 <b class="num">{{ sourceCounts.zip }}</b></span>
        </div>
      </div>
    </section>

    <section class="panel">
      <div class="panel-head">
        <span class="panel-title">
          全部项目
          <span class="count-chip">{{ filtered.length }}</span>
        </span>
        <div class="tools">
          <el-input v-model="keyword" placeholder="按名称、地址或技术栈筛选" clearable class="search">
            <template #prefix>
              <el-icon><Search /></el-icon>
            </template>
          </el-input>
          <el-radio-group v-model="view" class="view-switch">
            <el-radio-button value="cards" aria-label="卡片视图">
              <el-icon><Grid /></el-icon>
            </el-radio-button>
            <el-radio-button value="table" aria-label="表格视图">
              <el-icon><List /></el-icon>
            </el-radio-button>
          </el-radio-group>
        </div>
      </div>

      <div v-loading="loading" class="panel-body projects">
        <el-empty
          v-if="!loading && !filtered.length"
          :image-size="80"
          :description="projects.length ? '没有符合筛选条件的项目' : '还没有项目，点击右上角新建评估'"
        />

        <div v-else-if="view === 'cards'" class="cards">
          <article v-for="p in filtered" :key="p.id" :class="['card', { live: isActive(p) }]">
            <header class="card-head">
              <div class="card-title">
                <RouterLink
                  v-if="p.latest_task"
                  :to="{ name: 'workbench', params: { taskId: p.latest_task.id } }"
                  class="name"
                >
                  {{ p.name }}
                </RouterLink>
                <span v-else class="name">{{ p.name }}</span>
                <span class="sub" :title="sourceText(p)">{{ sourceText(p) }}</span>
              </div>
              <StatusPill v-if="p.latest_task" :status="p.latest_task.status" />
            </header>

            <template v-if="p.latest_task">
              <div class="progress">
                <StageTrack compact :status="p.latest_task.status" :current-stage="p.latest_task.current_stage" />
                <span class="muted">
                  <template v-if="p.latest_task.status === 'running' && p.latest_task.current_stage">
                    {{ STAGE_LABELS[p.latest_task.current_stage] }}
                  </template>
                  <template v-else-if="p.latest_task.status === 'created'">等待前面的评估结束</template>
                  <template v-else>{{ formatTime(p.latest_task.finished_at ?? p.latest_task.created_at) }}</template>
                </span>
              </div>
              <SeverityBar :counts="p.latest_task.counts" legend :height="4" />
            </template>
            <div v-else class="muted">还没有评估记录</div>

            <footer class="card-foot">
              <span class="facts">
                <span>{{ techLabel(p) }}</span>
                <span v-if="p.loc" class="num">{{ p.loc.toLocaleString() }} 行</span>
              </span>
              <span class="actions">
                <el-button
                  v-if="canCreate"
                  link
                  :disabled="isActive(p)"
                  @click="reassess(p)"
                >
                  <el-icon><RefreshRight /></el-icon>
                  <span>重新评估</span>
                </el-button>
                <el-button v-if="p.latest_task" type="primary" link @click="openTask(p.latest_task)">
                  <span>工作台</span>
                  <el-icon><Right /></el-icon>
                </el-button>
              </span>
            </footer>
          </article>
        </div>

        <el-table v-else :data="filtered">
          <el-table-column label="项目" min-width="180">
            <template #default="{ row }: { row: ProjectOut }">
              <div class="name">{{ row.name }}</div>
              <div class="sub">{{ sourceText(row) }}</div>
            </template>
          </el-table-column>
          <el-table-column label="技术栈" min-width="150">
            <template #default="{ row }: { row: ProjectOut }">{{ techLabel(row) }}</template>
          </el-table-column>
          <el-table-column label="代码行数" width="100" align="right">
            <template #default="{ row }: { row: ProjectOut }">
              <span class="num">{{ row.loc?.toLocaleString() ?? '—' }}</span>
            </template>
          </el-table-column>
          <el-table-column label="最新评估时间" width="150">
            <template #default="{ row }: { row: ProjectOut }">{{ formatTime(row.last_assessed_at) }}</template>
          </el-table-column>
          <el-table-column label="最近一次评估" min-width="240">
            <template #default="{ row }: { row: ProjectOut }">
              <div v-if="row.latest_task" class="table-state">
                <StatusPill :status="row.latest_task.status" />
                <SeverityBar :counts="row.latest_task.counts" class="table-bar" />
              </div>
              <span v-else class="sub">—</span>
            </template>
          </el-table-column>
          <el-table-column label="操作" width="170" fixed="right">
            <template #default="{ row }: { row: ProjectOut }">
              <el-button v-if="row.latest_task" link type="primary" @click="openTask(row.latest_task)">工作台</el-button>
              <el-button v-if="canCreate" link type="primary" :disabled="isActive(row)" @click="reassess(row)">
                重新评估
              </el-button>
            </template>
          </el-table-column>
        </el-table>
      </div>
    </section>

    <NewTaskDialog v-model="dialogVisible" @created="openTask" />
  </div>
</template>

<style scoped>
.block {
  margin-bottom: 16px;
}

/* 概览：一条横向的数据带，三格之间用细线分隔 */
.overview {
  display: grid;
  grid-template-columns: minmax(0, 1.7fr) minmax(0, 1fr) minmax(0, 1fr);
  margin-bottom: 28px;
}

.cell {
  display: flex;
  flex-direction: column;
  min-width: 0;
  padding: 22px 24px;
}

.cell + .cell {
  border-left: 1px solid var(--app-border);
}

.big {
  margin: 14px 0 4px;
  font-family: var(--app-font-display);
  font-size: 56px;
  font-weight: 500;
  line-height: 1;
  letter-spacing: -0.035em;
  color: var(--app-text);
}

.big small {
  margin-left: 8px;
  font-size: 20px;
  font-weight: 400;
  letter-spacing: 0;
  color: var(--app-text-muted);
}

.risk-note {
  font-size: 13px;
  color: var(--app-text-secondary);
}

.risk-bar {
  margin-top: auto;
  padding-top: 22px;
}

.states ul {
  list-style: none;
  margin: 12px 0 0;
  padding: 0;
}

.states li {
  --c: var(--app-text-muted);
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 6px 0;
  font-size: 13px;
  color: var(--app-text-secondary);
}

.states li + li {
  border-top: 1px solid var(--app-border);
}

.states li.running {
  --c: var(--app-primary);
}

.states li.completed {
  --c: var(--app-success);
}

.states li.failed {
  --c: var(--app-danger);
}

.states li.stopped {
  --c: var(--app-warning);
}

.states li.zero {
  opacity: 0.5;
}

.states .dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--c);
}

.states b {
  margin-left: auto;
  font-size: 14px;
  font-weight: 600;
  color: var(--app-text);
}

.scale-row {
  display: grid;
  grid-template-columns: 1fr;
  gap: 16px;
  margin: 14px 0 0;
}

.scale-row dt {
  font-size: 12.5px;
  color: var(--app-text-muted);
}

.scale-row dd {
  margin: 2px 0 0;
  font-family: var(--app-font-display);
  font-size: 30px;
  font-weight: 500;
  line-height: 1.1;
  letter-spacing: -0.02em;
}

.sources {
  display: flex;
  flex-wrap: wrap;
  gap: 4px 16px;
  margin-top: auto;
  padding-top: 18px;
  font-size: 12.5px;
  color: var(--app-text-muted);
}

.sources b {
  margin-left: 2px;
  font-weight: 600;
  color: var(--app-text);
}

.tools {
  display: flex;
  align-items: center;
  gap: 10px;
}

.search {
  width: 260px;
}

.view-switch :deep(.el-radio-button__inner) {
  padding: 8px 10px;
}

.projects {
  min-height: 160px;
  padding: 0;
}

/* 卡片网格：卡片之间共用细线，不留缝隙 */
.cards {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(min(100%, 320px), 1fr));
  margin: 0 -1px -1px 0;
}

.card {
  position: relative;
  display: flex;
  flex-direction: column;
  gap: 16px;
  padding: 20px;
  border-right: 1px solid var(--app-border);
  border-bottom: 1px solid var(--app-border);
  transition: background-color 0.15s;
}

.card:hover {
  background: var(--app-surface-alt);
}

.card.live::before {
  content: '';
  position: absolute;
  inset: 0 auto 0 0;
  width: 2px;
  background: var(--app-primary);
}

.card-head {
  display: flex;
  align-items: flex-start;
  gap: 10px;
}

.card-title {
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 2px;
  min-width: 0;
}

.name {
  font-weight: 600;
  font-size: 15.5px;
  letter-spacing: -0.005em;
  color: var(--app-text);
  text-decoration: none;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

a.name:hover {
  text-decoration: underline;
  text-underline-offset: 3px;
}

.sub {
  font-size: 12px;
  color: var(--app-text-muted);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.progress {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.card-foot {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  margin-top: auto;
  padding-top: 14px;
  border-top: 1px dashed var(--app-border);
}

.facts {
  display: flex;
  gap: 10px;
  min-width: 0;
  font-size: 12.5px;
  color: var(--app-text-muted);
  overflow: hidden;
  white-space: nowrap;
}

.facts span:first-child {
  overflow: hidden;
  text-overflow: ellipsis;
}

.actions {
  display: flex;
  flex-shrink: 0;
}

.actions .el-button + .el-button {
  margin-left: 14px;
}

.el-table {
  padding: 0 8px;
}

.table-state {
  display: flex;
  align-items: center;
  gap: 10px;
}

.table-bar {
  flex: 1;
  max-width: 160px;
}

@media (max-width: 1199px) {
  .overview {
    grid-template-columns: 1fr 1fr;
  }

  .risk {
    grid-column: 1 / -1;
    border-bottom: 1px solid var(--app-border);
  }

  .risk + .cell {
    border-left: 0;
  }
}

@media (max-width: 767px) {
  .overview {
    grid-template-columns: 1fr;
  }

  .cell + .cell {
    border-left: 0;
    border-top: 1px solid var(--app-border);
  }

  .risk {
    border-bottom: 0;
  }

  .scale-row {
    grid-template-columns: 1fr 1fr;
  }

  .panel-head {
    flex-wrap: wrap;
    padding-top: 10px;
    padding-bottom: 10px;
  }

  .tools {
    width: 100%;
  }

  .search {
    flex: 1;
    width: auto;
  }

  .big {
    font-size: 44px;
  }
}
</style>
