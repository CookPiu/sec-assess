<script setup lang="ts">
import { computed, defineAsyncComponent, ref, watch } from 'vue'

import { getFinding, getSource, type Evidence, type FindingDetail, type TaintStep } from '@/api/findings'
import { ApiError } from '@/api/http'
import type { LineMark } from '@/components/CodeViewer.vue'
import { formatTime } from '@/utils/format'
import { ACCESS_LABELS, CATEGORY_LABELS, FINDING_GROUP_META, findingGroup, SEVERITY_META } from '@/utils/labels'
import { languageOf } from '@/utils/language'

// Monaco 体积大，打开漏洞详情时才加载
const CodeViewer = defineAsyncComponent(() => import('@/components/CodeViewer.vue'))

const MAX_RAW_CHARS = 50_000

/** revision 变化时重新拉取当前漏洞（验证阶段会改写状态和等级），保留当前步骤 */
const props = defineProps<{ taskId: number; findingId: number | null; revision?: string }>()

const detail = ref<FindingDetail | null>(null)
const loading = ref(false)
const error = ref('')
const current = ref(0)
const sources = ref(new Map<string, { content?: string; error?: string }>())
let seq = 0

/** 没有污点轨迹的问题（如调试模式、硬编码密钥）以触发行作为唯一一步 */
const steps = computed<TaintStep[]>(() => {
  const d = detail.value
  if (!d) return []
  if (d.steps.length) return d.steps
  return [{ seq: 1, file: d.file, line: d.line, snippet: '', note: '触发位置' }]
})

const step = computed(() => steps.value[current.value] ?? null)

async function load(id: number | null, keepStep = false): Promise<void> {
  const mine = ++seq
  error.value = ''
  if (id === null) {
    detail.value = null
    return
  }
  loading.value = !keepStep
  try {
    const d = await getFinding(id)
    if (mine !== seq) return
    detail.value = d
    if (keepStep && current.value < steps.value.length) return
    // 默认停在触发行所在的步骤，找不到时停在最后一步（Sink）
    const list = steps.value
    const at = list.findIndex((s) => s.file === d.file && s.line === d.line)
    current.value = at >= 0 ? at : list.length - 1
  } catch (err) {
    if (mine === seq) {
      detail.value = null
      error.value = err instanceof ApiError ? err.message : '漏洞详情加载失败'
    }
  } finally {
    if (mine === seq) loading.value = false
  }
}

watch(() => props.findingId, (id) => load(id), { immediate: true })
watch(
  () => props.revision,
  () => {
    if (detail.value) void load(detail.value.id, true)
  },
)
watch(
  () => props.taskId,
  () => (sources.value = new Map()),
)

async function ensureSource(path: string): Promise<void> {
  if (sources.value.has(path)) return
  sources.value.set(path, {})
  try {
    const content = await getSource(props.taskId, path)
    sources.value.set(path, { content })
  } catch (err) {
    sources.value.set(path, { error: err instanceof ApiError ? err.message : '源码加载失败' })
  }
}

watch(
  () => step.value?.file,
  (file) => {
    if (file) void ensureSource(file)
  },
  { immediate: true },
)

const source = computed(() => (step.value ? sources.value.get(step.value.file) : undefined))

const marks = computed<LineMark[]>(() => {
  const d = detail.value
  const s = step.value
  if (!d || !s) return []
  const result: LineMark[] = steps.value
    .filter((x) => x.file === s.file)
    .map((x) => ({ line: x.line, kind: 'step', hover: `第 ${x.seq} 步：${x.note}` }))
  if (d.file === s.file) result.push({ line: d.line, kind: 'trigger', hover: '漏洞触发行' })
  result.push({ line: s.line, kind: 'current' })
  return result
})

const group = computed(() => (detail.value ? FINDING_GROUP_META[findingGroup(detail.value)] : null))

const routeText = computed(() => {
  const r = detail.value?.route
  return r ? `${r.methods.join(' / ')} ${r.path}` : ''
})

function clip(text: string | null): string {
  if (!text) return '（空）'
  return text.length > MAX_RAW_CHARS
    ? `${text.slice(0, MAX_RAW_CHARS)}\n\n…… 共 ${text.length} 字符，仅显示前 ${MAX_RAW_CHARS} 字符`
    : text
}

function caseText(ev: Evidence): string {
  const { replay: _replay, ...rest } = ev.case
  return JSON.stringify(rest, null, 2)
}

/** 重放命令存为 argv 数组（用例以 base64 作为参数），拼成一行便于复制到 docker exec */
function replayText(ev: Evidence): string | null {
  const replay = ev.case.replay
  if (typeof replay === 'string') return replay
  if (Array.isArray(replay) && replay.every((x) => typeof x === 'string')) return replay.join(' ')
  return null
}

const evidenceHint = computed(() => {
  const d = detail.value
  if (!d) return ''
  if (d.model_false_positive) return '模型判定为误报的候选不进入动态验证'
  if (['hardcoded_secret', 'weak_password_storage'].includes(d.category)) return '此类问题只能静态发现，不做动态验证'
  return '没有验证记录：动态验证尚未执行、被跳过，或该漏洞无法构造无害用例，状态保持疑似'
})
</script>

<template>
  <div v-loading="loading" class="detail">
    <el-empty v-if="!detail && !loading" :image-size="70" :description="error || '在左侧列表选择一个漏洞'" />

    <template v-if="detail">
      <div class="head">
        <div class="title">
          <span class="code">{{ detail.code }}</span>
          {{ detail.title }}
        </div>
        <div class="tags">
          <el-tag :type="SEVERITY_META[detail.severity].tag" effect="dark" disable-transitions>
            {{ SEVERITY_META[detail.severity].label }}
          </el-tag>
          <el-tag v-if="group" :type="group.tag" effect="plain" disable-transitions>{{ group.label }}</el-tag>
        </div>
      </div>

      <el-descriptions :column="2" border size="small" class="block">
        <el-descriptions-item label="类别">{{ CATEGORY_LABELS[detail.category] ?? detail.category }}</el-descriptions-item>
        <el-descriptions-item label="位置">{{ detail.file }}:{{ detail.line }}</el-descriptions-item>
        <el-descriptions-item label="入口路由">
          <template v-if="detail.route">
            <code>{{ routeText }}</code>
            <span class="muted">（{{ ACCESS_LABELS[detail.route.access] ?? detail.route.access }}可访问）</span>
          </template>
          <span v-else class="muted">无</span>
        </el-descriptions-item>
        <el-descriptions-item label="CVSS 3.1">
          <b>{{ detail.cvss_score?.toFixed(1) ?? '—' }}</b>
          <code v-if="detail.cvss_vector" class="vector">{{ detail.cvss_vector }}</code>
        </el-descriptions-item>
        <el-descriptions-item label="研判" :span="2">
          <el-tag size="small" :type="detail.judged_by === 'model' ? 'primary' : 'info'" disable-transitions>
            {{ detail.judged_by === 'model' ? '大模型研判' : '默认向量' }}
          </el-tag>
          <span class="reason">{{ detail.reason || '无' }}</span>
        </el-descriptions-item>
      </el-descriptions>

      <div class="section-title">
        <span>污点轨迹</span>
        <span class="nav">
          <el-button size="small" :disabled="current <= 0" @click="current--">上一步</el-button>
          <span class="muted">第 {{ current + 1 }} / {{ steps.length }} 步</span>
          <el-button size="small" :disabled="current >= steps.length - 1" @click="current++">下一步</el-button>
        </span>
      </div>
      <div class="trace block">
        <ol class="steps">
          <li
            v-for="(s, i) in steps"
            :key="`${s.seq}-${s.file}-${s.line}`"
            :class="{ active: i === current }"
            @click="current = i"
          >
            <span class="num">{{ i + 1 }}</span>
            <div class="body">
              <div class="note">{{ s.note }}</div>
              <div class="loc">{{ s.file }}:{{ s.line }}</div>
              <code v-if="s.snippet" class="snippet">{{ s.snippet }}</code>
            </div>
          </li>
        </ol>
        <div class="code">
          <div v-if="step" class="file">{{ step.file }}</div>
          <el-alert v-if="source?.error" :title="source.error" type="warning" :closable="false" show-icon />
          <CodeViewer
            v-else-if="source?.content !== undefined && step"
            :value="source.content"
            :language="languageOf(step.file)"
            :marks="marks"
            :reveal="step.line"
            height="380px"
          />
          <div v-else class="code-loading" v-loading="true" />
        </div>
      </div>

      <div class="section-title"><span>验证证据</span></div>
      <el-empty v-if="!detail.evidence.length" :image-size="56" :description="evidenceHint" />
      <div v-for="ev in detail.evidence" :key="ev.id" class="evidence block">
        <el-alert
          :type="ev.hit ? 'success' : 'info'"
          :closable="false"
          show-icon
          :title="ev.hit ? `命中特征：${ev.matched}` : `未命中：${ev.matched ?? '响应中未出现命中特征'}`"
          :description="`验证时间 ${formatTime(ev.created_at)}`"
        />
        <el-tabs class="raw-tabs">
          <el-tab-pane label="请求原文">
            <pre class="raw">{{ clip(ev.request_raw) }}</pre>
          </el-tab-pane>
          <el-tab-pane label="响应原文">
            <pre class="raw">{{ clip(ev.response_raw) }}</pre>
          </el-tab-pane>
          <el-tab-pane label="验证用例">
            <pre class="raw">{{ caseText(ev) }}</pre>
            <template v-if="replayText(ev)">
              <div class="muted replay-label">在沙箱容器内重放：</div>
              <pre class="raw">{{ replayText(ev) }}</pre>
            </template>
          </el-tab-pane>
        </el-tabs>
      </div>
    </template>
  </div>
</template>

<style scoped>
.detail {
  min-height: 200px;
}

.head {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 12px;
  margin-bottom: 12px;
}

.head .title {
  font-size: 16px;
  font-weight: 600;
  line-height: 1.5;
}

.head .code {
  color: var(--app-text-muted);
  font-weight: 400;
  margin-right: 6px;
}

.tags {
  display: flex;
  gap: 6px;
  flex-shrink: 0;
}

.block {
  margin-bottom: 16px;
}

.muted {
  color: var(--app-text-muted);
  font-size: 12px;
}

.vector {
  margin-left: 8px;
  font-size: 12px;
  word-break: break-all;
}

.reason {
  margin-left: 8px;
  line-height: 1.6;
}

.section-title {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin: 4px 0 10px;
  font-weight: 600;
}

.nav {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  font-weight: 400;
}

.trace {
  display: grid;
  grid-template-columns: minmax(200px, 260px) minmax(0, 1fr);
  gap: 12px;
}

@media (max-width: 900px) {
  .trace {
    grid-template-columns: minmax(0, 1fr);
  }
}

.steps {
  list-style: none;
  margin: 0;
  padding: 0;
  max-height: 404px;
  overflow-y: auto;
}

.steps li {
  display: flex;
  gap: 8px;
  padding: 8px;
  border: 1px solid var(--app-border);
  border-radius: 4px;
  margin-bottom: 6px;
  cursor: pointer;
}

.steps li.active {
  border-color: #e6a23c;
  background: #fdf6ec;
}

.num {
  flex-shrink: 0;
  width: 20px;
  height: 20px;
  border-radius: 50%;
  background: #909399;
  color: #fff;
  font-size: 12px;
  line-height: 20px;
  text-align: center;
}

.steps li.active .num {
  background: #e6a23c;
}

.body {
  min-width: 0;
}

.note {
  font-size: 13px;
  line-height: 1.4;
}

.loc {
  font-size: 12px;
  color: var(--app-text-muted);
  word-break: break-all;
}

.snippet {
  display: block;
  margin-top: 4px;
  font-size: 12px;
  white-space: pre-wrap;
  word-break: break-all;
  color: #606266;
}

.code .file {
  font-size: 12px;
  color: var(--app-text-muted);
  margin-bottom: 4px;
  font-family: Consolas, 'Cascadia Mono', monospace;
}

.code-loading {
  height: 380px;
}

.raw-tabs {
  margin-top: 8px;
}

.raw {
  margin: 0;
  max-height: 320px;
  overflow: auto;
  background: #1e1e1e;
  color: #d4d4d4;
  border-radius: 4px;
  padding: 10px 12px;
  font-family: Consolas, 'Cascadia Mono', 'Courier New', monospace;
  font-size: 12.5px;
  line-height: 1.6;
  white-space: pre-wrap;
  word-break: break-all;
}

.replay-label {
  margin: 8px 0 4px;
}
</style>
