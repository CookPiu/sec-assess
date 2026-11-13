<script setup lang="ts">
import { computed, defineAsyncComponent, ref, watch } from 'vue'

import { getFinding, getSource, type Evidence, type FindingDetail, type TaintStep } from '@/api/findings'
import { ApiError } from '@/api/http'
import type { LineMark } from '@/components/CodeViewer.vue'
import SeverityBadge from '@/components/SeverityBadge.vue'
import { describeVector } from '@/utils/cvss'
import { formatTime } from '@/utils/format'
import { ACCESS_LABELS, CATEGORY_LABELS, FINDING_GROUP_META, findingGroup } from '@/utils/labels'
import { languageOf } from '@/utils/language'
import PatchPanel from '@/views/workbench/PatchPanel.vue'

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

const group = computed(() => (detail.value ? findingGroup(detail.value) : null))
const metrics = computed(() => describeVector(detail.value?.cvss_vector))

/** 轨迹的第一步是外部输入，最后一步是触发点，中间为传播 */
function stepRole(i: number): string {
  const n = steps.value.length
  if (n === 1) return '触发'
  if (i === 0) return '来源'
  return i === n - 1 ? '触发' : '传播'
}

function clip(text: string | null): string {
  if (!text) return '（空）'
  return text.length > MAX_RAW_CHARS
    ? `${text.slice(0, MAX_RAW_CHARS)}\n\n…… 共 ${text.length} 字符，仅显示前 ${MAX_RAW_CHARS} 字符`
    : text
}

/** 把响应原文按命中特征切段，命中的片段在界面上高亮；不用 v-html，原文按纯文本渲染 */
function highlight(text: string | null, needle: string | null, hit: boolean): { text: string; mark: boolean }[] {
  const body = clip(text)
  if (!hit || !needle || needle.length < 4 || !body.includes(needle)) return [{ text: body, mark: false }]
  const parts = body.split(needle)
  return parts.flatMap((part, i) => (i === 0 ? [{ text: part, mark: false }] : [{ text: needle, mark: true }, { text: part, mark: false }]))
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
      <header class="head">
        <div class="head-main">
          <div class="head-tags">
            <span class="code mono">{{ detail.code }}</span>
            <span v-if="group" :class="['group-tag', group]">{{ FINDING_GROUP_META[group].label }}</span>
            <span class="cat">{{ CATEGORY_LABELS[detail.category] ?? detail.category }}</span>
          </div>
          <h3 class="title">{{ detail.title }}</h3>
        </div>
        <div :class="['score-card', `sev-${detail.severity}`]">
          <b class="num">{{ detail.cvss_score?.toFixed(1) ?? '—' }}</b>
          <SeverityBadge :severity="detail.severity" />
        </div>
      </header>

      <div class="facts">
        <div class="fact">
          <span class="fact-label">触发位置</span>
          <span class="mono fact-value">{{ detail.file }}:{{ detail.line }}</span>
        </div>
        <div class="fact">
          <span class="fact-label">入口路由</span>
          <span v-if="detail.route" class="fact-value route">
            <span v-for="m in detail.route.methods" :key="m" class="method">{{ m }}</span>
            <span class="mono">{{ detail.route.path }}</span>
            <span class="access">{{ ACCESS_LABELS[detail.route.access] ?? detail.route.access }}可访问</span>
          </span>
          <span v-else class="fact-value muted">无</span>
        </div>
      </div>

      <div v-if="metrics.length" class="vector">
        <div class="vector-head">
          <span class="fact-label">CVSS 3.1 基础指标</span>
          <code class="vector-raw">{{ detail.cvss_vector }}</code>
        </div>
        <div class="metrics">
          <span v-for="m in metrics" :key="m.key" :class="['metric', { risky: m.risky }]" :title="`${m.key}:${m.value}`">
            <span class="m-label">{{ m.label }}</span>
            <b>{{ m.text }}</b>
          </span>
        </div>
      </div>
      <div v-else-if="detail.cvss_vector" class="vector">
        <span class="fact-label">CVSS 3.1</span>
        <code class="vector-raw">{{ detail.cvss_vector }}</code>
      </div>

      <div class="judge">
        <span :class="['judge-tag', detail.judged_by]">
          <el-icon><component :is="detail.judged_by === 'model' ? 'MagicStick' : 'Operation'" /></el-icon>
          {{ detail.judged_by === 'model' ? '大模型研判' : '默认向量' }}
        </span>
        <p>{{ detail.reason || '无' }}</p>
      </div>

      <div class="section-title">
        <span>污点轨迹</span>
        <span class="nav">
          <el-button size="small" circle :disabled="current <= 0" aria-label="上一步" @click="current--">
            <el-icon><ArrowUp /></el-icon>
          </el-button>
          <span class="muted num">{{ current + 1 }} / {{ steps.length }}</span>
          <el-button
            size="small"
            circle
            :disabled="current >= steps.length - 1"
            aria-label="下一步"
            @click="current++"
          >
            <el-icon><ArrowDown /></el-icon>
          </el-button>
        </span>
      </div>
      <div class="trace">
        <ol class="steps">
          <li
            v-for="(s, i) in steps"
            :key="`${s.seq}-${s.file}-${s.line}`"
            :class="{ active: i === current, last: i === steps.length - 1 }"
            tabindex="0"
            @click="current = i"
            @keydown.enter="current = i"
          >
            <span class="rail"><span class="node">{{ i + 1 }}</span></span>
            <div class="body">
              <div class="step-top">
                <span :class="['role', stepRole(i)]">{{ stepRole(i) }}</span>
                <span class="loc mono">{{ s.file }}:{{ s.line }}</span>
              </div>
              <div class="note">{{ s.note }}</div>
              <code v-if="s.snippet" class="snippet">{{ s.snippet }}</code>
            </div>
          </li>
        </ol>
        <div class="code">
          <div v-if="step" class="file mono">
            <el-icon><Document /></el-icon>
            {{ step.file }}
          </div>
          <el-alert v-if="source?.error" :title="source.error" type="warning" :closable="false" show-icon />
          <CodeViewer
            v-else-if="source?.content !== undefined && step"
            :value="source.content"
            :language="languageOf(step.file)"
            :marks="marks"
            :reveal="step.line"
            height="380px"
          />
          <div v-else v-loading="true" class="code-loading" />
        </div>
      </div>

      <div class="section-title"><span>验证证据</span></div>
      <div v-if="!detail.evidence.length" class="no-evidence">
        <el-icon><InfoFilled /></el-icon>
        {{ evidenceHint }}
      </div>
      <div v-for="ev in detail.evidence" :key="ev.id" :class="['evidence', { hit: ev.hit }]">
        <div class="ev-head">
          <span class="ev-icon">
            <el-icon><component :is="ev.hit ? 'CircleCheckFilled' : 'RemoveFilled'" /></el-icon>
          </span>
          <div class="ev-text">
            <b>{{ ev.hit ? '命中特征' : '未命中' }}</b>
            <code v-if="ev.hit" class="marker">{{ ev.matched }}</code>
            <span v-else>{{ ev.matched ?? '响应中未出现命中特征' }}</span>
          </div>
          <span class="muted">{{ formatTime(ev.created_at) }}</span>
        </div>
        <el-tabs class="raw-tabs">
          <el-tab-pane label="请求原文">
            <pre class="term raw">{{ clip(ev.request_raw) }}</pre>
          </el-tab-pane>
          <el-tab-pane label="响应原文">
            <pre class="term raw"><template v-for="(part, i) in highlight(ev.response_raw, ev.matched, ev.hit)" :key="i"><mark v-if="part.mark">{{ part.text }}</mark><template v-else>{{ part.text }}</template></template></pre>
          </el-tab-pane>
          <el-tab-pane label="验证用例">
            <pre class="term raw">{{ caseText(ev) }}</pre>
            <template v-if="replayText(ev)">
              <div class="muted replay-label">在沙箱容器内重放：</div>
              <pre class="term raw">{{ replayText(ev) }}</pre>
            </template>
          </el-tab-pane>
        </el-tabs>
      </div>

      <!-- 只为已验证漏洞生成补丁（FR-012） -->
      <template v-if="detail.status === 'verified'">
        <div class="section-title"><span>修复补丁</span></div>
        <PatchPanel :finding-id="detail.id" :revision="revision" />
      </template>
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
  gap: 16px;
  margin-bottom: 16px;
}

.head-main {
  min-width: 0;
}

.head-tags {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 6px 8px;
  font-size: 12.5px;
}

.code {
  color: var(--app-text-muted);
}

.group-tag {
  --c: var(--app-text-muted);
  padding: 1px 8px;
  border-radius: 6px;
  font-weight: 600;
  color: var(--c);
  background: color-mix(in srgb, var(--c) 12%, transparent);
}

.group-tag.verified {
  --c: var(--app-danger);
}

.group-tag.unverified {
  --c: var(--app-warning);
}

.cat {
  color: var(--app-text-secondary);
}

.title {
  margin: 6px 0 0;
  font-size: 18px;
  font-weight: 650;
  line-height: 1.45;
  word-break: break-all;
}

.score-card {
  --c: var(--sev-info);
  flex-shrink: 0;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 6px;
  min-width: 84px;
  padding: 10px 12px;
  border-radius: 12px;
  background: color-mix(in srgb, var(--c) 9%, var(--app-surface));
  box-shadow: inset 0 0 0 1px color-mix(in srgb, var(--c) 25%, transparent);
}

.score-card b {
  font-size: 28px;
  line-height: 1;
  font-weight: 750;
  color: var(--c);
}

.score-card.sev-critical {
  --c: var(--sev-critical);
}

.score-card.sev-high {
  --c: var(--sev-high);
}

.score-card.sev-medium {
  --c: var(--sev-medium);
}

.score-card.sev-low {
  --c: var(--sev-low);
}

.facts {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(0, 1.6fr);
  gap: 10px;
  margin-bottom: 10px;
}

.fact,
.vector,
.judge {
  padding: 10px 12px;
  border-radius: 10px;
  background: var(--app-surface-alt);
  border: 1px solid var(--app-border);
}

.fact {
  display: flex;
  flex-direction: column;
  gap: 4px;
  min-width: 0;
}

.fact-label {
  font-size: 12px;
  color: var(--app-text-muted);
}

.fact-value {
  font-size: 13px;
  word-break: break-all;
}

.route {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 4px 8px;
}

.method {
  padding: 0 6px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 700;
  line-height: 18px;
  font-family: var(--app-font-mono);
  color: var(--app-primary);
  background: var(--app-primary-soft);
}

.access {
  font-size: 12px;
  color: var(--app-text-muted);
}

.vector {
  margin-bottom: 10px;
}

.vector-head {
  display: flex;
  flex-wrap: wrap;
  justify-content: space-between;
  gap: 4px 12px;
  margin-bottom: 8px;
}

.vector-raw {
  font-size: 11.5px;
  color: var(--app-text-muted);
  word-break: break-all;
}

.metrics {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 6px;
}

.metric {
  display: flex;
  flex-direction: column;
  gap: 1px;
  padding: 6px 8px;
  border-radius: 8px;
  background: var(--app-surface);
  border: 1px solid var(--app-border);
}

.metric.risky {
  border-color: color-mix(in srgb, var(--app-danger) 35%, var(--app-border));
  background: color-mix(in srgb, var(--app-danger) 6%, var(--app-surface));
}

.m-label {
  font-size: 11.5px;
  color: var(--app-text-muted);
}

.metric b {
  font-size: 13px;
}

.metric.risky b {
  color: var(--app-danger);
}

.judge {
  display: flex;
  gap: 10px;
  align-items: flex-start;
}

.judge p {
  margin: 0;
  font-size: 13px;
  line-height: 1.7;
  color: var(--app-text-secondary);
}

.judge-tag {
  flex-shrink: 0;
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 2px 8px;
  border-radius: 6px;
  font-size: 12px;
  font-weight: 600;
  color: var(--app-text-secondary);
  background: var(--app-surface-sunken);
}

.judge-tag.model {
  color: var(--app-primary);
  background: var(--app-primary-soft);
}

.nav {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  font-weight: 400;
}

.trace {
  display: grid;
  grid-template-columns: minmax(220px, 290px) minmax(0, 1fr);
  gap: 14px;
}

.steps {
  list-style: none;
  margin: 0;
  padding: 0;
  max-height: 412px;
  overflow-y: auto;
}

.steps li {
  display: flex;
  gap: 10px;
  cursor: pointer;
  outline: none;
}

.rail {
  position: relative;
  flex-shrink: 0;
  display: flex;
  justify-content: center;
  width: 24px;
}

/* 步骤之间的竖线 */
.rail::after {
  content: '';
  position: absolute;
  top: 26px;
  bottom: -2px;
  width: 2px;
  background: var(--app-border);
}

.steps li.last .rail::after {
  display: none;
}

.node {
  position: relative;
  z-index: 1;
  display: grid;
  place-items: center;
  width: 24px;
  height: 24px;
  border-radius: 50%;
  font-size: 12px;
  font-weight: 700;
  color: var(--app-text-secondary);
  background: var(--app-surface);
  box-shadow: inset 0 0 0 1.5px var(--app-border-strong);
}

.steps li.active .node {
  color: #fff;
  background: var(--app-warning);
  box-shadow: 0 0 0 4px color-mix(in srgb, var(--app-warning) 22%, transparent);
}

.body {
  flex: 1;
  min-width: 0;
  margin-bottom: 8px;
  padding: 8px 10px;
  border-radius: 10px;
  border: 1px solid transparent;
  transition: background-color 0.15s, border-color 0.15s;
}

.steps li:hover .body {
  background: var(--app-surface-alt);
}

.steps li.active .body {
  border-color: color-mix(in srgb, var(--app-warning) 45%, transparent);
  background: var(--app-warning-soft);
}

.steps li:focus-visible .body {
  outline: 2px solid var(--app-primary);
}

.step-top {
  display: flex;
  align-items: center;
  gap: 6px;
  min-width: 0;
}

.role {
  flex-shrink: 0;
  padding: 0 6px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 700;
  line-height: 18px;
  color: var(--app-text-secondary);
  background: var(--app-surface-sunken);
}

.role.来源 {
  color: var(--app-primary);
  background: var(--app-primary-soft);
}

.role.触发 {
  color: var(--app-danger);
  background: var(--app-danger-soft);
}

.loc {
  font-size: 11.5px;
  color: var(--app-text-muted);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.note {
  margin-top: 4px;
  font-size: 13px;
  line-height: 1.45;
}

.snippet {
  display: block;
  margin-top: 4px;
  font-size: 11.5px;
  white-space: pre-wrap;
  word-break: break-all;
  color: var(--app-text-secondary);
}

.code .file {
  display: flex;
  align-items: center;
  gap: 4px;
  font-size: 12px;
  color: var(--app-text-muted);
  margin-bottom: 6px;
}

.code-loading {
  height: 380px;
}

.no-evidence {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px 14px;
  border-radius: 10px;
  font-size: 13px;
  color: var(--app-text-secondary);
  background: var(--app-surface-alt);
  border: 1px dashed var(--app-border-strong);
}

.evidence {
  margin-bottom: 14px;
  padding: 12px 14px 4px;
  border-radius: 12px;
  border: 1px solid var(--app-border);
}

.evidence.hit {
  border-color: color-mix(in srgb, var(--app-success) 40%, var(--app-border));
  background: linear-gradient(180deg, var(--app-success-soft), transparent 64px);
}

.ev-head {
  display: flex;
  align-items: center;
  gap: 10px;
}

.ev-icon {
  font-size: 22px;
  color: var(--app-text-muted);
  display: grid;
}

.evidence.hit .ev-icon {
  color: var(--app-success);
}

.ev-text {
  flex: 1;
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 4px 10px;
  min-width: 0;
  font-size: 13.5px;
}

.marker {
  padding: 1px 8px;
  border-radius: 6px;
  font-size: 12.5px;
  color: var(--app-success);
  background: var(--app-surface);
  border: 1px solid color-mix(in srgb, var(--app-success) 35%, transparent);
  word-break: break-all;
}

.raw-tabs {
  margin-top: 6px;
}

.raw {
  max-height: 320px;
}

.raw mark {
  padding: 0 2px;
  border-radius: 3px;
  color: #0f1523;
  background: #f4d35e;
}

.replay-label {
  margin: 8px 0 4px;
}

@media (max-width: 900px) {
  .trace,
  .facts {
    grid-template-columns: minmax(0, 1fr);
  }

  .metrics {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}
</style>
