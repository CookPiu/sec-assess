<script setup lang="ts">
import { type EdgeData, Graph, type IElementEvent, type NodeData } from '@antv/g6'
import { computed, nextTick, onBeforeUnmount, ref, shallowRef, useTemplateRef, watch } from 'vue'

import { type AttackPath, type ChainData, type ChainNode, getChain } from '@/api/chain'
import { ApiError } from '@/api/http'
import type { TaskOut } from '@/api/tasks'
import { isDark, palette } from '@/utils/theme'

const props = defineProps<{ taskId: number; task: TaskOut | null }>()
const emit = defineEmits<{ openFinding: [findingId: number] }>()

const DONE_STAGES = ['report_gen']
const GRAPH_PADDING = 24

const data = ref<ChainData | null>(null)
const error = ref('')
const loading = ref(false)
const activePath = ref<number | null>(null)
const container = useTemplateRef<HTMLDivElement>('container')
const graph = shallowRef<Graph | null>(null)
let seq = 0

const nodeById = computed(() => new Map((data.value?.nodes ?? []).map((n) => [n.id, n])))
const selected = computed(() => data.value?.paths.find((p) => p.id === activePath.value) ?? null)

/** 推演阶段结束（进入报告阶段或任务已结束）后才有结果 */
const chainDone = computed(() => {
  const t = props.task
  if (!t) return false
  if (t.status === 'completed') return true
  return DONE_STAGES.includes(t.current_stage ?? '')
})

const emptyText = computed(() => {
  if (error.value) return error.value
  const t = props.task
  if (t && (t.status === 'failed' || t.status === 'stopped') && !chainDone.value) return '评估未完成攻击路径推演'
  if (!chainDone.value) return '攻击路径推演完成后显示'
  return '已验证漏洞之间没有能力衔接，未形成攻击路径'
})

function shorten(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, max - 1)}…` : text
}

/** 画布上的颜色取自当前主题；半透明填充在深色下更柔和 */
function graphColors() {
  const c = palette.value
  const dark = isDark.value
  return {
    ...c,
    startFill: c.text,
    startStroke: c.text,
    startLabel: c.surface,
    capFill: dark ? 'rgba(127, 149, 255, 0.14)' : '#eef1fe',
    goalFill: dark ? 'rgba(255, 107, 128, 0.14)' : '#fcecee',
    edge: dark ? '#55555a' : '#b4b3ad',
  }
}

function nodeStyle(n: ChainNode): Record<string, unknown> {
  const c = graphColors()
  const base = {
    labelText: n.label,
    labelPlacement: 'center',
    labelFontSize: 12,
    labelFontFamily: 'Microsoft YaHei, PingFang SC, sans-serif',
    labelWordWrap: true,
    labelMaxLines: 2,
    lineWidth: 1.5,
  }
  if (n.kind === 'start') return { ...base, size: 72, fill: c.startFill, stroke: c.startStroke, labelFill: c.startLabel }
  if (n.kind === 'goal')
    return { ...base, size: [104, 44], radius: 22, fill: c.goalFill, stroke: c.danger, labelFill: c.danger, lineWidth: 2 }
  if (n.kind === 'capability')
    return { ...base, size: [112, 40], radius: 8, fill: c.capFill, stroke: c.primary, labelFill: c.primary, lineDash: [4, 3] }
  const color = c.severity[(n.severity ?? 'info') as keyof typeof c.severity] ?? c.muted
  return {
    ...base,
    size: [176, 52],
    radius: 6,
    fill: c.surface,
    stroke: color,
    lineWidth: 1.5,
    labelText: n.route ? `${n.label}\n${shorten(n.route.path, 26)}` : n.label,
    labelFill: c.text,
    labelMaxWidth: 164,
    cursor: 'pointer',
  }
}

function toGraphData(d: ChainData): { nodes: NodeData[]; edges: EdgeData[] } {
  return {
    nodes: d.nodes.map((n) => ({
      id: `n${n.id}`,
      type: n.kind === 'start' ? 'circle' : 'rect',
      data: { kind: n.kind, findingId: n.finding_id, title: n.title },
      style: nodeStyle(n),
    })),
    edges: d.edges.map((e) => ({
      id: `e${e.id}`,
      source: `n${e.src}`,
      target: `n${e.dst}`,
      data: { reason: e.reason },
      style: { labelText: e.reason },
    })),
  }
}

function escapeHtml(text: string): string {
  return text.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`)
}

let observer: ResizeObserver | null = null
let resizeTimer = 0

function destroyGraph(): void {
  observer?.disconnect()
  observer = null
  window.clearTimeout(resizeTimer)
  graph.value?.destroy()
  graph.value = null
}

async function draw(): Promise<void> {
  destroyGraph()
  const d = data.value
  if (!d?.nodes.length || !container.value) return
  const c = graphColors()
  const g = new Graph({
    container: container.value,
    // 关闭动画：渲染结束时元素位置即为最终位置，随后的适配与居中才能按实际边界计算
    animation: false,
    padding: GRAPH_PADDING,
    data: toGraphData(d),
    node: {
      state: {
        active: { lineWidth: 3 },
        inactive: { opacity: 0.25 },
      },
    },
    edge: {
      type: 'cubic-horizontal',
      style: {
        stroke: c.edge,
        lineWidth: 1.5,
        endArrow: true,
        labelFontSize: 11,
        labelFill: c.textSecondary,
        labelBackground: true,
        labelBackgroundFill: c.surface,
        labelBackgroundRadius: 3,
        labelBackgroundOpacity: 0.9,
        labelPadding: [1, 4],
        labelAutoRotate: false,
        // 边的默认样式不换行，长说明会撑出画布；截断部分悬停查看
        labelWordWrap: true,
        labelMaxWidth: 120,
        labelMaxLines: 2,
      },
      state: {
        active: { stroke: c.text, lineWidth: 2, labelFill: c.text },
        inactive: { opacity: 0.15 },
      },
    },
    // edgeLabelSpace 默认会在每条边中间插入占位节点，使布局宽度翻倍；边标签放在层间距里即可。
    // antv-dagre 把 ranksep / nodesep 加在节点两侧，再叠加 dagre 自身的间距：
    // 层间距约为 2 × ranksep + 50，同层间距约为 3 × nodesep
    layout: {
      type: 'antv-dagre',
      rankdir: 'LR',
      nodesep: 8,
      ranksep: 45,
      edgeLabelSpace: false,
      nodeSize: (d: NodeData) => (d.style?.size as number | [number, number] | undefined) ?? 40,
    },
    behaviors: ['drag-canvas', 'zoom-canvas'],
    plugins: [
      {
        type: 'tooltip',
        // 边上的说明会截断，悬停显示完整的能力或推导依据；漏洞节点显示标题
        enable: (e: IElementEvent) =>
          e.targetType === 'edge' || (e.targetType === 'node' && nodeData(e)?.kind === 'finding'),
        getContent: async (e: IElementEvent) => {
          if (e.targetType === 'edge') {
            const reason = (g.getEdgeData(e.target.id).data?.reason as string) ?? ''
            return `<div class="graph-tip">${escapeHtml(reason)}</div>`
          }
          const title = (nodeData(e)?.title as string) ?? ''
          return `<div class="graph-tip">${escapeHtml(title)}<br><span>点击查看漏洞详情</span></div>`
        },
      },
    ],
  })
  function nodeData(e: IElementEvent): Record<string, unknown> | undefined {
    return g.getNodeData(e.target.id).data as Record<string, unknown> | undefined
  }
  g.on('node:click', (e: IElementEvent) => {
    const findingId = nodeData(e)?.findingId
    if (typeof findingId === 'number') emit('openFinding', findingId)
  })
  graph.value = g
  await g.render()
  await fit()
  if (activePath.value !== null) await highlight(activePath.value)
  // 页面后续内容加载、出现滚动条或窗口缩放都会改变容器宽度，画布随之调整并重新居中
  const el = container.value
  if (el && graph.value === g) {
    observer = new ResizeObserver(() => {
      window.clearTimeout(resizeTimer)
      resizeTimer = window.setTimeout(() => {
        if (graph.value !== g || !el.clientWidth) return
        g.resize(el.clientWidth, el.clientHeight)
        void fit()
      }, 150)
    })
    observer.observe(el)
  }
}

async function highlight(pathId: number | null): Promise<void> {
  const g = graph.value
  const d = data.value
  if (!g || !d) return
  const path = d.paths.find((p) => p.id === pathId)
  const states: Record<string, string[]> = {}
  if (!path) {
    for (const n of d.nodes) states[`n${n.id}`] = []
    for (const e of d.edges) states[`e${e.id}`] = []
  } else {
    const onPath = new Set(path.node_ids)
    const pairs = new Set(path.node_ids.slice(1).map((id, i) => `${path.node_ids[i]}-${id}`))
    for (const n of d.nodes) states[`n${n.id}`] = [onPath.has(n.id) ? 'active' : 'inactive']
    for (const e of d.edges) states[`e${e.id}`] = [pairs.has(`${e.src}-${e.dst}`) ? 'active' : 'inactive']
  }
  await g.setElementState(states)
}

function togglePath(p: AttackPath): void {
  activePath.value = activePath.value === p.id ? null : p.id
  void highlight(activePath.value)
}

async function load(): Promise<void> {
  if (!chainDone.value) {
    data.value = null
    return
  }
  const mine = ++seq
  loading.value = data.value === null
  try {
    const d = await getChain(props.taskId)
    if (mine !== seq) return
    error.value = ''
    const changed = JSON.stringify(d) !== JSON.stringify(data.value)
    data.value = d
    if (activePath.value !== null && !d.paths.some((p) => p.id === activePath.value)) activePath.value = null
    if (activePath.value === null && d.paths.length) activePath.value = d.paths[0].id
    if (changed) {
      await nextTick()
      await draw()
    }
  } catch (err) {
    if (mine === seq) error.value = err instanceof ApiError ? err.message : '攻击路径加载失败'
  } finally {
    if (mine === seq) loading.value = false
  }
}

watch(
  () => props.taskId,
  () => {
    data.value = null
    activePath.value = null
    destroyGraph()
  },
)
watch(() => [props.taskId, chainDone.value, props.task?.status], load, { immediate: true })

onBeforeUnmount(destroyGraph)

// 切换明暗主题时按新配色重画
watch(isDark, () => {
  if (data.value?.nodes.length) void nextTick().then(draw)
})

function pathText(p: AttackPath): string {
  return p.node_ids
    .slice(1)
    .map((id) => nodeById.value.get(id)?.label ?? '')
    .join(' → ')
}

function findingCount(p: AttackPath): number {
  return p.node_ids.filter((id) => nodeById.value.get(id)?.kind === 'finding').length
}

/** 超出画布时缩小到能完整显示，否则保持原始大小，再居中；不放大，避免节点少时文字过大 */
async function fit(): Promise<void> {
  const g = graph.value
  if (!g) return
  await g.zoomTo(1, false)
  // fitView 的 when: 'overflow' 在 G6 5.1 中不生效，这里按内容边界与画布尺寸自行判断
  const [width, height] = g.getSize()
  const { min, max } = g.getCanvas().getBounds()
  if (max[0] - min[0] + GRAPH_PADDING * 2 > width || max[1] - min[1] + GRAPH_PADDING * 2 > height) {
    await g.fitView(undefined, false)
  }
  await g.fitCenter(false)
}
</script>

<template>
  <div v-loading="loading" class="attack-graph">
    <el-empty v-if="!data?.nodes.length" :image-size="70" :description="emptyText" />
    <template v-else>
      <div class="canvas-wrap">
        <div ref="container" class="canvas" />
        <div class="legend">
          <span><i class="dot start" />起点</span>
          <span><i class="dot finding" />已验证漏洞（边框按等级着色，点击查看详情）</span>
          <span><i class="dot capability" />推导出的身份</span>
          <span><i class="dot goal" />攻陷目标</span>
          <span class="muted">滚轮缩放，拖动平移，悬停在边上查看完整说明</span>
          <el-button size="small" link @click="fit">适应画布</el-button>
        </div>
      </div>

      <div class="paths-head">
        多步攻击路径 {{ data.paths.length }} 条
        <span v-if="data.paths.length" class="muted">点击路径在图上高亮，再次点击取消</span>
      </div>
      <el-empty
        v-if="!data.paths.length"
        :image-size="56"
        description="每条到达攻陷目标的路径只经过一个漏洞，没有多步攻击路径"
      />
      <template v-else>
        <ol class="paths">
          <li
            v-for="(p, i) in data.paths"
            :key="p.id"
            :class="{ active: activePath === p.id }"
            @click="togglePath(p)"
          >
            <div class="path-title">
              <span>路径 {{ i + 1 }}</span>
              <el-tag size="small" type="danger" effect="plain" disable-transitions>{{ p.target }}</el-tag>
              <span class="muted">{{ findingCount(p) }} 个漏洞节点</span>
            </div>
            <div class="path-nodes">{{ pathText(p) }}</div>
          </li>
        </ol>

        <div v-if="selected" class="path-detail">
          <div class="label">攻击步骤</div>
          <ol class="steps">
            <li v-for="(s, i) in selected.steps.slice(1)" :key="s.node_id">
              <span class="num">{{ i + 1 }}</span>
              <div>
                <b>{{ s.label }}</b>
                <div v-if="s.via !== s.label" class="via">{{ s.via }}</div>
              </div>
            </li>
          </ol>
          <div class="label">阶段说明</div>
          <p>{{ selected.summary || '—' }}</p>
          <div class="label">业务危害</div>
          <p>{{ selected.impact || '—' }}</p>
          <div class="muted">{{ selected.written_by === 'model' ? '说明由大模型撰写' : '说明按路径步骤生成' }}</div>
        </div>
      </template>
    </template>
  </div>
</template>

<style scoped>
.attack-graph {
  min-height: 160px;
}

.canvas-wrap {
  overflow: hidden;
  border: 1px solid var(--app-border);
  border-radius: var(--app-radius-sm);
  background-color: var(--app-surface-alt);
  /* 点阵底纹 */
  background-image: radial-gradient(circle, var(--app-border-strong) 0.8px, transparent 1px);
  background-size: 20px 20px;
}

.canvas {
  height: 500px;
}

.legend {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px 18px;
  padding: 10px 14px;
  border-top: 1px solid var(--app-border);
  background: var(--app-surface);
  font-size: 12px;
  color: var(--app-text-secondary);
}

.legend span {
  display: inline-flex;
  align-items: center;
  gap: 6px;
}

.legend .el-button {
  margin-left: auto;
}

.dot {
  display: inline-block;
  width: 11px;
  height: 11px;
  border-radius: 2px;
  border: 1.5px solid;
  box-sizing: border-box;
}

.dot.start {
  background: var(--app-ink);
  border-color: var(--app-ink);
  border-radius: 50%;
}

.dot.finding {
  background: var(--app-surface);
  border-color: var(--sev-high);
}

.dot.capability {
  background: var(--app-primary-soft);
  border-color: var(--app-primary);
  border-style: dashed;
}

.dot.goal {
  background: var(--app-danger-soft);
  border-color: var(--app-danger);
  border-radius: 6px;
}

.paths-head {
  display: flex;
  align-items: baseline;
  gap: 10px;
  margin: 28px 0 14px;
  padding-bottom: 10px;
  border-bottom: 1px solid var(--app-border);
  font-size: 15px;
  font-weight: 600;
}

.muted {
  font-size: 12px;
  font-weight: 400;
  color: var(--app-text-muted);
}

.paths {
  list-style: none;
  margin: 0;
  padding: 0;
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(min(100%, 300px), 1fr));
  gap: 10px;
}

.paths li {
  padding: 12px 14px;
  border: 1px solid var(--app-border);
  border-radius: var(--app-radius-sm);
  background: var(--app-surface);
  cursor: pointer;
  transition: border-color 0.15s, background-color 0.15s;
}

.paths li:hover {
  border-color: var(--app-border-strong);
}

.paths li.active {
  border-color: var(--app-ink);
  box-shadow: inset 0 0 0 1px var(--app-ink);
}

.path-title {
  display: flex;
  align-items: center;
  gap: 8px;
  font-weight: 600;
  font-size: 13.5px;
}

.path-nodes {
  margin-top: 6px;
  font-size: 12.5px;
  color: var(--app-text-secondary);
  line-height: 1.6;
}

.path-detail {
  margin-top: 14px;
  padding: 8px 20px 18px;
  border: 1px solid var(--app-border);
  border-left: 2px solid var(--app-warning);
  border-radius: var(--app-radius-sm);
  background: var(--app-surface);
}

.steps {
  list-style: none;
  margin: 8px 0 0;
  padding: 0;
}

.steps li {
  position: relative;
  display: flex;
  gap: 12px;
  padding: 5px 0;
  font-size: 13px;
}

/* 步骤之间的竖线 */
.steps li:not(:last-child)::after {
  content: '';
  position: absolute;
  left: 10px;
  top: 27px;
  bottom: -5px;
  width: 1px;
  background: var(--app-border-strong);
}

.num {
  position: relative;
  z-index: 1;
  flex-shrink: 0;
  width: 21px;
  height: 21px;
  border-radius: 50%;
  background: var(--app-ink);
  color: var(--app-ink-contrast);
  font-family: var(--app-font-mono);
  font-size: 11.5px;
  font-weight: 600;
  line-height: 21px;
  text-align: center;
}

.via {
  color: var(--app-text-secondary);
  font-size: 12.5px;
  line-height: 1.5;
}

.label {
  margin-top: 16px;
  font-size: 12px;
  font-weight: 500;
  color: var(--app-text-muted);
}

.paths p {
  margin: 4px 0 0;
  font-size: 13px;
  line-height: 1.7;
}

.path-detail p {
  margin: 4px 0 0;
  font-size: 13.5px;
  line-height: 1.75;
}

@media (max-width: 767px) {
  .canvas {
    height: 360px;
  }
}
</style>

<style>
.graph-tip {
  max-width: 280px;
  font-size: 12px;
  line-height: 1.5;
  color: var(--app-text);
}

.graph-tip span {
  color: var(--app-text-muted);
}
</style>
