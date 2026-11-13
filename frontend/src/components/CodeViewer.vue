<script setup lang="ts">
import { onBeforeUnmount, onMounted, useTemplateRef, watch } from 'vue'

import { monaco } from '@/utils/monaco'

/** trigger 为漏洞触发行，step 为污点轨迹经过的行，current 为当前选中的步骤；同一行取最强的一种 */
export interface LineMark {
  line: number
  kind: 'trigger' | 'step' | 'current'
  hover?: string
}

const props = withDefaults(
  defineProps<{ value: string; language?: string; marks?: LineMark[]; reveal?: number | null; height?: string }>(),
  { language: 'plaintext', marks: () => [], reveal: null, height: '360px' },
)

const RANK: Record<LineMark['kind'], number> = { step: 0, trigger: 1, current: 2 }

const el = useTemplateRef<HTMLDivElement>('el')
let editor: monaco.editor.IStandaloneCodeEditor | null = null
let decorations: monaco.editor.IEditorDecorationsCollection | null = null

function applyMarks(): void {
  const model = editor?.getModel()
  if (!editor || !model || !decorations) return
  const lineCount = model.getLineCount()
  const byLine = new Map<number, { kind: LineMark['kind']; hovers: string[] }>()
  for (const mark of props.marks) {
    if (mark.line < 1 || mark.line > lineCount) continue
    const entry = byLine.get(mark.line) ?? { kind: mark.kind, hovers: [] }
    if (RANK[mark.kind] > RANK[entry.kind]) entry.kind = mark.kind
    if (mark.hover) entry.hovers.push(mark.hover)
    byLine.set(mark.line, entry)
  }
  decorations.set(
    [...byLine].map(([line, { kind, hovers }]) => ({
      range: new monaco.Range(line, 1, line, 1),
      options: {
        isWholeLine: true,
        className: `cv-line-${kind}`,
        linesDecorationsClassName: `cv-gutter-${kind}`,
        hoverMessage: hovers.map((value) => ({ value })),
      },
    })),
  )
  if (props.reveal && props.reveal <= lineCount) editor.revealLineInCenter(props.reveal)
}

onMounted(() => {
  if (!el.value) return
  editor = monaco.editor.create(el.value, {
    value: props.value,
    language: props.language,
    readOnly: true,
    domReadOnly: true,
    automaticLayout: true,
    minimap: { enabled: false },
    scrollBeyondLastLine: false,
    renderLineHighlight: 'none',
    contextmenu: false,
    fontSize: 13,
    lineNumbersMinChars: 4,
    lineDecorationsWidth: 6,
  })
  decorations = editor.createDecorationsCollection()
  applyMarks()
})

watch(
  () => [props.value, props.language] as const,
  ([value, language]) => {
    const model = editor?.getModel()
    if (!model) return
    if (model.getValue() !== value) model.setValue(value)
    monaco.editor.setModelLanguage(model, language)
    applyMarks()
  },
)

watch(() => [props.marks, props.reveal], applyMarks)

onBeforeUnmount(() => {
  editor?.getModel()?.dispose()
  editor?.dispose()
})
</script>

<template>
  <div ref="el" class="code-viewer" :style="{ height: props.height }" />
</template>

<style>
.code-viewer {
  width: 100%;
  border: 1px solid var(--app-border);
  border-radius: var(--app-radius-sm);
  overflow: hidden;
}

.cv-line-step {
  background: rgba(64, 158, 255, 0.1);
}

.cv-line-trigger {
  background: rgba(245, 108, 108, 0.16);
}

.cv-line-current {
  background: rgba(230, 162, 60, 0.3);
}

.cv-gutter-step {
  background: #79bbff;
  width: 4px !important;
  margin-left: 2px;
}

.cv-gutter-trigger {
  background: #f56c6c;
  width: 4px !important;
  margin-left: 2px;
}

.cv-gutter-current {
  background: #e6a23c;
  width: 4px !important;
  margin-left: 2px;
}
</style>
