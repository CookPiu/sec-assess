<script setup lang="ts">
import { onBeforeUnmount, onMounted, useTemplateRef, watch } from 'vue'

import { monaco } from '@/utils/monaco'

const props = withDefaults(
  defineProps<{ original: string; modified: string; language?: string; height?: string }>(),
  { language: 'plaintext', height: '360px' },
)

const el = useTemplateRef<HTMLDivElement>('el')
let editor: monaco.editor.IStandaloneDiffEditor | null = null
let models: monaco.editor.ITextModel[] = []

function setModels(): void {
  if (!editor) return
  const next = [
    monaco.editor.createModel(props.original, props.language),
    monaco.editor.createModel(props.modified, props.language),
  ]
  editor.setModel({ original: next[0], modified: next[1] })
  for (const model of models) model.dispose()
  models = next
}

onMounted(() => {
  if (!el.value) return
  editor = monaco.editor.createDiffEditor(el.value, {
    readOnly: true,
    originalEditable: false,
    domReadOnly: true,
    automaticLayout: true,
    renderSideBySide: true,
    // 宽度不够时改为上下对照
    useInlineViewWhenSpaceIsLimited: true,
    renderSideBySideInlineBreakpoint: 760,
    // 折叠未改动的大段代码，只展开修改处及上下文
    hideUnchangedRegions: { enabled: true, contextLineCount: 3, minimumLineCount: 6, revealLineCount: 10 },
    // 左右各占一半宽度，长行折行显示
    diffWordWrap: 'on',
    wordWrap: 'on',
    minimap: { enabled: false },
    scrollBeyondLastLine: false,
    renderOverviewRuler: false,
    contextmenu: false,
    fontSize: 13,
    lineNumbersMinChars: 4,
  })
  setModels()
})

watch(() => [props.original, props.modified, props.language], setModels)

onBeforeUnmount(() => {
  editor?.dispose()
  for (const model of models) model.dispose()
})
</script>

<template>
  <div ref="el" class="diff-viewer" :style="{ height: props.height }" />
</template>

<style scoped>
.diff-viewer {
  width: 100%;
  border: 1px solid var(--app-border);
  border-radius: 4px;
  overflow: hidden;
}
</style>
