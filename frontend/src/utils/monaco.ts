// 只引入编辑器核心和 Python 语法高亮，不加载 TypeScript、CSS 等语言服务，控制打包体积
import * as monaco from 'monaco-editor/editor/editor.api'
import 'monaco-editor/languages/definitions/python/register'
import EditorWorker from 'monaco-editor/editor/editor.worker?worker'
import { watch } from 'vue'

import { isDark } from '@/utils/theme'

self.MonacoEnvironment = { getWorker: () => new EditorWorker() }

// 主题对页面上所有编辑器生效，随界面明暗切换
watch(isDark, (dark) => monaco.editor.setTheme(dark ? 'vs-dark' : 'vs'), { immediate: true })

export { monaco }
