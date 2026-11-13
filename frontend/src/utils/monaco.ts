// 只引入编辑器核心和 Python 语法高亮，不加载 TypeScript、CSS 等语言服务，控制打包体积
import * as monaco from 'monaco-editor/editor/editor.api'
import 'monaco-editor/languages/definitions/python/register'
import EditorWorker from 'monaco-editor/editor/editor.worker?worker'

self.MonacoEnvironment = { getWorker: () => new EditorWorker() }

export function languageOf(path: string): string {
  return path.toLowerCase().endsWith('.py') ? 'python' : 'plaintext'
}

export { monaco }
