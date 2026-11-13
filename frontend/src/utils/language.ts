// 按文件名选择代码视图的语法高亮；单独成文件，引用它的组件不必同步加载 Monaco
export function languageOf(path: string): string {
  return path.toLowerCase().endsWith('.py') ? 'python' : 'plaintext'
}
