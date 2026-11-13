<script setup lang="ts">
import { ElMessage, ElMessageBox } from 'element-plus'
import { computed, defineAsyncComponent, ref, watch } from 'vue'

import { ApiError } from '@/api/http'
import { adoptPatch, downloadPatch, getPatch, type PatchOut } from '@/api/patches'
import { useAuthStore } from '@/stores/auth'
import { formatTime } from '@/utils/format'
import { languageOf } from '@/utils/language'

// Monaco 体积大，打开补丁时才加载
const DiffViewer = defineAsyncComponent(() => import('@/components/DiffViewer.vue'))

/** revision 变化时重新拉取（补丁在“补丁与报告”阶段生成） */
const props = defineProps<{ findingId: number; revision?: string }>()

const auth = useAuthStore()
const patch = ref<PatchOut | null>(null)
const loading = ref(false)
const missing = ref(false)
const error = ref('')
const view = ref<'compare' | 'text'>('compare')
const adopting = ref(false)
const downloading = ref(false)
let seq = 0

const canAdopt = computed(() => auth.hasRole('developer'))

async function load(id: number, quiet = false): Promise<void> {
  const mine = ++seq
  loading.value = !quiet
  error.value = ''
  try {
    const data = await getPatch(id)
    if (mine !== seq) return
    patch.value = data
    missing.value = false
  } catch (err) {
    if (mine !== seq) return
    patch.value = null
    missing.value = err instanceof ApiError && err.status === 404
    if (!missing.value) error.value = err instanceof ApiError ? err.message : '补丁加载失败'
  } finally {
    if (mine === seq) loading.value = false
  }
}

watch(() => props.findingId, (id) => load(id), { immediate: true })
watch(
  () => props.revision,
  () => load(props.findingId, true),
)

/** diff 按行着色：文件头、修改块头、新增行、删除行 */
const diffLines = computed(() =>
  (patch.value?.diff ?? '').replace(/\n$/, '').split('\n').map((text) => {
    let kind = ''
    if (/^(diff --git|---|\+\+\+) /.test(text)) kind = 'head'
    else if (text.startsWith('@@')) kind = 'hunk'
    else if (text.startsWith('+')) kind = 'add'
    else if (text.startsWith('-')) kind = 'del'
    return { text, kind }
  }),
)

/** 剪贴板接口被拒绝时（如浏览器未授予写权限）退回选中文本复制 */
function copyBySelection(text: string): boolean {
  const area = document.createElement('textarea')
  area.value = text
  area.setAttribute('readonly', '')
  area.style.position = 'fixed'
  area.style.opacity = '0'
  document.body.appendChild(area)
  area.select()
  try {
    return document.execCommand('copy')
  } catch {
    return false
  } finally {
    area.remove()
  }
}

async function copy(): Promise<void> {
  if (!patch.value) return
  const text = patch.value.diff
  let ok = false
  try {
    await navigator.clipboard.writeText(text)
    ok = true
  } catch {
    ok = copyBySelection(text)
  }
  if (ok) ElMessage.success('diff 已复制')
  else ElMessage.error('复制失败，请改用下载 .patch')
}

async function doDownload(): Promise<void> {
  if (!patch.value) return
  downloading.value = true
  try {
    await downloadPatch(props.findingId, patch.value.finding_code)
  } catch (err) {
    ElMessage.error(err instanceof ApiError ? err.message : '下载失败')
  } finally {
    downloading.value = false
  }
}

async function adopt(): Promise<void> {
  if (!patch.value) return
  try {
    await ElMessageBox.confirm(
      '采纳只记录状态并写入审计日志，不会改动工程代码。请在本地仓库应用补丁并完成验证。',
      `采纳 ${patch.value.finding_code} 的补丁`,
      { confirmButtonText: '采纳', cancelButtonText: '取消', type: 'info' },
    )
  } catch {
    return
  }
  adopting.value = true
  try {
    patch.value = await adoptPatch(props.findingId)
    ElMessage.success('已标记为采纳')
  } catch (err) {
    ElMessage.error(err instanceof ApiError ? err.message : '采纳失败')
    if (err instanceof ApiError && err.status === 409) void load(props.findingId, true)
  } finally {
    adopting.value = false
  }
}
</script>

<template>
  <div v-loading="loading" class="patch">
    <el-alert v-if="error" type="error" :title="error" show-icon :closable="false" />
    <el-empty
      v-else-if="missing"
      :image-size="56"
      description="没有修复补丁：补丁在补丁与报告阶段为已验证漏洞生成，大模型未启用、调用失败或输出未通过校验时不生成，原因见该阶段日志"
    />
    <template v-else-if="patch">
      <div class="bar">
        <div class="meta">
          <el-tag :type="patch.adopted ? 'success' : 'info'" disable-transitions>
            {{ patch.adopted ? '已采纳' : '未采纳' }}
          </el-tag>
          <code class="file">{{ patch.file }}</code>
          <span class="stat"><span class="add">+{{ patch.added }}</span> <span class="del">-{{ patch.removed }}</span></span>
          <span v-if="patch.adopted" class="muted">{{ patch.adopted_by ?? '已删除的用户' }} 于 {{ formatTime(patch.adopted_at) }} 采纳</span>
        </div>
        <div class="actions">
          <el-button size="small" @click="copy">
            <el-icon><CopyDocument /></el-icon>
            <span>复制 diff</span>
          </el-button>
          <el-button size="small" :loading="downloading" @click="doDownload">
            <el-icon v-if="!downloading"><Download /></el-icon>
            <span>下载 .patch</span>
          </el-button>
          <el-button
            v-if="canAdopt"
            size="small"
            type="primary"
            :disabled="patch.adopted"
            :loading="adopting"
            @click="adopt"
          >
            <el-icon v-if="!adopting"><Select /></el-icon>
            <span>{{ patch.adopted ? '已采纳' : '采纳' }}</span>
          </el-button>
        </div>
      </div>
      <el-tabs v-model="view">
        <el-tab-pane label="修复前后对比" name="compare">
          <DiffViewer
            v-if="view === 'compare' && patch.original !== null && patch.patched !== null"
            :original="patch.original"
            :modified="patch.patched"
            :language="languageOf(patch.file)"
          />
          <el-alert
            v-else-if="patch.original === null"
            type="warning"
            title="工程源码已变化或无法读取，补丁与原文件对不上，请查看 Diff 文本"
            show-icon
            :closable="false"
          />
        </el-tab-pane>
        <el-tab-pane label="Diff 文本" name="text">
          <pre class="diff"><span v-for="(line, i) in diffLines" :key="i" :class="line.kind">{{ line.text }}
</span></pre>
        </el-tab-pane>
      </el-tabs>
    </template>
  </div>
</template>

<style scoped>
.patch {
  min-height: 80px;
}

.bar {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 8px 16px;
}

.meta {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 6px 10px;
  min-width: 0;
}

.file {
  font-size: 12px;
  word-break: break-all;
}

.stat {
  font-family: Consolas, 'Cascadia Mono', monospace;
  font-size: 12px;
}

.add {
  color: var(--app-success);
}

.del {
  color: var(--app-danger);
}

.muted {
  color: var(--app-text-muted);
  font-size: 12px;
}

.actions {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.actions .el-button + .el-button {
  margin-left: 0;
}

.diff {
  margin: 0;
  max-height: 420px;
  overflow: auto;
  background: var(--app-surface-alt);
  border: 1px solid var(--app-border);
  border-radius: var(--app-radius-sm);
  padding: 10px 0;
  font-family: var(--app-font-mono);
  font-size: 12.5px;
  line-height: 1.6;
}

.diff span {
  display: block;
  padding: 0 12px;
  white-space: pre-wrap;
  word-break: break-all;
}

.diff .head {
  color: var(--app-text-secondary);
  font-weight: 600;
}

.diff .hunk {
  color: var(--app-primary);
  background: var(--app-primary-soft);
}

.diff .add {
  color: var(--app-text);
  background: var(--app-success-soft);
}

.diff .del {
  color: var(--app-text);
  background: var(--app-danger-soft);
}
</style>
