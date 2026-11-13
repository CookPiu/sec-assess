<script setup lang="ts">
import { ElMessage, type UploadFile, type UploadInstance } from 'element-plus'
import { computed, ref, useTemplateRef } from 'vue'

import { ApiError } from '@/api/http'
import { createTask, type TaskOut } from '@/api/tasks'

const MAX_ZIP_MB = 50

const visible = defineModel<boolean>({ required: true })
const emit = defineEmits<{ created: [task: TaskOut] }>()

const mode = ref<'git' | 'zip'>('git')
const gitUrl = ref('')
const name = ref('')
const file = ref<File | null>(null)
const submitting = ref(false)
const upload = useTemplateRef<UploadInstance>('upload')

const canSubmit = computed(() => (mode.value === 'git' ? /^https:\/\/\S+$/.test(gitUrl.value.trim()) : file.value !== null))

function onFileChange(uploadFile: UploadFile): void {
  const raw = uploadFile.raw ?? null
  if (raw && raw.size > MAX_ZIP_MB * 1024 * 1024) {
    ElMessage.error(`压缩包不能超过 ${MAX_ZIP_MB} MB`)
    upload.value?.clearFiles()
    file.value = null
    return
  }
  file.value = raw
}

function onFileRemove(): void {
  file.value = null
}

function reset(): void {
  gitUrl.value = ''
  name.value = ''
  file.value = null
  upload.value?.clearFiles()
}

async function submit(): Promise<void> {
  if (!canSubmit.value) return
  submitting.value = true
  try {
    const task =
      mode.value === 'git'
        ? await createTask({ kind: 'git', url: gitUrl.value.trim(), name: name.value.trim() || undefined })
        : await createTask({ kind: 'zip', file: file.value as File, name: name.value.trim() || undefined })
    ElMessage.success('评估任务已创建')
    visible.value = false
    reset()
    emit('created', task)
  } catch (err) {
    ElMessage.error(err instanceof ApiError ? err.message : '创建失败')
  } finally {
    submitting.value = false
  }
}
</script>

<template>
  <el-dialog v-model="visible" title="新建评估" width="520px" :close-on-click-modal="!submitting">
    <el-form label-position="top" @submit.prevent="submit">
      <el-form-item label="源码来源">
        <el-radio-group v-model="mode">
          <el-radio-button value="git">Git 仓库</el-radio-button>
          <el-radio-button value="zip">上传 zip</el-radio-button>
        </el-radio-group>
      </el-form-item>

      <el-form-item v-if="mode === 'git'" label="仓库地址">
        <el-input v-model="gitUrl" placeholder="https://github.com/owner/repo.git" clearable />
        <div class="hint">只接受公开的 HTTPS 地址，克隆时不拉取子模块和 LFS 文件，仓库不超过 200 MB。</div>
      </el-form-item>

      <el-form-item v-else label="源码包">
        <el-upload
          ref="upload"
          class="uploader"
          drag
          accept=".zip"
          :limit="1"
          :auto-upload="false"
          :on-change="onFileChange"
          :on-remove="onFileRemove"
          :on-exceed="() => ElMessage.warning('一次只能上传一个压缩包，请先移除已选文件')"
        >
          <el-icon class="upload-icon"><UploadFilled /></el-icon>
          <div>将 zip 文件拖到这里，或<em>点击选择</em></div>
          <template #tip>
            <div class="hint">压缩包不超过 {{ MAX_ZIP_MB }} MB，解压后不超过 200 MB，不能包含符号链接或 ../ 路径。</div>
          </template>
        </el-upload>
      </el-form-item>

      <el-form-item label="项目名称（可选）">
        <el-input v-model="name" maxlength="128" placeholder="留空时使用仓库名或文件名" />
      </el-form-item>
    </el-form>

    <template #footer>
      <el-button :disabled="submitting" @click="visible = false">取消</el-button>
      <el-button type="primary" :loading="submitting" :disabled="!canSubmit" @click="submit">开始评估</el-button>
    </template>
  </el-dialog>
</template>

<style scoped>
.hint {
  margin-top: 4px;
  font-size: 12px;
  line-height: 1.5;
  color: var(--app-text-muted);
}

.uploader {
  width: 100%;
}

.upload-icon {
  font-size: 40px;
  color: var(--app-text-muted);
  margin-bottom: 8px;
}
</style>
