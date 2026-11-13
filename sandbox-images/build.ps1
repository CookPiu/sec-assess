# 构建评估沙箱镜像。需要 Docker Desktop 已启动；构建时会联网拉取基础镜像和预装依赖，任务运行时不联网。
# 用法（PowerShell 7，项目根目录）：./sandbox-images/build.ps1 [-Tag sec-assess/sandbox-python:3.12]
param(
    [string]$Tag = "sec-assess/sandbox-python:3.12"
)

$ErrorActionPreference = "Stop"
$context = Join-Path $PSScriptRoot "python312"

docker build --tag $Tag $context
if ($LASTEXITCODE -ne 0) { throw "镜像构建失败：$Tag" }
Write-Host "已构建镜像 $Tag"
