# 自动化安全评估系统 任务清单

依据 [SPEC.md](SPEC.md)（已确认）与 [DESIGN.md](DESIGN.md)。格式为 `T编号 [P] [场景] 描述（文件路径）关联编号`，[P] 表示与同组其他任务没有文件和顺序上的依赖，可以并行。完成 US1 即可演示一个能跑完全部阶段、在大盘和监控区看到结果的最小版本。

## 准备

- [x] T001 后端工程骨架：uv 项目（Python 3.12）、FastAPI 入口、`.env` 与配置读取、`.env.example` 占位（backend/pyproject.toml、backend/app/main.py、backend/app/core/config.py、.env.example）C-004 C-005
- [x] T002 [P] 前端工程骨架：Vite + Vue 3 + TypeScript + Element Plus + Pinia、路由、请求封装（frontend/）D-010
- [x] T003 [P] `.gitignore` 与 `data/` 目录约定，忽略依赖、运行数据和 `.env`（.gitignore、data/）C-005 C-007

## 公共基础

- [x] T004 数据模型与建表：project、task、stage_log、finding、taint_step、evidence、chain、chain_edge、patch、user、audit_log、setting（backend/app/models/、backend/app/core/db.py）D-005
- [x] T005 登录与角色：JWT 签发与校验、bcrypt、三类预置账号、按角色校验的依赖项（backend/app/core/auth.py、backend/app/api/auth.py）FR-019
- [x] T006 审计日志写入工具与查询接口，仅管理员可查（backend/app/core/audit.py、backend/app/api/audit.py）FR-020
- [x] T007 [P] 沙箱镜像：python:3.12-slim、预装 Flask 常见依赖、非 root 用户、构建脚本（sandbox-images/python312/Dockerfile、sandbox-images/build.ps1）FR-003
- [x] T008 沙箱管理：创建容器（`/src` 只读、`/work` 任务卷、`/tmp` tmpfs、`--network none`、丢弃 capabilities、`no-new-privileges`、配额、本系统标签）、exec、kill 与卷清理（backend/app/sandbox/manager.py）FR-003 FR-005 D-001 D-016
- [x] T009 沙箱隔离集成测试：外连失败、写 `/src` 失败、root 失败、kill 后 5 秒内容器与卷消失（backend/tests/sandbox/test_isolation.py）SC-006 SC-007
- [x] T010 资源采样：Docker stats 每 2 秒一次，输出 CPU、内存、进程数（backend/app/sandbox/stats.py）FR-014
- [x] T011 事件总线与 SSE 接口：阶段、日志、资源三类事件，按任务订阅（backend/app/core/events.py、backend/app/api/events.py）FR-014 D-006
- [x] T012 [P] 大模型客户端：DeepSeek OpenAI 兼容接口、超时、总开关、只接收代码片段（backend/app/core/llm.py）D-011
- [x] T013 [P] 电商靶场 shop-admin：S1–S9、诱饵写法、种子数据（含无盐 MD5 管理员密码）（targets/shop-admin/）FR-021
- [x] T014 [P] 用户中心靶场 user-center：U1–U3、诱饵写法、注册与登录接口、一个预装镜像外的依赖（targets/user-center/）FR-021 SC-010
- [x] T015 [P] 前端登录页、按角色显示菜单、路由守卫（frontend/src/views/LoginView.vue、frontend/src/router/）FR-019

## US1 新建评估并自动跑完流水线（P1）

- [x] T016 项目接入：Git 浅克隆（只接受 HTTPS，禁用 hooks、子模块、LFS，超时与 200 MB 上限）、zip 安全解压（拒绝路径穿越和符号链接，50 MB / 200 MB 上限）、项目接口（backend/app/project/ingest.py、backend/app/api/projects.py）FR-001
- [x] T017 [P] 侦察：解析 requirements.txt、pyproject.toml、package.json、pom.xml，统计代码行数（backend/app/project/stack.py）FR-002
- [x] T018 侦察：Flask 路由表与侦察事实（启动方式与端口、路由访问前提、注册登录字段、密码存储方式、会话方式）（backend/app/project/flask_facts.py）FR-002
- [x] T019 依赖准备：宿主机 `pip download --only-binary=:all:`、wheel 缓存、容器内离线安装、回退预装版本、结果写日志（backend/app/sandbox/deps.py）FR-022 D-012
- [x] T020 [P] 污点引擎：跨文件函数级调用图、Source / Sink / Sanitizer 规则表、赋值与拼接及参数返回值传播、3 层限制、逐步轨迹，以两个靶场为测试集（backend/app/taint/、backend/tests/taint/）FR-006 D-003 D-018；另有每类漏洞与诱饵的内联用例（D-021）
- [x] T021 越权规则与敏感信息规则（硬编码密钥、调试模式、配置暴露、弱密码存储）（backend/app/taint/rules_authz.py、backend/app/taint/rules_secrets.py）FR-007
- [x] T022 [P] CVSS 3.1 基础分计算与各漏洞类别的默认向量（backend/app/core/cvss.py、backend/tests/test_cvss.py）FR-008 D-015
- [x] T023 审计 Agent：大模型研判（4 路并发）、模型判定误报分组、模型不可用时回退默认向量（backend/app/pipeline/agents/audit.py）FR-008
- [x] T024 [P] 容器内探针执行脚本：读取用例 JSON、发往 `127.0.0.1`、返回请求与响应原文、检查 `/tmp` 标记文件（sandbox-images/probe/runner.py）D-014
- [x] T025 验证用例模板与命中判定：9 类探针、算式与随机名标记、测试账号自动注册（backend/app/verify/）FR-009 FR-010
- [x] T026 验证 Agent：启动工程副本、逐条执行用例、进程退出后重启、证据落库、未命中降级（backend/app/pipeline/agents/verify.py）FR-009 FR-010
- [x] T027 流水线编排：LangGraph 五阶段（exploit_chain、report_gen 先占位直通）、阶段起止落库与推送、停止与超时、排队与并发上限、后端启动时清理遗留容器与任务（backend/app/pipeline/state.py、backend/app/pipeline/graph.py、backend/app/pipeline/runner.py）FR-004 FR-005 D-004 D-019
- [x] T028 任务接口：新建（含 Docker 可用性预检）、停止、查询，研发人员无权新建与停止（backend/app/api/tasks.py）FR-004 FR-005
- [x] T029 [P] 概览大盘：项目列表、全局统计图、新建评估弹窗（Git 地址 / zip 上传）（frontend/src/views/DashboardView.vue、frontend/src/views/dashboard/NewTaskDialog.vue）FR-016
- [x] T030 [P] 工作台监控区：阶段步进器、日志滚动窗、资源曲线、停止按钮，用 fetch 读取 SSE（frontend/src/views/workbench/MonitorPanel.vue、frontend/src/api/sse.ts）FR-014 FR-017 SC-005
- [x] T031 US1 端到端测试：两个靶场跑到 completed，检出结果与 DESIGN.md 第 8 节清单一致、诱饵无 Verified，停止后数据保留（backend/tests/e2e/test_pipeline.py）SC-001 SC-002 SC-006 SC-010

## US2 复核漏洞证据（P1）

- [x] T032 漏洞查询接口：列表、详情、污点步骤、证据、源码文件内容（backend/app/api/findings.py）FR-017
- [x] T033 [P] 工作台漏洞列表：CVSS、分类、验证状态，Verified、Unverified、模型判定误报分组显示（frontend/src/views/workbench/FindingList.vue）FR-017
- [x] T034 漏洞详情：Monaco 定位触发行、污点步骤逐步高亮、请求与响应报文与命中特征（frontend/src/views/workbench/FindingDetail.vue）FR-017

## US3 查看多步攻击路径（P1）

- [ ] T035 攻击路径组装：能力登记、推导规则、DAG 生成、多步路径筛选，含以靶场侦察事实为输入的单元测试（backend/app/chain/、backend/tests/test_chain.py）FR-011 D-008 SC-004
- [ ] T036 推演 Agent：替换占位节点，调用组装并由大模型写阶段说明与业务危害（backend/app/pipeline/agents/chain.py）FR-011
- [ ] T037 [P] 拓扑图：G6 dagre 布局、边上显示能力说明、点击节点打开漏洞详情侧栏（frontend/src/views/workbench/AttackGraph.vue）FR-017

## US4 导出评估报告（P1）

- [ ] T038 [P] 安全评分与综合等级计算（backend/app/report/scoring.py、backend/tests/test_scoring.py）FR-015
- [ ] T039 报告模板与渲染：Jinja2 生成 Markdown 与 HTML，覆盖需求说明 2.5.8 全部章节与图表（backend/app/report/templates/、backend/app/report/render.py）FR-015
- [ ] T040 [P] PDF 导出：Playwright Chromium 打印 HTML（backend/app/report/pdf.py）FR-015 D-007
- [ ] T041 报告 Agent 与报告接口：替换占位节点，汇编报告、预览与三种格式下载、导出写审计日志（backend/app/pipeline/agents/report.py、backend/app/api/reports.py）FR-015 FR-020
- [ ] T042 报告中心页：在线预览、一键导出三种格式（frontend/src/views/ReportCenter.vue）FR-015 SC-008

## US5 查看与采纳修复补丁（P2）

- [ ] T043 补丁生成：大模型输出修复后的完整函数，`difflib` 生成 unified diff（backend/app/patch/）FR-012 D-009
- [ ] T044 补丁接入 report_gen 阶段与报告章节（backend/app/pipeline/agents/report.py、backend/app/report/templates/）FR-012 FR-015
- [ ] T045 补丁接口：查询、下载 .patch、采纳并写审计日志（backend/app/api/patches.py）FR-013 FR-020
- [ ] T046 [P] 补丁 Diff 区：Monaco DiffEditor 左右对比、复制、下载、采纳按钮（frontend/src/views/workbench/PatchPanel.vue）FR-013
- [ ] T047 补丁端到端检查：靶场每条 Verified 漏洞都有补丁，全部通过 `git apply --check`（backend/tests/e2e/test_patches.py）SC-003

## US6 系统管理（P3）

- [ ] T048 配置接口：镜像列表、超时、资源配额、并发数、PyPI 地址、大模型参数与开关、网络策略只读，修改写审计日志（backend/app/api/settings.py）FR-018 FR-020
- [ ] T049 [P] 沙箱与环境配置页、审计日志查询页（frontend/src/views/admin/）FR-018 FR-020
- [ ] T050 权限测试：非管理员访问配置与审计接口返回 403，研发人员新建与停止评估返回 403（backend/tests/test_permissions.py）SC-009

## 收尾

- [ ] T051 对照 SPEC.md 每条 FR、SC 和各场景验收逐条核对，录制演示截图（docs/screenshots/）
