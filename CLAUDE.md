# sec-assess 自动化安全评估系统

需求见 docs/需求说明.md（项目实战 2.5），规格与决策记录见 docs/SPEC.md，实现方案见 docs/DESIGN.md，任务清单见 docs/TASKS.md。

## 项目约束
- 动态验证只在本系统创建的隔离容器内、针对容器里的工程副本进行，容器不接外网
- 首版只完整支持 Python（Flask）工程
- 本机无 CUDA；Docker Desktop 需先启动

## 工作纪律
- 练手项目，提交时按“组名_姓名_项目_行业”另行复制改名，只放代码（不带依赖）和测试截图
- 真实密钥只放 .env，不写入代码、文档、日志或提交
- 实现范围与取舍以 docs/DESIGN.md 为准，方案变更时同步更新 DESIGN.md 与 SPEC.md 决策记录，完成任务时勾选 TASKS.md
