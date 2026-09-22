# Claude 环境管理应用

> 项目开发方案 v1.3；当前施工安排更新于 2026-09-21。已有业务与离线合成成果，完整产品补齐中，尚无经过整体验收的客户端安装包。

**直接使用本目录中的文档即可，无需下载或解压“方案包”。** README.md 是入口，ARCHITECTURE.md 是架构，DOCS/ 保存功能需求、复用方案、开发计划和验收标准。dist/ 的 ZIP 及其展开目录只是此前导出的快照，后续实施以项目内当前文件为准。

**当前项：RC6 发布候选交付与全链实现复核。OPUS 已按[施工单](evidence/development/opus-rc6-release-candidate-task.md)施工，RC6 Round 1 复核 FAIL（1 BLOCK、3 MAJOR、1 MINOR），Round 2、Round 3 复核都 FAIL（各 2 BLOCK、1 MAJOR）；Round 4 限定整改（[Round 4 交接](evidence/development/rc6-round4-handoff.md)）于 2026-09-21 复核 PASS WITH DEBT。RC6 仍 `NOT_READY`、未关闭，下一步由 Owner 准备构建机与隔离验收机，完成 Rust/NSIS 构建和 E53—E58；独立验收与技术裁决仍由当前验收 Agent（本任务）负责。** RC1—RC5 已按离线阶段关闭，最近一项 RC5 于 2026-09-21 经 Round 2 限定复核 PASS WITH DEBT（[Round 2 交接](evidence/development/rc5-round2-handoff.md)）。Rust 宿主、网络服务与控制端仍未编译/运行；SCM/pipe、Mihomo、WFP、真实网络、真实日志与睡眠唤醒仍未验证。见 [项目工作规则](AGENTS.md)与 [完整产品补齐计划](evidence/development/product-completion-plan.md)。

**先补齐客户端、服务器端、四模块、内核接入代码和交付流程，再到其他电脑统一验收。** T9 通过仅代表原离线阶段；T1 未关闭，T10 未启动。不得以 E01 未执行为由停止其他实现。本机只做项目内开发和离线模拟，保持网络与运行环境稳定；最终测试机上的报错需保存到本地日志，用于集中修复与复测。历史阶段见 [连续计划](evidence/development/implementation-plan.md)。

把已有的 Claude 清理和固定出口方案做成普通用户能使用的环境管家：自动扫描、AI 判断、展示处理清单、用户确认、程序精确处理并复查；内置 Clash，后台配置资源，用户切换三套网络方案，查看流量与每日分析。没有聊天框。

**AI 主导识别与处理规划，调用客户端受限工具完成获确认的操作。模型服务配置在服务端，提示词在客户端。** 首版不建隔离工作台，不要求用户安装 WSL、Docker 或独立浏览器引擎。

先看 [完整首版方案](DOCS/V1_PLAN.md)，再看 [复用比较与采用条件](DOCS/REUSE_PLAN.md)和[开发计划与工期](DOCS/IMPLEMENTATION_PLAN.md)。桌面与 AI 路线按实际改造量选择，供应商原生配额优先；6—8 周仅为待选型校正的原参考，文档通过不表示技术已经定型。

| 需要了解 | 文档 |
|---|---|
| 产品目标与用户流程 | [项目说明](PROJECT_OVERVIEW.md) |
| 已确认范围、首版支持建议 | [首版范围](DOCS/RELEASE_SCOPE.md) |
| 组件、数据与调用关系 | [架构](ARCHITECTURE.md)、[接口](DOCS/INTERFACES.md) |
| 启停、应急上网、浏览器与恢复 | [运行行为](DOCS/RUNTIME_BEHAVIOR.md) |
| 开源复用、固定版本与差距 | [复用计划](DOCS/REUSE_PLAN.md) |
| 隐私、AI 工具与配置授权 | [数据和权限](DOCS/SECURITY_PRIVACY.md) |
| 验收、覆盖和未验证状态 | [综合验收](DOCS/ACCEPTANCE.md)、[机器索引](DOCS/index/spec-index.json) |
| 已确认依据、仍待验证的选择 | [决策依据](DOCS/SOURCE_DECISIONS.md)、[待定决策](DOCS/OPEN_DECISIONS.md) |
| 修改与历史材料说明 | [本次补齐记录](DOCS/CHANGELOG.md) |

四份详细 FD 保留原编号及 v1.2 业务基线，文件名中的 v1.0 仅用于兼容引用。v1.3 更新配套实现方案、工具调用方式、选型顺序和任务依赖，未削减四模块功能或原验收。

- [FD-01：本地文件检测与清理](DOCS/01_Claude检测_本地文件环境检测与清理_功能文档_v1.0.md)
- [FD-02：网络与浏览器检测及优化](DOCS/02_Claude检测_网络与浏览器环境检测诊断及优化_功能文档_v1.0.md)
- [FD-03：内置 Clash、托管方案与用户配额](DOCS/03_内置Clash_托管网络方案与用户流量配额管理_功能文档_v1.0.md)
- [FD-04：流量监测、紧急保护、归档和日报](DOCS/04_流量监测_紧急保护日志归档与每日审计_功能文档_v1.0.md)

[文档索引](DOCS/DOCUMENT_INDEX.md)覆盖 146 项功能、126 项原验收场景、80 条规则；新增跨模块验收使用 X 编号，不重排 FD。数量表示需求覆盖，不表示功能已经完成。

在项目根目录执行：

```powershell
python tools/verify_documents.py
```

校验当前文档链接、编号与行号、来源哈希、任务覆盖、Mermaid 图源，结果见 [文档校验](DOCS/index/document-validation.json)。这是文档验证，不是产品测试。

当前 Markdown 是后续选型验证和实施的方案依据，所需测试资源及产品施工按任务授权执行。dist/ 下 v1.2、v1.3 ZIP 及展开目录保留为当时导出的历史快照，不自动跟随源文档更新，也不覆盖当前项目文件；仅在需要传递副本时重新导出。原 Word、PNG、空的 v1.1 ZIP 属于历史接收材料，**不包含后续修订，不用于实施**。修改前八份 Markdown 仍在 history/pre-v1.2-20260912，原审计报告保持原样。未安装软件、改动网络、提交 Git 或发布到外部仓库。
