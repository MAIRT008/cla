# 文档与需求编号索引

> v1.3。读取顺序：README → 首版范围 → 架构 → 当前 FD 完整相关章节 → 复用比较/接口/运行行为 → 开发任务与验收。

| 模块 | 文件 | 功能前缀/数量 | 验收/规则 |
|---|---|---|---|
| FD-01 | [本地检测清理](01_Claude检测_本地文件环境检测与清理_功能文档_v1.0.md) | F01—F28 / 28 | A22 / R14 |
| FD-02 | [网络浏览器](02_Claude检测_网络与浏览器环境检测诊断及优化_功能文档_v1.0.md) | N01—N34 / 34 | A28 / R18 |
| FD-03 | [托管网络配额](03_内置Clash_托管网络方案与用户流量配额管理_功能文档_v1.0.md) | F01—F40 / 40 | A34 / R22 |
| FD-04 | [监测保护日报](04_流量监测_紧急保护日志归档与每日审计_功能文档_v1.0.md) | F01—F44 / 44 | A42 / R26 |

总计 146 项功能、126 个原验收、80 条规则。完整编号、标题、当前文件行号和 SHA-256 由 [spec-index.json](index/spec-index.json)提供。FD-02 保持 N 前缀；A/R 必须连同 FD 引用，避免跨模块重号。

[实现任务覆盖](index/implementation-coverage.json)给每条功能指定主阶段和对应模块原验收集；它只表示任务没有漏项，不证明某条验收已经通过。[来源清单](index/source-manifest.json)区分当前修订与修改前快照。[文档验证](index/document-validation.json)单独记录结构检查。

| 配套资料 | 用途 |
|---|---|
| [V1_PLAN](V1_PLAN.md) | Owner 可连贯阅读的完整方案 |
| [RELEASE_SCOPE](RELEASE_SCOPE.md) | 首版四模块与支持范围建议 |
| [SOURCE_DECISIONS](SOURCE_DECISIONS.md) | 原对话/当前明确要求和建议的分界 |
| [INTERFACES](INTERFACES.md) | AI 工具、版本应用、配额、浏览器与报告交接 |
| [RUNTIME_BEHAVIOR](RUNTIME_BEHAVIOR.md) | 启停/升级/卸载/应急/恢复默认提案 |
| [SCORING_AND_ROUTING](SCORING_AND_ROUTING.md) | 网络评分、根因去重、缺测处理和基础路由模板提案 |
| [REUSE_PLAN](REUSE_PLAN.md) | 现成组件版本、复用边界、源码事实 |
| [IMPLEMENTATION_PLAN](IMPLEMENTATION_PLAN.md) | 分阶段任务、拟改路径、依赖与工期 |
| [ACCEPTANCE](ACCEPTANCE.md) | 原 A 场景与新增 X 场景的产品验收 |
| [OPEN_DECISIONS](OPEN_DECISIONS.md) | 尚待实测的选型和具体数值提案 |
| [SECURITY_PRIVACY](SECURITY_PRIVACY.md) | AI数据流、受限工具、共享订阅与隐私 |
| [CHANGELOG](CHANGELOG.md) | 本次修改、历史材料与未实施边界 |

当前 FD 文件名保留 v1.0 仅为兼容原路径，其 v1.2 业务基线本轮未改；v1.3 包更新配套实现方案与任务依赖。未改内容可保留原修订版本，机器索引记录当前字节和行号。原 Word/PNG 不自动同步，属于历史阅读材料；不要按其中旧的 AI 只读、未定部署或海报工期实施。
