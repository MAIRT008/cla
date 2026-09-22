# 现成能力复用与适配计划

> v1.3 · 核对日期 2026-09-12。已做官方资料和指定源码阅读；当前可逆施工选择见下段，实际接入与真实运行分别验收，不构成生产能力承诺。

**当前施工决定（2026-09-12）：** Owner 已授权连续完成四模块，真实实验留到最后。桌面沿 CVR v2.5.2 的 Tauri/Rust 实现裁剪复用，Wails 保留后备；模型协议采用固定 OpenAI JavaScript SDK v7.15.0 与必要的窄工具循环，Pi 保留比较记录。依据分别见 [桌面源码对照](../evidence/development/desktop-reuse-decision.md)、[AI 复用决定](../evidence/development/ai-reuse-decision.md)。这项声明更新下文历史比较中的“尚未选择”，并不宣告宿主、真实模型或配额链路已验证。供应商及配额执行点仍待实际资源条件确定；模拟开发先实现适配、真实业务逻辑和消费链，不等待实测。

## 1. 当前比较规则与采用状态

本地历史材料《开发前复用选型初筛》保留当时的研究过程，不作为当前方案包的实施依赖；其中 CVR、Pi 和 Remnawave 的“第一顺位”由本节当前比较规则取代。源码存在相关功能，只能支持进入候选，不能证明本项目的总开发成本更低。桌面底座和 AI 编排均只比较下列两条路线，不预先认定优胜者；用户计量先检查供应商原生能力，缺口明确后再评估受管节点。

| 来源/固定版本 | 可复用 | 必须补的本项目能力 | 采用状态 |
|---|---|---|---|
| [Mihomo v1.19.30](https://github.com/MetaCubeX/mihomo/releases/tag/v1.19.30) | TUN、规则、固定代理链、连接/流量 API | 受管配置生命周期、系统层保护、用户资源分配和验证 | 首选候选，P0 验证，按该版本 LICENSE 处理分发 |
| [Wails v2.14.0](https://github.com/wailsapp/wails/releases/tag/v2.14.0) 轻壳 + Mihomo/已有采集 | Go + Web UI + 系统 WebView、桌面打包基础及已有采集片段 | 内核/服务生命周期、配置应用、退出与恢复、本地工具编排 | 桌面比较路线之一；不预定语言组合和目录 |
| [Clash Verge Rev v2.5.2](https://github.com/clash-verge-rev/clash-verge-rev/tree/v2.5.2) 裁剪复用 | 已有内核生命周期、服务、托盘和桌面能力 | 收窄原配置生成链，接入受管分配及管家流程，调整不符合本项目的启停/恢复行为 | 桌面比较路线之一；按该版本 GPL-3.0 处理取用与分发 |
| 现成模型 SDK + 窄工具循环 | 模型请求、响应解析与适用的流式能力 | 客户端工具调度、取消、业务计划和执行回执；具体 SDK 随服务端模型接入确定 | AI 比较路线之一；不自行重做模型协议层 |
| [Pi agent-core v0.85.1](https://github.com/earendil-works/pi/blob/v0.85.1/packages/agent/README.md) | 自定义工具、执行拦截、顺序执行、事件与代理传输 | 服务器选模型的传输适配、客户端授权校验、业务计划和执行回执 | AI 比较路线之一；只取需要的 SDK 能力，不内嵌编码 CLI |
| 当前供应商原生用户/子账号能力 | 若实际提供，可复用用户计量、额度与停用 | 核对同一用户 A/B 全部路径、在途断流、缓存身份及账目连续性 | 先查合同/接口与实际流量能力；当前适配情况 UNKNOWN |
| [Remnawave backend 3.4.3](https://github.com/remnawave/backend/releases/tag/3.4.3)、[node 3.4.1](https://github.com/remnawave/node/releases/tag/3.4.1) | 用户额度、重置/停用管理及真实节点 | 共享前置到用户 A/B 的链式接入、全部路径受控、在途断流与对账 | 供应商原生能力不足时的单个受管节点候选；版本配套/许可/协议能力须实测 |

### 1.1 桌面按同一业务闭环比较净改造量

CVR 的固定版本[生命周期源码](https://github.com/clash-verge-rev/clash-verge-rev/blob/v2.5.2/src-tauri/src/core/manager/lifecycle.rs)和[服务源码](https://github.com/clash-verge-rev/clash-verge-rev/blob/v2.5.2/src-tauri/src/core/service.rs)已经包含可评估的启停与服务能力；这些实现依赖其原配置和应用状态，不能只按目录中已有功能数量估算省工。两条桌面路线都以同一受管配置的应用、实际回读、UI/内核退出及有效版本恢复为比较样例，列出可直接保留、必须修改、需要补齐的部分及验证结果。加一张管家页面且原服务仍能启动，只证明页面接入，不足以完成底座选择。

若采用 CVR，直接收窄其[原配置生成链](https://github.com/clash-verge-rev/clash-verge-rev/blob/v2.5.2/src-tauri/src/enhance/mod.rs)。该链目前组合 profile、规则/代理组、全局与局部 merge/script、DNS/TUN 设置；本项目让后台分配版本与唯一用户白名单进入同一受管生成/应用路径。原订阅刷新、profile 切换、任意规则编辑、脚本覆盖和恢复入口按需要收窄或改接；隐藏页面不能代替写入口接管。方案切换、FD-02 修复、常规更新与恢复共用这一入口，不在 CVR 外再加第二个配置管理器。对应 FD-03/F18、F23—F25、F37，具体责任见 [接口](INTERFACES.md) §4。

### 1.2 AI 复用模型能力，业务确认与执行保持本地共用

两条 AI 路线共用 FD-01/F08、F21—F25 的同一合成混合配置闭环：客户端提示词和脱敏事实经本应用服务器调用模型，AI 补充受限读取并生成精确计划，用户确认后由 AI 调用本地工具处理并复查。比较事件、取消、等待确认后的继续执行和传输适配实际需要多少代码，再决定是否采用 Pi 的 Agent 层，不为引入 SDK 额外增加独立 Node 服务或第二个 AI 后台。

Pi 的 [streamProxy 固定源码](https://github.com/earendil-works/pi/blob/v0.85.1/packages/agent/src/proxy.ts)由客户端提交 model、context 和 options。它证明可以经自有后台传输，尚不直接证明符合本项目“服务器选择模型、端点、密钥和参数”的责任分配。采用时通过小型传输适配接本应用后台：客户端发送提示词、任务类型、工具说明及必要脱敏事实/工具结果，服务器使用自身模型配置与预算；不把客户端传来的模型配置直接当成服务器权威。提示词源仍在客户端，密钥不下发，见 [接口](INTERFACES.md) §3。

用户确认后，具体对象与动作固定到已确认的业务计划。AI 一次调用 ExecuteConfirmedPlan 执行本次已确认清单，本地执行器完成逐项授权/指纹校验、备份、精确修改和复查，返回分项回执，再由 AI 解释结果；无需每处理一个文件都重新请求模型决定。标准模式共用同一执行器。计划、确认、恢复引用与实际回执保存在同一本地业务记录中，不以 SDK 内部会话作为唯一记录；AI 仍主导识别、计划和获确认工具调用，不降为报告润色。

### 1.3 先验证全链和用户账目，再选择配额面板

先确认当前供应商是否已有真实用户/子账号的计量与停用接口。若满足需求，直接接入；不能仅因开源面板已有用户页面而新增受管节点。若存在明确缺口，先把客户端、计量执行点、共享前置与最终 A/B 的实际链路顺序、各段协议和身份位置画清，确认如何由同一用户身份覆盖 A/B、如何选择唯一计量点且不重复扣量，再用一个 Remnawave 候选验证。面板选型不能先于这些条件。

Remnawave [用户文档](https://docs.rw/learn-en/users/)描述用户流量限制、重置与状态；[节点文档](https://docs.rw/learn-en/nodes/)明确实际流量在节点，面板不是转发内核。由此可将其列为候选，但不能推断装面板就能给任意共享订阅分别记账。本项目是否适配当前上游仍 UNKNOWN。

只有 Remnawave 对上述链路、用户控制或维护方式存在明确不足，才将 [Marzban v0.8.4](https://github.com/Gozargah/Marzban/tree/v0.8.4)作为针对该缺口的对照，不同时搭建两套面板。其已核对[额度检查源码](https://github.com/Gozargah/Marzban/blob/v0.8.4/app/jobs/review_users.py)与[配置](https://github.com/Gozargah/Marzban/blob/v0.8.4/config.py)只能说明现有计量/停用实现，不能替代本项目的在途断流实测。三用户共享资源、耗尽者全部代理路径停用而另外两人继续，以及 A/B 同账、重装/恢复不重置的验证仍按 FD-03/F29—F36 执行。

### 1.4 选择出口与验证边界

每条路线仅记录采用版本、直接复用部分、必要改动、实际验证结果、放弃备选理由及维护/许可要求。当前阅读证据不填写产品测试 PASS；上述比较完成后才固定桌面/AI 技术组合与配额接入方式，再更新对应目录和工期。无需增加新框架、统一选型平台或新的审批层。

Mihomo [连接接口](https://wiki.metacubex.one/api/)提供连接、字节和路由信息；关闭连接的 API 不等于禁止后续新连接。Windows [WFP 官方介绍](https://learn.microsoft.com/en-us/windows/win32/fwp/about-windows-filtering-platform)可作为系统层保护选项，是否满足当前应用/失效边界由测试决定。

## 2. 检测与恢复参考仓库

| 已读取固定源码 | 复用范围 | 不能照搬 |
|---|---|---|
| [TZZ520/claude-environment-check @723385d](https://github.com/TZZ520/claude-environment-check/tree/723385d6e07052196fe0e2df4647c7c88882c993)；Apache-2.0 | Go 本机检查、Wails 组织、浏览器采样实现 | 把环境变量代理称为系统真实代理；TUN 下“未设代理”不证明直连；重用采集而非未经验证风险分 |
| [stormzhang/ipcheck @a8daf6a](https://github.com/stormzhang/ipcheck/tree/a8daf6adcfe37435fd819a8c0c98828f6f92b7fc) | IP/DNS/端点检测思路与部分采集逻辑 | 国内回显服务请求未必走直连，不能当真实 ISP IP。该 commit 的 LICENSE 为 Apache-2.0，README 却写 MIT，采用按实际文件核对 |
| [yiancode/fuck-claude @51cd25c](https://github.com/yiancode/fuck-claude/tree/51cd25cbca17f2ab6f8a567ef50e9cd92934c702)；MIT | apply/restore 配对和修改前状态保留思路 | 默认改系统时区/语言、批量强杀 Chrome/Edge/Brave、创建隔离环境不进入本项目自动流程 |
| [yacuo/check-cc](https://github.com/yacuo/check-cc)、[LinXiaoTao/FuckClaude](https://github.com/LinXiaoTao/FuckClaude) | 浏览器信号与用户解释参考 | 网页能力不等于桌面修复已实现；不复制风险分或未授权服务 API。若取代码需先固定 commit |
| [CleanIP](https://cleanip.io/) | 产品检测项与解释方式的对标 | 不是已授权 API/源码供应商，不照搬页面所有商业功能 |
| [nmhjklnm/cac](https://github.com/nmhjklnm/cac) | 隔离方向留作后续资料 | 首版不引入其多身份隔离、Docker 或身份修改链路 |

这些判断来自源码/官方资料阅读，不是本轮安装后的跑分。没有直接复用价值的组件不因“开源可用”自动并入。

## 3. Owner 历史方案如何继承

| 已核对材料 | 保留内容 | 产品化调整 |
|---|---|---|
| 本地清理清单及定向清理历史 | 整文件与字段/记录操作区别，正常账号保留、项目保护、清理后回读 | 用真实发现和合成正反样例代替硬编码个人路径；AI 负责识别与规划 |
| 固定出口方案 | TUN/规则、前置与最终 A 分开、固定链故障保持失败、未知出口不兜底 | 按用户资源渲染，支持三模式与有范围的手动应急入口 |
| archive-run.ps1 / replay-logs.ps1 / route-classifier.ps1 | 两小时归档、声明版本分类器、旧 v2 样例与窗口证据思路 | 个人组名改为新版本映射；补报告有效性、秘密预检、并列状态和 AI 附注 |

本轮审计已读取三个脚本；旧 v2 八条合成用例通过，覆盖固定正确路线、错误拨号、DIRECT、REJECT、旧版进程、恶意后缀、通用 Chrome 和通用 node 场景。未运行生产归档或实时网络故障试验。

旧脚本仅以两份文件非空判日报交付，产品还需验证 JSON/MD 对应的窗口和结构。旧 v2 把个人 chrome.exe 整体纳入 Claude，不能直接把所有新用户 Chrome 流量如此命名。保持旧 v2 不变，产品映射另声明版本。

不默认复制个人原脚本到公开包：其中路径、节点名、原始日志和运行控制信息需移除。开发时先建立合成样例，再提取公共实现；复用验收是同一输入得到一致分类，后续需求差异用新版本解释。

## 4. 前置链性能优化

历史配置采用较大的共用前置候选池，前置节点的单独健康检查未必反映穿过最终 A/B 的连接质量。可复用 [dialer-proxy](https://wiki.metacubex.one/config/proxies/dialer-proxy/) 与 [url-test](https://wiki.metacubex.one/config/proxy-groups/url-test/) 能力验证全链，不新增独立调度平台。

先在不改变 A/B 的前提下测完整链的成功率、连接延迟中位数/P95和切换次数。若 A/B 的最佳前置相同，只缩小公共候选池；若确实不同，再为 A/B 各保留 3—4 个已验证前置。检测目标与频率计入流量预算，避免不断测速。

此为性能优化，不是首版新增阻断项，也不预先承诺降低到某个毫秒数。先把固定出口和断流闭环做好，有测量证据再采用。
