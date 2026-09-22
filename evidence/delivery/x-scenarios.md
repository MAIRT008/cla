# X01—X20 跨模块模拟综合验收

日期：2026-09-14。对应 [ACCEPTANCE.md 第 2 节](../../DOCS/ACCEPTANCE.md)的二十条新增跨模块场景。

```powershell
node tests/delivery/run-acceptance.mjs test
```

退出码 0，`tests 60 / pass 60 / fail 0`（X01—X20 加缺口补充、平台层与正式链路用例）。全部在项目内合成资料上运行，未触真实 Profile、网络、模型或系统设置。

## 组合方式

场景按被验证的边界选组合根，不新建第二套装配：

| 组合根 | 用于 | 说明 |
|---|---|---|
| `apps/desktop-ui/compose.mjs` | X01—X08、X12—X19 | 产品的应用组合根，注入 T2/T3/T4/T5/T6/T7 |
| `fixtures/control/harness.mjs` | X09—X11、X17、X20 | T6 既有的管理后台夹具，含权威替身与三用户资源 |
| `fixtures/delivery/aiScripts.mjs` | X01、X02、X04、X18 | 合成模型脚本，复用 `fixtures/ai/model-scripts.mjs` 的 `completion`/`tool` |

## 逐条结果

| 编号 | 用例 | 实际观察到 |
|---|---|---|
| X01 | `tests/delivery/x01-x05.test.mjs`「X01 AI 规划混合 JSON」 | AI 规划停在 `AWAITING_CONFIRMATION`，确认后 13 项逐条备份执行，回执数等于确认条数；`settings.json` 里只有选中的受限账号字段被清除，其他字段与项目/审计/备份三个非目标文件字节不变；复查后新出现的条目再执行被 `NOT_CONFIRMED` 拒绝 |
| X02 | 同文件「X02 模型越权请求被客户端拒绝」 | `RunShellCommand` → `AI_TOOL_NOT_ALLOWED`；越界 object_ref → `AI_TOOL_SCOPE_DENIED`；伪造确认执行 → `AI_CONFIRMATION_REQUIRED`；随后合法的 `BuildActionPlan` 仍产出计划，`operation_id` 始终为 null，非目标文件不变 |
| X03 | 同文件「X03 确认后目标改变暂停」 | 漂移文件的动作回执 `FAILED/STALE_PLAN`，注入值未被覆盖；同一 `operation_id` 重放返回同一 operation，已成功的 `delete_file` 回执与 `backup_ref` 不变，回执条数不增 |
| X04 | 同文件「X04 客户端包与上传内容不含模型配置」 | `app.bundle.js` 不含模型端点、密钥或 key 字段名；外发请求的 model 由服务端选择，消息体不含合成凭据；任务记录里 `prompt_version=cleanup-v1` 且能在 `src/core/ai/prompts/cleanup.mjs` 定位；服务端事件不含凭据 |
| X05 | 同文件「X05 默认浏览器与内嵌 WebView 不同」 | 发现结果带出实际 `profile_ref`；伪造 nonce 的回传被 `NONCE_INVALID` 拒绝；正确 nonce 的回传写回 `Profile 1`，未知观测不被改写为 PASS |
| X06 | `tests/delivery/x06-x11.test.mjs`「X06 三模式依次切换」 | 三套方案的 `claude.exit` 恒为 A 且 `rotate=false`；双 IP 的 `other.exit=B`；专用模式 `whitelist.enabled=false` 而 `whitelist_retained=true`，`tun_required=true`；切换后白名单条目仍在库里 |
| X07 | 同文件「X07 固定出口故障后终止内核」 | 保护结果里请求（`requested`）、生效（`status=CONFIRMED`、`new_connections_restricted`）、断开与禁止重连分别记录且带时间；`core_crash` 保持 OS 保护且 `direct_released=false`；`close_window` 的 `core_stopped=false`；`stop_management` 明确 `claude_unprotected` 且要求单独确认 |
| X08 | 同文件「X08 手动应急走可区分的第二浏览器」 | 未确认时 `EMERGENCY_NOT_CONFIRMED`；确认后打开 `firefox.exe`，`claude_protected=true`，`general_emergency=OPEN`，有到期时刻；手动结束记 `USER_ENDED`；另起一次并把时钟推过到期时刻后，**不再调用 `endEmergency`**：走常规 `readState` 就由到期清扫关闭，记 `EXPIRED`、`ended_at` 等于当前时刻、宿主会话 `open=false`、Claude 仍受保护且不声称主线已恢复 |
| X09 | 同文件「X09 共享池内甲额度耗尽」 | 甲被服务端判 `LIMITED`，A 与 B 的新连接都被 `USER_LIMITED` 拒绝且节点侧有 remove 处置；乙丙状态未变且仍可开连接 |
| X10 | 同文件「X10 重装、改本机时间、恢复旧配置、换模式」 | 改时钟、重跑同一 allocate operation 后用量仍是 900；停用后跨周期仍为 `DISABLED`；另在应用组合根上真的切到专用模式再恢复上一配置，服务端限额、用量与状态三项都不变 |
| X11 | 同文件「X11 上游池耗尽、用户超额与后台失联」 | 池 `exhausted=true` 且 `user_quota_sum_is_not_pool=true` 时用户不判超额；用户超额单独变 `LIMITED`；权威失联时快照 `stale=true` 且不被读成不限量；失联期间节点仍拒绝该用户新连接 |
| X12 | `tests/delivery/x12-x16.test.mjs`「X12 未知进程与短连接缺测保留」 | 未知记录保留在 `routeCounts.unknown`；字节来自计量样本而不是日志条数；计数器重置产生覆盖缺口而不是补零；双 IP 下 A/B 两条出口同时存在，权威快照的 `split_ab`、上下行均为带原因的 `UNKNOWN`，报告里没有把本机总量命名成 Claude 或 A 的用量 |
| X13 | 同文件「X13 日报 FAIL 与覆盖不足并列」 | `routeResult=FAIL` 与 `coverageStatus=MONITORING_INCOMPLETE` 并列且 `DELIVERED`；AI 附注 `affectsStandardFacts=false`，写入后已交付 JSON 字节不变；再次交付返回 `ALREADY_DELIVERED`，报告仍只有一份 |
| X14 | 同文件「X14 源日志意外含秘密作为异常处理」 | 含凭据的源日志记入 `restrictedExceptions/SECRET_MATERIAL`，归档树里搜不到该凭据；分类版本由程序给出 |
| X15 | 同文件「X15 休眠错过 09:00 后首次唤醒补做一次」 | 09:00 前 `BEFORE_0900`；11:00 首次唤醒 `due=true`；交付后重复唤醒 `ALREADY_DELIVERED`；只有当天一份报告，MD/JSON 与序列化结果逐字节一致；重启按 `protection_first` 先于 `load_last_valid_unrevoked`、不放出未知代理，唤醒标覆盖缺口，期望版本与实际加载分开可读，升级失败回到上一有效配置且不重置额度 |
| X16 | 同文件「X16 恢复时字段已被用户改动」 | 无关字段改动时预览 `recoverable=true` 无冲突；目标字段被他人写入后 `recoverable=false` 且冲突可见，强行恢复被 `RESTORE_CONFLICT` 拒绝；外部改动与项目资料都原样保留；卸载只撤销本应用拥有且未被外部改动的设置，其余按 `EXTERNAL_MODIFICATION`/`NOT_OWNED` 写明；恢复原网络要单独确认且失去保护写明 |
| X17 | `tests/delivery/x17-x20.test.mjs`「X17 额度耗尽后只开放明确的支持路径」 | 超额时应急目标被收窄为模板声明的支持站点，`general_emergency=INCOMPLETE`，`claude_protected=true` |
| X18 | 同文件「X18 AI 离线、模型失败与预算耗尽」 | 未配置模型时不发放 AI 会话且服务端能力接口回 `UNAVAILABLE`；模型 503 时任务 `MODEL_FAILED` 并保留原因、不产生执行；预算收到 1 轮时 `BUDGET_EXHAUSTED`；三种情况下标准分类结果都还在，非目标文件不变 |
| X19 | 同文件「X19 文件占用与权限不足时逐项失败」 | 权限不足项 `FAILED/ACCESS_DENIED`，占用项 `FAILED/OBJECT_BUSY` 且其同对象后续动作记 `DEPENDENCY_BLOCKED` 而不是硬闯；其余独立项照常 `APPLIED`，整体 `partial`；被拒文件内容完好；磁盘不足时保护保留、停止新归档写入、不删活动证据 |
| X20 | 同文件「X20 节点重启与资源版本更新后账目连续」 | 同一 `eventId` 在 admission 与 metering 两段只计一次，非计量跳数 `NON_METERING_HOP` 不计；流量节点重启是**真的换实例**——丢掉旧内存态，从同一持久层重建一个新的 `createAuthoritySim` 与其传输，新实例 `connections` 为空、同一 `eventId` 仍被去重、用量仍是 400；重新分配使 `assignment_version` 真的递增且账目不变；用户超额后进入 `LIMITED` 并被拒新连接；把控制库关掉、在同一数据库上重建控制节点后，用量 1,001,000、状态仍 `LIMITED`、资源版本保持 |

## 边界与未覆盖

- X05 的「默认浏览器不同于内嵌 WebView」用会话 nonce 与 `profile_ref` 绑定来验证，没有真实的两个浏览器进程。真实 Profile 归属留 T10。
- X07、X08 的内核、TUN、防火墙与第二浏览器都是替身端口；动作与效果的分离是真的，OS 层效果不是。
- X09—X11、X17、X20 的额度权威是 `fixtures/control/authoritySim.mjs`，不是真实 Remnawave 后端与节点。
- X12、X13、X15 用合成日志与计量样本，不是真实 Clash 日志与计数器。
- X19 的占用与权限不足由 `localCapabilities` 注入，真实 Windows 文件锁与 ACL 留 T10。
- X13 的「AI 晚到」用 `appendAiNote` 直接写迟到附注，没有模拟真实的模型延迟时序。
