const NET = 'src/core/network/controller.mjs';
const APPLY = 'src/core/network/apply.mjs';
const COMPILE = 'src/core/network/compile.mjs';
const ASSIGN = 'src/core/network/assignment.mjs';
const WL = 'src/core/network/whitelist.mjs';
const STATE = 'src/core/network/state.mjs';
const LIFE = 'src/core/network/lifecycle.mjs';
const EMERGENCY = 'src/core/network/emergency.mjs';
const QUOTA = 'src/core/network/quota.mjs';
const CREDS = 'src/core/network/credentials.mjs';
const YAML = 'src/core/network/yaml.mjs';
const PROTECT = 'src/core/network/protection.mjs';
const CONTROL_NET = 'services/control/network.mjs';
const CONTROL_ROUTES = 'services/control/networkRoutes.mjs';
const QUOTA_ADAPTER = 'services/control/index.mjs';
const NATIVE = 'src/adapters/network/nativeHost.mjs';
const UI_SESSION = 'apps/desktop-ui/session.mjs';

const ASSIGNMENT = ['tests/network/assignment.test.mjs', 'FD-03/A01-A04 A09-A11 三用户分配与路由矩阵'];
const WHITELIST = ['tests/network/whitelist.test.mjs', 'FD-03/A05-A08 白名单范围、冲突与模式保留'];
const APPLYT = ['tests/network/apply.test.mjs', 'FD-03/A12-A13 A25-A29 A31 应用、回读、恢复与重试'];
const LIFECYCLE = ['tests/network/lifecycle.test.mjs', 'FD-03/A30 RUNTIME §1 生命周期动作与效果分开'];
const EMERGENCYT = ['tests/network/emergency.test.mjs', 'FD-04/F22 RUNTIME §2 手动应急'];
const NETQUOTA = ['tests/network/quota.test.mjs', 'FD-03/A18-A24 A28-A29 超额消费与权威故障'];
const PROTOCOL = ['tests/network/protocol.test.mjs', 'FD-03/A27 A32-A34 协议适配与控制器消费'];
const SEC_OWNER = ['tests/network/security.test.mjs', 'BLOCK2 不能应用他人 Assignment，operation_id 按用户隔离'];
const SEC_RESTORE = ['tests/network/security.test.mjs', 'BLOCK3 恢复要授权并保持限额，保护失败不得加载配置'];
const SEC_EMERGENCY = ['tests/network/security.test.mjs', 'BLOCK4 应急绑定进程、非递归组，限额结束仍 REJECT'];
const SEC_PROTECT = ['tests/network/security.test.mjs', 'BLOCK5 当前连接经 T2 分类后立即保护'];
const SEC_PATHS = ['tests/network/security.test.mjs', '控制器把批准的完整进程路径传到 Windows 保护适配器'];
const SEC_SCOPE = ['tests/network/security.test.mjs', '未批准 state 不能覆盖当前 Assignment 的批准范围'];
const SEC_NATIVE = ['tests/network/security.test.mjs', '原生宿主实际发送 Mihomo 请求并注入保护 invoke'];
const CTRL_API = ['tests/network/control-api.test.mjs', 'MAJOR6 正式 HTTP Assignment 下发受管模板，编译不回落硬编码 DNS'];
const CTRL_LIVE = ['tests/network/control-api.test.mjs', 'BLOCK5 liveTransport 连接快照不是配置投影，并提供 traffic/logs 流'];
const CQUOTA_HARD = ['tests/control/quota.test.mjs', 'FD-03/A14-A21 单点计量、硬限额替身与超额暂停'];
const CQUOTA_REBUILD = ['tests/control/quota.test.mjs', 'FD-03/A18 A23 A29 客户端重建、改时钟和应用库重开不清权威账'];
const CQUOTA_POOL = ['tests/control/quota.test.mjs', 'FD-03/A22-A24 池耗尽、调额恢复原 A/B、查询失败保留快照'];
const CQUOTA_IDEM = ['tests/control/quota.test.mjs', 'FD-03/A32 同一 operation 重试不多建用户，产品拒绝无限额'];
const CRESOURCES = ['tests/control/resources.test.mjs', 'FD-03/A01-A03 A33 三用户资源隔离、未分配与无 B 不能发布双 IP'];
const CEVENTS = ['tests/control/events.test.mjs', 'FD-03/A32-A33 FD-04/A20 最小事件隔离、幂等与秘密拒绝'];
const CTEMPLATE = ['tests/control/events.test.mjs', 'FD-03/A08 A25 模板更新不覆盖分配，敏感 A 变更需确认'];
const CSUB = ['tests/control/events.test.mjs', '订阅刷新解析 Clash YAML，未知格式不冒充完成'];
const CPROTO = ['tests/control/protocol.test.mjs', 'FD-03/A27 A34 固定方法/路径/字段与错误响应'];
const CFIX_IDENTITY = ['tests/control/review-fix.test.mjs', 'BLOCK 不同应用用户不能落到同一 provider 身份'];
const CFIX_STALE = ['tests/control/review-fix.test.mjs', 'MAJOR 权威未配置时保留最后快照并标 STALE/OFFLINE'];
const CFIX_OFFLINE = ['tests/control/review-fix.test.mjs', 'MAJOR HTTP client 离线保留刚读到的 Assignment 和 Quota'];
const CFIX_DISABLE = ['tests/control/review-fix.test.mjs', 'MAJOR 停用效果不可由调用者伪造，过期 Assignment 不能恢复'];
const CFIX_LOST = ['tests/control/review-fix.test.mjs', 'MAJOR 丢失 disable 响应后同 operation 不二次执行'];
const CFIX_SUBSRC = ['tests/control/review-fix.test.mjs', 'MAJOR 订阅来源可创建，HTTP 失败不能标 ACTIVE'];
const T4_NET = ['tests/ai/networkT5.test.mjs', 'T5 网络口接入 AI 已确认计划且不另建配置工具'];
const UI_J4 = ['tests/ui/journeys.test.mjs', '旅程4 方案切换'];
const UI_J6 = ['tests/ui/journeys.test.mjs', '旅程6 管理员调额只影响目标用户'];
const UI_J8 = ['tests/ui/journeys.test.mjs', '合成宿主关闭重启后从既有存储挂载'];
const X06 = ['tests/delivery/x06-x11.test.mjs', 'X06 三模式依次切换'];
const X07 = ['tests/delivery/x06-x11.test.mjs', 'X07 固定出口故障后终止内核'];
const X08 = ['tests/delivery/x06-x11.test.mjs', 'X08 手动应急走可区分的第二浏览器'];
const X09 = ['tests/delivery/x06-x11.test.mjs', 'X09 共享池内甲额度耗尽'];
const X10 = ['tests/delivery/x06-x11.test.mjs', 'X10 重装、改本机时间、恢复旧配置、换模式'];
const X11 = ['tests/delivery/x06-x11.test.mjs', 'X11 上游池耗尽、用户超额与后台失联'];
const X17 = ['tests/delivery/x17-x20.test.mjs', 'X17 额度耗尽后只开放明确的支持路径'];
const X20 = ['tests/delivery/x17-x20.test.mjs', 'X20 节点重启与资源版本更新后账目连续'];
const X18 = ['tests/delivery/x17-x20.test.mjs', 'X18 AI 离线、模型失败与预算耗尽'];
const PROTOCOL_SOURCE = 'evidence/development/protocol-source.md';

export const FD03 = [
  {ids: ['R01'], impl: [NET, CONTROL_NET], evidence: [ASSIGNMENT, CRESOURCES], status: 'SIM_PASS'},
  {ids: ['R02'], impl: [`${ASSIGN}#recommendMode`, CONTROL_NET], evidence: [ASSIGNMENT], status: 'SIM_PASS'},
  {ids: ['R03'], impl: [`${COMPILE}#compileNetworkPlan`], evidence: [X06, ASSIGNMENT], status: 'SIM_PASS'},
  {ids: ['R04'], impl: [CONTROL_NET, `${ASSIGN}#validateAssignment`], evidence: [CRESOURCES, ASSIGNMENT], status: 'SIM_PASS'},
  {ids: ['R05'], impl: [`${COMPILE}#expectedRouteMatrix`], evidence: [X06], status: 'SIM_PASS'},
  {ids: ['R06'], impl: [`${COMPILE}#compileNetworkPlan`, `${WL}#activeWhitelist`], evidence: [WHITELIST, X06], status: 'SIM_PASS'},
  {ids: ['R07'], impl: [`${WL}#claudeConflict`], evidence: [WHITELIST], status: 'SIM_PASS'},
  {ids: ['R08'], impl: [`${COMPILE}#compileNetworkPlan`], evidence: [X06], status: 'SIM_PASS'},
  {ids: ['R09'], impl: [`${WL}#activeWhitelist`], evidence: [WHITELIST, X06, UI_J4], status: 'SIM_PASS'},
  {ids: ['R10'], impl: [`${ASSIGN}#recommendMode`, `${ASSIGN}#explainRecommendation`], evidence: [ASSIGNMENT], status: 'SIM_PASS'},
  {ids: ['R11'], impl: [CONTROL_ROUTES], evidence: [CQUOTA_HARD, UI_J6], status: 'SIM_PASS'},
  {ids: ['R12'], impl: [`${QUOTA}#readQuotaView`, QUOTA_ADAPTER], evidence: [CQUOTA_HARD, X20], status: 'SIM_PASS'},
  {ids: ['R13'], impl: [QUOTA_ADAPTER], evidence: [X20], status: 'SIM_PASS',
    note: '直连/局域网事件在权威侧记 DIRECT_OR_LAN 不计量。'},
  {ids: ['R14'], impl: [QUOTA_ADAPTER, CONTROL_ROUTES], evidence: [CQUOTA_HARD, X09], status: 'SIM_PASS'},
  {ids: ['R15'], impl: [CONTROL_ROUTES, QUOTA_ADAPTER], evidence: [CQUOTA_REBUILD, X10, UI_J8], status: 'SIM_PASS'},
  {ids: ['R16'], impl: [`${QUOTA}#applyQuotaOperation`, `${APPLY}#applyNetworkPlan`], evidence: [NETQUOTA, SEC_EMERGENCY], status: 'SIM_PASS'},
  {ids: ['R17'], impl: [CONTROL_NET], evidence: [CTEMPLATE], status: 'SIM_PASS'},
  {ids: ['R18'], impl: [`${APPLY}#applyNetworkPlan`, `${COMPILE}#staticValidateConfig`], evidence: [APPLYT], status: 'SIM_PASS'},
  {ids: ['R19'], impl: ['src/adapters/network/controlClient.mjs'], evidence: [CFIX_OFFLINE, CFIX_STALE], status: 'SIM_PASS'},
  {ids: ['R20'], impl: [`${STATE}#readNetworkState`, `${APPLY}#applyNetworkPlan`], evidence: [APPLYT, UI_J4], status: 'SIM_PASS'},
  {ids: ['R21'], impl: ['src/core/ai/tools.mjs#executeClientTool', UI_SESSION], evidence: [T4_NET, X18], status: 'SIM_PASS'},
  {ids: ['R22'], impl: [`${CREDS}#resolveManagedPayload`], evidence: [SEC_OWNER, CFIX_IDENTITY], status: 'SIM_PASS'},

  {ids: ['F01'], impl: [CONTROL_NET], evidence: [CRESOURCES], status: 'SIM_PASS'},
  {ids: ['F02'], impl: [`${COMPILE}#compileNetworkPlan`], evidence: [X06], status: 'SIM_PASS'},
  {ids: ['F03'], impl: [`${ASSIGN}#explainRecommendation`], evidence: [ASSIGNMENT], status: 'SIM_PASS'},
  {ids: ['F04'], impl: [CONTROL_NET], evidence: [CRESOURCES, UI_J6], status: 'SIM_PASS'},
  {ids: ['F05'], impl: [CONTROL_NET], evidence: [CSUB, CFIX_SUBSRC], status: 'SIM_PASS'},
  {ids: ['F06'], impl: [`${COMPILE}#compileNetworkPlan`, `${CREDS}#publicProxies`], evidence: [ASSIGNMENT], status: 'SIM_PASS'},
  {ids: ['F07'], impl: [`${COMPILE}#expectedRouteMatrix`], evidence: [X06], status: 'SIM_PASS'},
  {ids: ['F08'], impl: [`${ASSIGN}#validateAssignment`], evidence: [ASSIGNMENT, CRESOURCES], status: 'SIM_PASS'},
  {ids: ['F09'], impl: [`${LIFE}#advanceLifecycle`, `${APPLY}#authorizationAllows`], evidence: [LIFECYCLE, SEC_SCOPE], status: 'SIM_PASS'},
  {ids: ['F10'], impl: [NET, NATIVE], evidence: [SEC_NATIVE, CTRL_LIVE], status: 'SIM_PASS'},
  {ids: ['F11'], impl: [`${COMPILE}#compileNetworkPlan`, YAML], evidence: [WHITELIST, CTRL_API], status: 'SIM_PASS'},
  {ids: ['F12'], impl: [`${COMPILE}#compileNetworkPlan`], evidence: [X06], status: 'SIM_PASS'},
  {ids: ['F13'], impl: [`${COMPILE}#compileNetworkPlan`], evidence: [X06, ASSIGNMENT], status: 'SIM_PASS'},
  {ids: ['F14'], impl: [`${COMPILE}#compileNetworkPlan`], evidence: [CTRL_API], status: 'SIM_PASS',
    note: '必要基础通信由受管模板给出，不回落硬编码 DNS。'},
  {ids: ['F15'], impl: [`${WL}#mutateWhitelist`], evidence: [WHITELIST, UI_J4], status: 'SIM_PASS'},
  {ids: ['F16'], impl: [`${WL}#claudeConflict`], evidence: [WHITELIST], status: 'SIM_PASS'},
  {ids: ['F17'], impl: [`${WL}#activeWhitelist`], evidence: [X06, UI_J4], status: 'SIM_PASS'},
  {ids: ['F18'], impl: [`${STATE}#readNetworkState`], evidence: [APPLYT, CTRL_LIVE], status: 'SIM_PASS'},
  {ids: ['F19'], impl: [`${NET}#confirmAndApply`], evidence: [APPLYT, UI_J4], status: 'SIM_PASS'},
  {ids: ['F20'], impl: ['src/core/network/observe.mjs#observeNetworkEvidence'], evidence: [SEC_PROTECT], status: 'SIM_PASS'},
  {ids: ['F21'], impl: [`${APPLY}#restoreNetworkPlan`], evidence: [APPLYT, SEC_RESTORE], status: 'SIM_PASS'},
  {ids: ['F22'], impl: [`${LIFE}#executeLifecycle`, 'apps/desktop-host/src-tauri/src/lifecycle.rs#tray_action', 'apps/desktop-host/src-tauri/src/lib.rs#prevent_close'], evidence: [LIFECYCLE, X07, ['tests/delivery/release-candidate.test.mjs', 'RC6 R06 桌面生命周期接线']], status: 'SIM_PASS',
    note: 'RC6：关窗只隐藏到托盘、托盘退出界面只结束 GUI 与托管控制端、不撤保护；宿主 lifecycle.rs 与 lib.rs 未编译，只有源码静态核对，真机待 E53。'},
  {ids: ['F23'], impl: [CONTROL_NET], evidence: [CSUB, CFIX_SUBSRC], status: 'SIM_PASS'},
  {ids: ['F24'], impl: [CONTROL_NET], evidence: [CTEMPLATE], status: 'SIM_PASS'},
  {ids: ['F25'], impl: [CONTROL_NET, `${APPLY}#applyNetworkPlan`], evidence: [CTEMPLATE, APPLYT], status: 'SIM_PASS'},
  {ids: ['F26'], impl: [`${APPLY}#authorizationAllows`], evidence: [CTEMPLATE, SEC_SCOPE], status: 'SIM_PASS'},
  {ids: ['F27'], impl: ['src/adapters/network/controlClient.mjs'], evidence: [CFIX_OFFLINE], status: 'SIM_PASS'},
  {ids: ['F28'], impl: [CONTROL_ROUTES], evidence: [CQUOTA_HARD, UI_J6], status: 'SIM_PASS'},
  {ids: ['F29'], impl: [QUOTA_ADAPTER], evidence: [CQUOTA_HARD, X09], status: 'SIM_PASS'},
  {ids: ['F30'], impl: [QUOTA_ADAPTER], evidence: [X20], status: 'SIM_PASS'},
  {ids: ['F31'], impl: [QUOTA_ADAPTER], evidence: [CQUOTA_HARD, X20], status: 'SIM_PASS'},
  {ids: ['F32'], impl: [QUOTA_ADAPTER], evidence: [X20], status: 'SIM_PASS'},
  {ids: ['F33'], impl: [`${QUOTA}#readQuotaView`], evidence: [CQUOTA_REBUILD, UI_J6], status: 'SIM_PASS'},
  {ids: ['F34'], impl: [`${QUOTA}#deriveQuotaNotice`], evidence: [CQUOTA_POOL, X11], status: 'SIM_PASS'},
  {ids: ['F35'], impl: [`${QUOTA}#applyQuotaOperation`], evidence: [NETQUOTA, X09], status: 'SIM_PASS'},
  {ids: ['F36'], impl: [CONTROL_ROUTES], evidence: [CQUOTA_POOL, UI_J8], status: 'SIM_PASS'},
  {ids: ['F37'], impl: ['src/core/diagnostics/plans.mjs#executeConfirmedDiagnosticPlan'], evidence: [['tests/diagnostics/review-fix.test.mjs', 'BLOCK 恢复引用用 T5 apply 回执，演练未验证不声明已恢复']], status: 'SIM_PASS'},
  {ids: ['F38'], impl: ['src/core/ai/tools.mjs#executeClientTool'], evidence: [T4_NET], status: 'SIM_PASS'},
  {ids: ['F39'], impl: [`${CREDS}#resolveManagedPayload`], evidence: [SEC_OWNER, CFIX_IDENTITY], status: 'SIM_PASS'},
  {ids: ['F40'], impl: [CONTROL_NET, `${APPLY}#operationRecordId`], evidence: [CEVENTS, CPROTO], status: 'SIM_PASS'},

  {ids: ['A01'], impl: [CONTROL_NET], evidence: [CRESOURCES, ASSIGNMENT], status: 'SIM_PASS'},
  {ids: ['A02'], impl: [`${ASSIGN}#validateAssignment`], evidence: [CRESOURCES, ASSIGNMENT], status: 'SIM_PASS'},
  {ids: ['A03'], impl: [`${ASSIGN}#explainRecommendation`], evidence: [ASSIGNMENT, CRESOURCES], status: 'SIM_PASS'},
  {ids: ['A04'], impl: [`${WL}#activeWhitelist`], evidence: [WHITELIST, ASSIGNMENT], status: 'SIM_PASS'},
  {ids: ['A05'], impl: [`${WL}#claudeConflict`], evidence: [WHITELIST], status: 'SIM_PASS'},
  {ids: ['A06'], impl: [`${WL}#normalizeWhitelist`], evidence: [WHITELIST], status: 'SIM_PASS'},
  {ids: ['A07'], impl: [`${WL}#activeWhitelist`], evidence: [WHITELIST, X06], status: 'SIM_PASS'},
  {ids: ['A08'], impl: [CONTROL_NET], evidence: [CTEMPLATE], status: 'SIM_PASS'},
  {ids: ['A09'], impl: [`${COMPILE}#compileNetworkPlan`], evidence: [ASSIGNMENT, X06], status: 'SIM_PASS'},
  {ids: ['A10'], impl: [`${COMPILE}#compileNetworkPlan`], evidence: [ASSIGNMENT, X06], status: 'SIM_PASS'},
  {ids: ['A11'], impl: [`${COMPILE}#expectedRouteMatrix`], evidence: [ASSIGNMENT, X06], status: 'SIM_PASS'},
  {ids: ['A12'], impl: [`${APPLY}#applyNetworkPlan`], evidence: [APPLYT], status: 'SIM_PASS'},
  {ids: ['A13'], impl: [`${LIFE}#advanceLifecycle`], evidence: [APPLYT, LIFECYCLE], status: 'SIM_PASS'},
  {ids: ['A14'], impl: [CONTROL_ROUTES], evidence: [CQUOTA_HARD], status: 'SIM_PASS'},
  {ids: ['A15'], impl: [QUOTA_ADAPTER], evidence: [CQUOTA_HARD, X20], status: 'SIM_PASS'},
  {ids: ['A16'], impl: [QUOTA_ADAPTER], evidence: [X20], status: 'SIM_PASS'},
  {ids: ['A17'], impl: [QUOTA_ADAPTER], evidence: [X20], status: 'SIM_PASS'},
  {ids: ['A18'], impl: [CONTROL_ROUTES], evidence: [CQUOTA_REBUILD, X10], status: 'SIM_PASS'},
  {ids: ['A19'], impl: [QUOTA_ADAPTER], evidence: [CQUOTA_HARD, X09], status: 'SIM_PASS'},
  {ids: ['A20'], impl: [`${QUOTA}#applyQuotaOperation`], evidence: [NETQUOTA, X09], status: 'SIM_PASS'},
  {ids: ['A21'], impl: [`${QUOTA}#applyQuotaOperation`], evidence: [NETQUOTA, X09], status: 'SIM_PASS'},
  {ids: ['A22'], impl: [CONTROL_ROUTES], evidence: [CQUOTA_POOL, X11], status: 'SIM_PASS'},
  {ids: ['A23'], impl: [CONTROL_ROUTES], evidence: [CQUOTA_REBUILD, X10], status: 'SIM_PASS'},
  {ids: ['A24'], impl: [CONTROL_ROUTES], evidence: [CQUOTA_POOL, UI_J8], status: 'SIM_PASS'},
  {ids: ['A25'], impl: [CONTROL_NET], evidence: [CTEMPLATE, APPLYT], status: 'SIM_PASS'},
  {ids: ['A26'], impl: [`${APPLY}#authorizationAllows`], evidence: [CTEMPLATE, SEC_SCOPE], status: 'SIM_PASS'},
  {ids: ['A27'], impl: [`${COMPILE}#staticValidateConfig`], evidence: [APPLYT, CPROTO], status: 'SIM_PASS'},
  {ids: ['A28'], impl: ['src/adapters/network/controlClient.mjs'], evidence: [CFIX_OFFLINE, APPLYT], status: 'SIM_PASS'},
  {ids: ['A29'], impl: [`${APPLY}#restoreNetworkPlan`], evidence: [APPLYT, SEC_RESTORE, CFIX_DISABLE], status: 'SIM_PASS'},
  {ids: ['A30'], impl: [`${LIFE}#executeLifecycle`, 'apps/desktop-host/src-tauri/src/lifecycle.rs#tray_action', 'apps/desktop-host/src-tauri/src/lib.rs#prevent_close'], evidence: [LIFECYCLE, X07, ['tests/delivery/release-candidate.test.mjs', 'RC6 R06 桌面生命周期接线']], status: 'SIM_PASS',
    note: 'RC6：关窗只隐藏到托盘、托盘退出界面只结束 GUI 与托管控制端、不撤保护；宿主 lifecycle.rs 与 lib.rs 未编译，只有源码静态核对，真机待 E53。'},
  {ids: ['A31'], impl: [`${APPLY}#applyNetworkPlan`], evidence: [APPLYT], status: 'SIM_PASS'},
  {ids: ['A32'], impl: [CONTROL_ROUTES], evidence: [CQUOTA_IDEM, CEVENTS, CFIX_LOST], status: 'SIM_PASS'},
  {ids: ['A33'], impl: [CONTROL_NET, `${PROTECT}#handleProtectionEvent`], evidence: [CEVENTS, CRESOURCES], status: 'SIM_PASS'},
  {ids: ['A34'], impl: [PROTOCOL_SOURCE], evidence: [CPROTO, PROTOCOL], status: 'SIM_PASS',
    note: '未验证的系统/分类/供应商能力在协议层按固定字段与错误响应处理，不冒充已验证。'},
];
