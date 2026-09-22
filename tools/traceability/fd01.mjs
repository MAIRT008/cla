const LOCAL = 'src/core/local/index.mjs';
const RULES = 'src/core/local/rules.mjs';
const WORKSPACE = 'src/adapters/local/workspace.mjs';
const UI_SESSION = 'apps/desktop-ui/session.mjs';
const UI_APP = 'apps/desktop-ui/app.js';
const DISCOVERY_RS = 'apps/desktop-host/src-tauri/src/discovery.rs';
const ROOTS_RS = 'apps/desktop-host/src-tauri/src/roots.rs';
const REAL_FORMATS = 'src/core/local/realFormats.mjs';
const RC4_DISCOVER = ['tests/delivery/authorized-roots.test.mjs', '未授权时发现只列位置、不给扫描范围；扫描被拒并点名要先授权'];
const RC4_ROOTS = ['tests/delivery/authorized-roots.test.mjs', '已授权的真实根走完扫描、计划、确认、执行与恢复；测试工作区 input/ 不被扫描'];
const RC4_IDENTIFY = ['tests/local/real-formats.test.mjs', 'F09/F15：从真实格式认出账号与网站登录，不记邮箱原文、凭据与其他站点的 Cookie'];
const RC4_RESTRICTED = ['tests/local/real-formats.test.mjs', 'F10—F12/F14：受限账号的登录资料进推荐，正常登录与第三方来源只报告'];
const RC4_WAL = ['tests/local/sqlite-wal.test.mjs', 'BLOCK 记录只在 WAL 里时，扫描、模拟、备份、执行复读与恢复都按 SQLite 一致快照'];
const RC4_NO_SNAPSHOT = ['tests/local/sqlite-wal.test.mjs', 'BLOCK 取不到一致快照时拒绝执行，库不动、不留备份'];
const RC4_STALE = ['tests/delivery/authorized-roots.test.mjs', 'MAJOR 已授权位置变了（如 CLAUDE_CONFIG_DIR 改指）就标授权过期、收回扫描范围；重新授权后按新位置'];
const RC4_SITE = ['tests/local/real-formats.test.mjs', 'F15：受限的网站登录只删 Claude 站点的 Cookie，Desktop 令牌缓存随同一登录处理'];

const T3_MAIN = ['tests/local/localService.test.mjs', 'T3 scans actual synthetic files, protects projects, and requires local confirmation'];
const T3_FREEZE = ['tests/local/localService.test.mjs', 'T3 confirmation freezes only selected same-file actions for execution and resume'];
const T3_EXEC = ['tests/local/localService.test.mjs', 'T3 executes JSON and SQLite actions, resumes across a new service instance, and restores only selected JSON'];
const T3_ENV = ['tests/local/localService.test.mjs', 'T3 consumes the declared environment snapshot, isolates a pure directory, and records a checked site command'];
const T3_POINTER = ['tests/local/localService.test.mjs', 'T3 preserves a JSON provider pointer when its provider action fails'];
const T3_CANCEL = ['tests/local/localService.test.mjs', 'T3 records runtime cancellation before each not-yet-started action'];
const T3_DISCOVERY = ['tests/local/sourceDiscovery.test.mjs', 'standard discovery attributes an actual Code credential to an inspected restricted Provider'];
const UI_J1 = ['tests/ui/journeys.test.mjs', '旅程1 本地完整处理'];
const UI_J2A = ['tests/ui/journeys.test.mjs', '旅程2a 确认后目标漂移被拒'];
const UI_J2B = ['tests/ui/journeys.test.mjs', '旅程2b 执行中取消保留成功项'];
const UI_J2C = ['tests/ui/journeys.test.mjs', '旅程2c 恢复预览'];
const UI_J7 = ['tests/ui/journeys.test.mjs', '旅程7 无服务降级'];
const UI_SCANGUARD = ['tests/ui/journeys.test.mjs', '扫描进行中点击依赖动作被拒'];
const X01 = ['tests/delivery/x01-x05.test.mjs', 'X01 AI 规划混合 JSON'];
const X02 = ['tests/delivery/x01-x05.test.mjs', 'X02 模型越权请求被客户端拒绝'];
const X03 = ['tests/delivery/x01-x05.test.mjs', 'X03 确认后目标改变暂停'];
const X04 = ['tests/delivery/x01-x05.test.mjs', 'X04 客户端包与上传内容不含模型配置'];
const X05 = ['tests/delivery/x01-x05.test.mjs', 'X05 默认浏览器与内嵌 WebView 不同'];
const X16 = ['tests/delivery/x12-x16.test.mjs', 'X16 恢复时字段已被用户改动'];
const X18 = ['tests/delivery/x17-x20.test.mjs', 'X18 AI 离线、模型失败与预算耗尽'];
const X19 = ['tests/delivery/x17-x20.test.mjs', 'X19 文件占用与权限不足时逐项失败'];
const GAP_MODES = ['tests/delivery/gaps.test.mjs', 'FD-01/F05 F06 快扫复用上次结果，专项扫描只覆盖选定范围'];
const GAP_RECHECK = ['tests/delivery/gaps.test.mjs', 'FD-01/F25 F26 复查后重新评分，脱敏报告不含凭据值'];
const GAP_SITE = ['tests/delivery/gaps.test.mjs', 'FD-01/F15 站点数据命令按声明能力执行并留回执'];
const GAP_COMPARE = ['tests/delivery/gaps.test.mjs', 'FD-01/A21 标准与 AI 在同一案例上给出同一组目标'];
const NATIVE_CHAIN = ['tests/delivery/native-chain.test.mjs', '正式页面经 bridge.js 与受限原生桥可取得快照并跑完本地处理'];

export const FD01 = [
  {ids: ['R01'], impl: [`${LOCAL}#discover`, `${LOCAL}#classify`, `${LOCAL}#confirmActionPlan`, UI_APP], evidence: [UI_J1], status: 'SIM_PASS',
    note: '扫描→分类→建议→一次确认→执行→复查在页面事件级跑通。'},
  {ids: ['R02'], impl: [`${LOCAL}#discover`], evidence: [UI_J1, X01, X18], status: 'SIM_PASS',
    note: '深扫为默认；AI 可用时走 T4 规划，AI 不可用时标准深扫仍可跑完。'},
  {ids: ['R03'], impl: [`${LOCAL}#discover`], evidence: [GAP_MODES], status: 'SIM_PASS',
    note: '快扫复用上次未变对象，专项扫描按 kinds/categories 收窄并标 FOCUSED_SCOPE_ONLY。'},
  {ids: ['R04'], impl: [UI_APP, `${LOCAL}#classify`], evidence: [UI_J1, X18], status: 'SIM_PASS',
    note: '同一套页面与执行路径；页面无聊天框（无对话入口元素）。'},
  {ids: ['R05'], impl: [`${LOCAL}#confirmActionPlan`, 'src/core/ai/tools.mjs#executeClientTool'], evidence: [X01, X02], status: 'SIM_PASS',
    note: '扫描与计划只读；未确认的执行被 AI_CONFIRMATION_REQUIRED 拒绝。'},
  {ids: ['R06'], impl: [`${LOCAL}#classify`, `${RULES}#scoreProblems`], evidence: [UI_J1], status: 'SIM_PASS',
    note: '推荐带 summary/severity/impact，不是只给路径。'},
  {ids: ['R07'], impl: [`${LOCAL}#isProtectedUnchanged`], evidence: [T3_MAIN, X01, X16], status: 'SIM_PASS',
    note: '项目记录/记忆/配置在执行与恢复两条路径上都未被改动。'},
  {ids: ['R08'], impl: [`${LOCAL}#recordAccountAnswer`, `${LOCAL}#classify`], evidence: [T3_MAIN, UI_J1], status: 'SIM_PASS'},
  {ids: ['R09'], impl: [`${LOCAL}#classify`, `${RULES}#scoreProblems`], evidence: [T3_MAIN], status: 'SIM_PASS',
    note: '正常账号答复直接跳过候选，不产生扣分项。'},
  {ids: ['R10'], impl: [`${RULES}#scoreProblems`], evidence: [UI_J1], status: 'SIM_PASS',
    note: 'score.status 为 unknown/final 的证据状态与三级严重度分开。'},
  {ids: ['R11'], impl: [`${LOCAL}#discover`, `${RULES}#scoreProblems`], evidence: [UI_J1], status: 'SIM_PASS',
    note: 'coverage.gaps 明示缺口；同根因问题去重后只扣一次。'},
  {ids: ['R12'], impl: [`${LOCAL}#classify`], evidence: [UI_J1], status: 'SIM_PASS',
    note: 'problems 按 root_cause_ref 归并，plan.actions 仍逐文件/字段/记录。'},
  {ids: ['R13'], impl: [`${LOCAL}#recheckAction`, `${LOCAL}#recordProblemDecision`], evidence: [GAP_RECHECK, UI_J1], status: 'SIM_PASS',
    note: '用户保留的问题仍计入扣分；复查确认后才重新计算。'},
  {ids: ['R14'], impl: [`${LOCAL}#executeConfirmedPlan`, `${LOCAL}#errorReceipt`], evidence: [X19, T3_EXEC], status: 'SIM_PASS',
    note: 'APPLIED/ALREADY_ABSENT/FAILED/CONFLICT/DEPENDENCY_BLOCKED/NOT_STARTED 分别记录。'},

  {ids: ['F01'], impl: [`${LOCAL}#discover`, WORKSPACE, 'src/adapters/local/bridgeWorkspace.mjs', `${DISCOVERY_RS}#discover`, `${ROOTS_RS}#resolve`], evidence: [T3_DISCOVERY, T3_ENV, NATIVE_CHAIN, RC4_DISCOVER, RC4_ROOTS, RC4_STALE], status: 'SIM_PASS',
    note: '正式桌面上同一发现流程经受限原生桥取得本地能力，已在正式页面链路上跑通。RC4：宿主按当前用户发现真实位置，授权根目录登记在保险库；Rust 侧未编译。'},
  {ids: ['F02'], impl: [`${LOCAL}#discover`, `${DISCOVERY_RS}#chromium_profiles`], evidence: [X05, RC4_DISCOVER], status: 'SIM_PASS', note: '发现结果带出 profile_ref；RC4 起 Chromium 系 Profile 取自 Local State。'},
  {ids: ['F03'], impl: [`${LOCAL}#discover`, `${DISCOVERY_RS}#environment_declaration`], evidence: [T3_ENV, RC4_DISCOVER], status: 'SIM_PASS',
    note: '声明环境快照区分 windows/wsl 客户端，未安装项记为 CLIENT_NOT_INSTALLED 缺口。'},
  {ids: ['F04'], impl: [`${LOCAL}#discover`], evidence: [T3_MAIN, UI_J1], status: 'SIM_PASS'},
  {ids: ['F05'], impl: [`${LOCAL}#discover`], evidence: [GAP_MODES], status: 'SIM_PASS', note: '快扫复用未变对象并标记 read=false。'},
  {ids: ['F06'], impl: [`${LOCAL}#discover`], evidence: [GAP_MODES], status: 'SIM_PASS', note: '专项扫描限定对象类型，评分标 FOCUSED_SCOPE_ONLY。'},
  {ids: ['F07'], impl: [`${LOCAL}#classify`], evidence: [X18], status: 'SIM_PASS'},
  {ids: ['F08'], impl: ['src/core/ai/index.mjs#startCleanup'], evidence: [X01], status: 'SIM_PASS'},
  {ids: ['F09'], impl: [`${LOCAL}#classify`, `${LOCAL}#inspectObject`, `${REAL_FORMATS}#claudeAccountIdentity`], evidence: [T3_DISCOVERY, RC4_IDENTIFY], status: 'SIM_PASS',
    note: '身份与 provider 关联来自实际读取的凭据引用。'},
  {ids: ['F10'], impl: [`${LOCAL}#recordAccountAnswer`, `${UI_SESSION}#localAnswer`], evidence: [UI_J1], status: 'SIM_PASS'},
  {ids: ['F11'], impl: [`${LOCAL}#classify`], evidence: [T3_MAIN, X01], status: 'SIM_PASS'},
  {ids: ['F12'], impl: [`${LOCAL}#classify`], evidence: [T3_MAIN, UI_J1, RC4_RESTRICTED], status: 'SIM_PASS'},
  {ids: ['F13'], impl: [`${LOCAL}#isProtectedUnchanged`], evidence: [T3_MAIN, X01], status: 'SIM_PASS'},
  {ids: ['F14'], impl: [`${LOCAL}#inspectObject`, `${REAL_FORMATS}#ccSwitchSources`], evidence: [T3_DISCOVERY, T3_POINTER, RC4_RESTRICTED], status: 'SIM_PASS'},
  {ids: ['F15'], impl: [`${LOCAL}#requestSiteCommand`, `${LOCAL}#recordSiteCommandResponse`, `${REAL_FORMATS}#isClaudeSiteHost`], evidence: [GAP_SITE, T3_ENV, RC4_SITE], status: 'SIM_PASS'},
  {ids: ['F16'], impl: [`${LOCAL}#discover`], evidence: [T3_ENV], status: 'SIM_PASS',
    note: 'object_relations 的 lifecycle active/archived 决定 protected_paths。'},
  {ids: ['F17'], impl: [`${LOCAL}#classify`], evidence: [UI_J1], status: 'SIM_PASS'},
  {ids: ['F18'], impl: [`${LOCAL}#classify`, `${RULES}#scoreProblems`], evidence: [UI_J1], status: 'SIM_PASS'},
  {ids: ['F19'], impl: [`${RULES}#LOCAL_RULESET_VERSION`, `${RULES}#scoreProblems`], evidence: [UI_J1], status: 'SIM_PASS'},
  {ids: ['F20'], impl: [`${LOCAL}#classify`], evidence: [UI_J1], status: 'SIM_PASS'},
  {ids: ['F21'], impl: [`${LOCAL}#confirmActionPlan`, `${LOCAL}#executeConfirmedPlan`], evidence: [T3_FREEZE, UI_J1], status: 'SIM_PASS'},
  {ids: ['F22'], impl: [`${LOCAL}#executeAction`, 'apps/desktop-host/src-tauri/src/workspace.rs'], evidence: [T3_EXEC, NATIVE_CHAIN, RC4_WAL], status: 'SIM_PASS',
    note: '字段与记录级处理在正式链路上经数据库能力组落到目标；Rust 侧实现未编译验证。'},
  {ids: ['F23'], impl: [`${LOCAL}#executeAction`], evidence: [X03, X19, RC4_NO_SNAPSHOT], status: 'SIM_PASS'},
  {ids: ['F24'], impl: [`${LOCAL}#previewRestore`, `${LOCAL}#restoreChange`, `${WORKSPACE}`], evidence: [T3_EXEC, X16, UI_J2C, RC4_WAL], status: 'SIM_PASS'},
  {ids: ['F25'], impl: [`${LOCAL}#recheckAction`], evidence: [GAP_RECHECK], status: 'SIM_PASS'},
  {ids: ['F26'], impl: [`${LOCAL}#getReport`, `${RULES}#redactForExport`], evidence: [GAP_RECHECK], status: 'SIM_PASS'},
  {ids: ['F27'], impl: [`${UI_SESSION}#localScan`, 'apps/desktop-ui/compose.mjs#createAi'], evidence: [UI_J7, X18], status: 'SIM_PASS'},
  {ids: ['F28'], impl: [`${RULES}#LOCAL_RULESET_VERSION`], evidence: [], status: 'PARTIAL',
    note: '规则集有版本号且随分类落盘。缺的是原文另两条：历史正反样例未纳入测试；「不把未知路径自动发布为删除规则」没有专门证据。原文并未要求维护界面，本版按固定规则集交付。'},

  {ids: ['A01'], impl: [`${LOCAL}#discover`, 'src/core/ai/index.mjs#startCleanup'], evidence: [X01], status: 'SIM_PASS'},
  {ids: ['A02'], impl: [`${UI_SESSION}#localScan`], evidence: [UI_J7, X18], status: 'SIM_PASS'},
  {ids: ['A03'], impl: [`${LOCAL}#classify`], evidence: [T3_MAIN], status: 'SIM_PASS'},
  {ids: ['A04'], impl: [`${LOCAL}#classify`], evidence: [UI_J1], status: 'SIM_PASS'},
  {ids: ['A05'], impl: [`${LOCAL}#classify`], evidence: [UI_J1], status: 'SIM_PASS',
    note: '未回答身份产生 ACCOUNT_ANSWER_MISSING 缺口而不是默认清理。'},
  {ids: ['A06'], impl: [`${LOCAL}#classify`], evidence: [UI_J1], status: 'SIM_PASS',
    note: '合成夹具含 normal-account/restricted-account/shared 三身份共用同一浏览器数据。'},
  {ids: ['A07'], impl: [`${LOCAL}#inspectObject`], evidence: [T3_DISCOVERY], status: 'SIM_PASS'},
  {ids: ['A08'], impl: [`${LOCAL}#executeAction`], evidence: [X01], status: 'SIM_PASS'},
  {ids: ['A09'], impl: [`${LOCAL}#executeAction`], evidence: [X03], status: 'SIM_PASS',
    note: '同名文件重生成按冻结前后哈希判为 STALE_PLAN，不盲删。'},
  {ids: ['A10'], impl: [`${LOCAL}#executeAction`, `${LOCAL}#requestSiteCommand`], evidence: [T3_EXEC, GAP_SITE], status: 'SIM_PASS'},
  {ids: ['A11'], impl: [`${LOCAL}#classify`], evidence: [T3_MAIN], status: 'SIM_PASS',
    note: '旧备份含项目引用时进入保护路径，不纳入自动清理。'},
  {ids: ['A12'], impl: [`${LOCAL}#classify`], evidence: [UI_J1], status: 'SIM_PASS'},
  {ids: ['A13'], impl: [`${RULES}#scoreProblems`], evidence: [UI_J1], status: 'SIM_PASS'},
  {ids: ['A14'], impl: [`${LOCAL}#discover`], evidence: [T3_ENV], status: 'SIM_PASS',
    note: '关键范围未读到时 coverage.complete=false 且 score.status 非 final。'},
  {ids: ['A15'], impl: [`${LOCAL}#recordProblemDecision`], evidence: [UI_J1], status: 'SIM_PASS'},
  {ids: ['A16'], impl: [`${LOCAL}#executeAction`], evidence: [X03, X19], status: 'SIM_PASS'},
  {ids: ['A17'], impl: [`${LOCAL}#executeConfirmedPlan`], evidence: [X19], status: 'SIM_PASS'},
  {ids: ['A18'], impl: [`${LOCAL}#recheckAction`], evidence: [GAP_RECHECK], status: 'SIM_PASS'},
  {ids: ['A19'], impl: [`${LOCAL}#restoreChange`], evidence: [X16, UI_J2C], status: 'SIM_PASS'},
  {ids: ['A20'], impl: [`${RULES}#redactForExport`, 'src/core/ai/evidence.mjs#redactForModel'], evidence: [GAP_RECHECK, X04], status: 'SIM_PASS'},
  {ids: ['A21'], impl: [`${LOCAL}#classify`, 'src/core/ai/index.mjs#startCleanup'], evidence: [GAP_COMPARE, X01, X18], status: 'SIM_PASS',
    note: '同一次扫描上标准计划与 AI 计划的目标集合逐项相同，AI 不增删目标；真实样本对照仍留 T10。'},
  {ids: ['A22'], impl: [`${LOCAL}#discover`, `${LOCAL}#resumeOperation`], evidence: [T3_EXEC, UI_J2B], status: 'SIM_PASS',
    note: '历史来源冲突走 REPLAY_MISMATCH/EXTERNALLY_CHANGED，证据缺口进 coverage.gaps。'},
];
