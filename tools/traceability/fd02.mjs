const CTRL = 'src/core/diagnostics/controller.mjs';
const SCAN = 'src/core/diagnostics/scan.mjs';
const EVIDENCE = 'src/core/diagnostics/evidence.mjs';
const RULES = 'src/core/diagnostics/rules.mjs';
const PLANS = 'src/core/diagnostics/plans.mjs';
const REPORTS = 'src/core/diagnostics/reports.mjs';
const SESSION = 'src/core/diagnostics/session.mjs';
const PARSE = 'src/core/diagnostics/parse.mjs';
const WEBRTC = 'src/core/diagnostics/webrtc.mjs';
const FINGERPRINT = 'src/core/diagnostics/fingerprint.mjs';
const PLATFORM = 'src/core/diagnostics/platform.mjs';
const EXPECTED = 'src/core/diagnostics/assignmentExpected.mjs';
const PORTS = 'src/adapters/diagnostics/index.mjs';
const PAGE = 'apps/diagnostic-page/app.js';
const UI_SESSION = 'apps/desktop-ui/session.mjs';
const BROWSER_DIAG = 'apps/desktop-host/src-tauri/src/browser_diag.rs';
const DEFAULT_BROWSER = 'src/adapters/diagnostics/defaultBrowser.mjs';
const RC4_BROWSER = ['tests/diagnostics/default-browser.test.mjs', '默认浏览器回传进问题与评分：时区与 WebRTC 暴露按分配期望判定，来源标 default_browser'];
const RC4_GUEST_ONLY = ['tests/delivery/native-chain.test.mjs', 'MAJOR 只给客体配了探测服务时诊断照样挂上：客体按自己的端口诊断，宿主本机如实缺测'];
const RC4_PROBES = ['tests/control-runtime/admin-journey.test.mjs', 'RC4 管理员按环境配置探测服务，客户端登录后只为配置了的环境建探测端口'];

const A_STD = ['tests/diagnostics/a-scenarios.test.mjs', 'FD-02/A01-A04 A13-A14 标准扫描、HTTP 状态不判账号、JA3 缺测'];
const A_EXPORT = ['tests/diagnostics/a-scenarios.test.mjs', 'FD-02/A27 导出脱敏且不含 cookie 值'];
const A_NOECHO = ['tests/diagnostics/a-scenarios.test.mjs', '未配置 echo 时零请求并记录 SERVICE_NOT_CONFIGURED'];
const PLAN_A19 = ['tests/diagnostics/plan.test.mjs', 'FD-02/A19-A26 确认、漂移暂停、应用成功仍异常、恢复冲突'];
const PLAN_A22 = ['tests/diagnostics/plan.test.mjs', 'FD-02/A22-A24 无批准候选拒绝，普通扫描不演练'];
const SCAN_MODES = ['tests/diagnostics/scan.test.mjs', 'FD-02/N04-N06 深/快/专项请求集合不同，取消保留已完成项'];
const SCAN_GAPS = ['tests/diagnostics/scan.test.mjs', 'FD-02/A07-A10 情报缺失、DNS未捕获、无公网STUN、IPv6无结果分开'];
const SCORE_A15 = ['tests/diagnostics/score.test.mjs', 'FD-02/A15-A18 危急封顶、同根因只扣一次、信誉不默认扣分、字体不扣分'];
const SCORE_A05 = ['tests/diagnostics/score.test.mjs', 'FD-02/A05 绕行批准 A 记危急，首次回显不是基准'];
const SCORE_OBS = ['tests/diagnostics/score.test.mjs', 'BLOCK 结论只来自观测：无 bypass 开关仍记问题，匹配出口不因开关记问题'];
const SCORE_DNS = ['tests/diagnostics/score.test.mjs', 'BLOCK DNS/保护结论来自观测，不读 dnsViolation/forbiddenOpen'];
const SESSION_A11 = ['tests/diagnostics/session.test.mjs', 'FD-02/A11-A12 nonce/过期/不同Profile 拒绝，UA 不能覆盖 Profile'];
const FIX_EXPECTED = ['tests/diagnostics/review-fix.test.mjs', 'BLOCK 调用者 expected 不能覆盖 Assignment，出口不匹配必出问题'];
const FIX_EXEC = ['tests/diagnostics/review-fix.test.mjs', 'BLOCK 空 payload 不能假 EXECUTED；恢复走 T5 restore；演练不声明已恢复'];
const FIX_CANCEL = ['tests/diagnostics/review-fix.test.mjs', 'MAJOR 取消中止 I/O 且最终保持 CANCELLED'];
const FIX_QUICK = ['tests/diagnostics/review-fix.test.mjs', 'MAJOR 快扫保留未关闭问题，专项不给全环境分'];
const FIX_ECHO = ['tests/diagnostics/review-fix.test.mjs', 'MAJOR echo 503 不能当 OBSERVED；T4 读取 T7 诊断结果'];
const FIX_AUTH = ['tests/diagnostics/review-fix.test.mjs', 'BLOCK 调用者 Assignment 不能覆盖控制器持有的权威，合法 B 不是绕行'];
const FIX_REPORT = ['tests/diagnostics/review-fix.test.mjs', 'BLOCK 扫描结束后回传写入 DiagnosticResult 和报告'];
const FIX_RESTORE = ['tests/diagnostics/review-fix.test.mjs', 'BLOCK 恢复引用用 T5 apply 回执，演练未验证不声明已恢复'];
const FIX_T4CONFIRM = ['tests/diagnostics/review-fix.test.mjs', 'MAJOR T4 本地确认会确认诊断计划后再执行'];
const FIX_T4SCOPE = ['tests/diagnostics/review-fix.test.mjs', 'BLOCK T4 确认只覆盖用户选定的一个动作'];
const FIX_DOH = ['tests/diagnostics/review-fix.test.mjs', 'MAJOR DoH/Intel 取消、503 与抛错收敛到 DiagnosticResult'];
const FIX_PROBE = ['tests/diagnostics/review-fix.test.mjs', 'MAJOR Probe 取消后扫描在 150ms 内结束'];
const FIX_TOKEN = ['tests/diagnostics/review-fix.test.mjs', 'MAJOR 深层 token 与 errors[].token 不能泄漏到回执、结果或报告'];
const UI_J3 = ['tests/ui/journeys.test.mjs', '旅程3 诊断输入决定扫描对象'];
const UI_J3B = ['tests/ui/journeys.test.mjs', '旅程3b AI 模式走 T4 会话'];
const UI_J7 = ['tests/ui/journeys.test.mjs', '旅程7 无服务降级'];
const X05 = ['tests/delivery/x01-x05.test.mjs', 'X05 默认浏览器与内嵌 WebView 不同'];
const X18 = ['tests/delivery/x17-x20.test.mjs', 'X18 AI 离线、模型失败与预算耗尽'];
const GAP_ENV = ['tests/delivery/gaps.test.mjs', 'FD-02/N03 FD-04/A05 主机与客体分别标注覆盖'];

export const FD02 = [
  {ids: ['R01'], impl: [CTRL, PLANS, REPORTS], evidence: [UI_J3, PLAN_A19], status: 'SIM_PASS',
    note: '检测、诊断、处理、复查、恢复在同一控制器内闭环，不是网页外壳。'},
  {ids: ['R02'], impl: ['src/core/network/controller.mjs#readState', 'src/core/network/apply.mjs#applyNetworkPlan'], evidence: [FIX_RESTORE], status: 'SIM_PASS',
    note: '运行态读取与配置应用都走 T5 唯一入口，诊断不另开写入口。'},
  {ids: ['R03'], impl: ['src/core/network/controller.mjs#confirmAndApply'], evidence: [FIX_RESTORE], status: 'SIM_PASS'},
  {ids: ['R04'], impl: [`${SCAN}#scan`], evidence: [SCAN_MODES], status: 'SIM_PASS'},
  {ids: ['R05'], impl: [`${CTRL}#createDiagnosticsController`, UI_SESSION], evidence: [UI_J3, UI_J3B], status: 'SIM_PASS'},
  {ids: ['R06'], impl: [`${SCAN}#scan`, PORTS], evidence: [PLAN_A22, A_NOECHO], status: 'SIM_PASS',
    note: '普通扫描不演练、未配置服务时零请求。'},
  {ids: ['R07'], impl: [`${RULES}#suggestionFor`, `${PLANS}#buildDiagnosticPlan`], evidence: [PLAN_A19], status: 'SIM_PASS'},
  {ids: ['R08'], impl: [`${PLANS}#buildDiagnosticPlan`], evidence: [PLAN_A22], status: 'SIM_PASS',
    note: '不受支持的动作标 supported=false，不混进可执行清单。'},
  {ids: ['R09'], impl: [`${SESSION}#acceptBrowserReport`, `${EXPECTED}#expectedFromAssignment`], evidence: [SESSION_A11, X05], status: 'SIM_PASS'},
  {ids: ['R10'], impl: [`${RULES}#scoreNetwork`], evidence: [SCORE_A15], status: 'SIM_PASS'},
  {ids: ['R11'], impl: [`${RULES}#issuesFromObservations`, `${REPORTS}#toDiagnosticView`], evidence: [SCORE_OBS, SCAN_GAPS], status: 'SIM_PASS'},
  {ids: ['R12'], impl: ['src/core/ai/tools.mjs#executeClientTool'], evidence: [FIX_T4CONFIRM, FIX_T4SCOPE, UI_J3B], status: 'SIM_PASS'},
  {ids: ['R13'], impl: [`${PLANS}#buildDiagnosticPlan`], evidence: [PLAN_A22, FIX_AUTH], status: 'SIM_PASS'},
  {ids: ['R14'], impl: [`${PLANS}#executeConfirmedDiagnosticPlan`], evidence: [PLAN_A22, FIX_EXEC], status: 'SIM_PASS'},
  {ids: ['R15'], impl: [`${PLANS}#confirmDiagnosticPlan`, `${PLANS}#recheckDiagnosticAction`], evidence: [PLAN_A19], status: 'SIM_PASS'},
  {ids: ['R16'], impl: ['evidence/development/desktop-reuse-decision.md'], evidence: [], status: 'PARTIAL',
    note: '复用选型与来源固定在 protocol-source.md / desktop-reuse-decision.md；本版没有引入 CleanIP 的权重或默认修改。无自动化断言。'},
  {ids: ['R17'], impl: [`${RULES}#classifyIssue`], evidence: [A_STD], status: 'SIM_PASS',
    note: 'HTTP 状态与连通性不参与账号判定。'},
  {ids: ['R18'], impl: ['src/core/local/index.mjs#isProtectedUnchanged'], evidence: [['tests/delivery/x12-x16.test.mjs', 'X16 恢复时字段已被用户改动']], status: 'SIM_PASS'},

  {ids: ['N01'], impl: [`${EVIDENCE}#checksFor`], evidence: [A_STD], status: 'SIM_PASS'},
  {ids: ['N02'], impl: [`${SESSION}#createBrowserSession`, `${SESSION}#acceptBrowserReport`, `${BROWSER_DIAG}#listen`, `${DEFAULT_BROWSER}#createDefaultBrowserDiagnostics`], evidence: [SESSION_A11, X05, RC4_BROWSER], status: 'SIM_PASS',
    note: 'RC4：证据来自系统默认浏览器里的诊断页，宿主回环监听未编译、未在真机打开过浏览器。'},
  {ids: ['N03'], impl: [`${SCAN}#environmentCoverage`, `${EVIDENCE}#collectCategory`], evidence: [GAP_ENV, A_STD, RC4_GUEST_ONLY], status: 'SIM_PASS',
    note: '声明的主机与客体分别标注 MEASURED/NOT_MEASURED 并带原因，单环境扫描恒不声称整机；真实 WSL 探测集合留 T10。'},
  {ids: ['N04', 'N05', 'N06'], impl: [`${SCAN}#scan`], evidence: [SCAN_MODES, FIX_QUICK], status: 'SIM_PASS'},
  {ids: ['N07'], impl: [`${PARSE}#parsePublicIPBody`, `${EVIDENCE}#collectCategory`], evidence: [SCAN_GAPS, SCORE_A05], status: 'SIM_PASS'},
  {ids: ['N08'], impl: [`${PARSE}#normalizeAsn`], evidence: [SCAN_GAPS, SCORE_A15], status: 'SIM_PASS',
    note: '情报缺失或多源冲突分别保留，不默认扣分。'},
  {ids: ['N09'], impl: [`${EVIDENCE}#collectCategory`, `${EXPECTED}#expectedFromAssignment`], evidence: [FIX_AUTH], status: 'SIM_PASS'},
  {ids: ['N10'], impl: [`${PARSE}#parseDoHJSON`], evidence: [SCAN_GAPS, FIX_DOH], status: 'SIM_PASS'},
  {ids: ['N11'], impl: [`${WEBRTC}#collectIce`, `${PARSE}#classifyIceCandidate`, `${RULES}#issuesFromBrowserSample`], evidence: [SCAN_GAPS, RC4_BROWSER], status: 'SIM_PASS'},
  {ids: ['N12'], impl: [`${PARSE}#parseIPv`], evidence: [SCAN_GAPS], status: 'SIM_PASS'},
  {ids: ['N13'], impl: [`${PLATFORM}#collectPlatform`, `${PARSE}#timezoneMatch`, `${RULES}#issuesFromBrowserSample`], evidence: [SESSION_A11, X05, RC4_BROWSER], status: 'SIM_PASS'},
  {ids: ['N14'], impl: [`${FINGERPRINT}#collectFingerprint`], evidence: [SCORE_A15], status: 'SIM_PASS'},
  {ids: ['N15'], impl: [`${EVIDENCE}#collectCategory`], evidence: [A_STD], status: 'SIM_PASS'},
  {ids: ['N16'], impl: [`${PARSE}#parseTlsInfo`], evidence: [A_STD], status: 'SIM_PASS', note: 'JA3/JA4 来源不同连接时记为缺测。'},
  {ids: ['N17'], impl: ['src/core/network/state.mjs#readNetworkState'], evidence: [FIX_RESTORE], status: 'SIM_PASS'},
  {ids: ['N18'], impl: ['src/core/network/apply.mjs#applyNetworkPlan'], evidence: [FIX_RESTORE, FIX_EXEC], status: 'SIM_PASS'},
  {ids: ['N19'], impl: [`${PLANS}#executeConfirmedDiagnosticPlan`], evidence: [PLAN_A22, FIX_EXEC], status: 'SIM_PASS',
    note: '演练须单独授权；未验证不声明已恢复。'},
  {ids: ['N20'], impl: [`${SCAN}#scan`, `${RULES}#scoreNetwork`], evidence: [A_STD, X18], status: 'SIM_PASS'},
  {ids: ['N21'], impl: ['src/core/ai/index.mjs#startNetworkDiagnosis'], evidence: [UI_J3B, FIX_ECHO], status: 'SIM_PASS'},
  {ids: ['N22'], impl: [`${RULES}#classifyIssue`, `${REPORTS}#toDiagnosticView`], evidence: [SCORE_A15], status: 'SIM_PASS'},
  {ids: ['N23'], impl: [`${RULES}#scoreNetwork`], evidence: [SCORE_A15, FIX_QUICK], status: 'SIM_PASS'},
  {ids: ['N24'], impl: [`${RULES}#mergeRootCauses`], evidence: [SCORE_A15], status: 'SIM_PASS'},
  {ids: ['N25'], impl: [`${RULES}#suggestionFor`, `${PLANS}#buildDiagnosticPlan`], evidence: [PLAN_A19, PLAN_A22], status: 'SIM_PASS'},
  {ids: ['N26'], impl: [`${PLANS}#confirmDiagnosticPlan`], evidence: [PLAN_A19, FIX_T4SCOPE], status: 'SIM_PASS'},
  {ids: ['N27'], impl: [`${PLANS}#executeConfirmedDiagnosticPlan`], evidence: [PLAN_A19, FIX_EXEC], status: 'SIM_PASS'},
  {ids: ['N28'], impl: [`${PLANS}#buildDiagnosticPlan`], evidence: [PLAN_A22], status: 'SIM_PASS',
    note: '没有获批候选出口时拒绝换线，不临场选未批准节点。'},
  {ids: ['N29'], impl: [`${PLANS}#previewRestore`, `${PLANS}#restoreDiagnostic`], evidence: [PLAN_A19, FIX_RESTORE], status: 'SIM_PASS'},
  {ids: ['N30'], impl: [`${PLANS}#recheckDiagnosticAction`], evidence: [PLAN_A19, UI_J3], status: 'SIM_PASS'},
  {ids: ['N31'], impl: [`${REPORTS}#redactDiagnostic`, `${REPORTS}#persistDiagnosticReport`], evidence: [A_EXPORT, FIX_TOKEN, FIX_REPORT], status: 'SIM_PASS'},
  {ids: ['N32'], impl: [PORTS, `${SCAN}#scan`, 'services/control-rs/src/probes.rs#network_view', 'apps/desktop-ui/product-runtime.mjs#createProductRuntimeOptions'], evidence: [A_NOECHO, FIX_PROBE, RC4_PROBES], status: 'SIM_PASS',
    note: 'RC4：探测服务地址由控制端管理员按环境配置下发；控制端 Rust 未编译。'},
  {ids: ['N33'], impl: [`${SCAN}#scan`, `${UI_SESSION}#diagAiMode`], evidence: [FIX_DOH, UI_J7, X18], status: 'SIM_PASS'},
  {ids: ['N34'], impl: ['DOCS/REUSE_PLAN.md'], evidence: [], status: 'PARTIAL',
    note: '复用候选与边界写在 REUSE_PLAN/protocol-source；没有引入外部实现，也没有自动化断言。'},

  {ids: ['A01'], impl: [`${SCAN}#scan`], evidence: [A_STD, UI_J3B], status: 'SIM_PASS'},
  {ids: ['A02'], impl: [`${SCAN}#scan`], evidence: [A_STD, UI_J7, X18], status: 'SIM_PASS'},
  {ids: ['A03'], impl: [`${RULES}#suggestionFor`], evidence: [A_STD], status: 'SIM_PASS'},
  {ids: ['A04'], impl: ['src/core/network/lifecycle.mjs#advanceLifecycle'], evidence: [A_STD, ['tests/delivery/x06-x11.test.mjs', 'X07 固定出口故障后终止内核']], status: 'SIM_PASS'},
  {ids: ['A05'], impl: [`${RULES}#scoreNetwork`], evidence: [SCORE_A05], status: 'SIM_PASS'},
  {ids: ['A06'], impl: [`${EXPECTED}#expectedFromAssignment`], evidence: [FIX_EXPECTED, FIX_AUTH], status: 'SIM_PASS'},
  {ids: ['A07'], impl: [`${PARSE}#normalizeAsn`], evidence: [SCAN_GAPS], status: 'SIM_PASS'},
  {ids: ['A08'], impl: [`${PARSE}#parseDoHJSON`], evidence: [SCAN_GAPS], status: 'SIM_PASS'},
  {ids: ['A09'], impl: [`${WEBRTC}#collectIce`], evidence: [SCAN_GAPS], status: 'SIM_PASS'},
  {ids: ['A10'], impl: [`${PARSE}#parseIPv`], evidence: [SCAN_GAPS], status: 'SIM_PASS'},
  {ids: ['A11'], impl: [`${SESSION}#acceptBrowserReport`], evidence: [SESSION_A11, X05], status: 'SIM_PASS'},
  {ids: ['A12'], impl: [`${EVIDENCE}#collectCategory`], evidence: [SESSION_A11], status: 'SIM_PASS'},
  {ids: ['A13'], impl: [`${EVIDENCE}#collectCategory`], evidence: [A_STD], status: 'SIM_PASS'},
  {ids: ['A14'], impl: [`${PARSE}#parseTlsInfo`], evidence: [A_STD], status: 'SIM_PASS'},
  {ids: ['A15'], impl: [`${RULES}#scoreNetwork`], evidence: [SCORE_A15], status: 'SIM_PASS'},
  {ids: ['A16'], impl: [`${RULES}#scoreNetwork`], evidence: [SCORE_A15], status: 'SIM_PASS'},
  {ids: ['A17'], impl: [`${REPORTS}#toDiagnosticView`], evidence: [SCORE_A15], status: 'SIM_PASS'},
  {ids: ['A18'], impl: [`${FINGERPRINT}#collectFingerprint`, `${RULES}#scoreNetwork`], evidence: [SCORE_A15], status: 'SIM_PASS'},
  {ids: ['A19'], impl: [`${PLANS}#executeConfirmedDiagnosticPlan`], evidence: [PLAN_A19], status: 'SIM_PASS'},
  {ids: ['A20'], impl: [`${PLANS}#buildDiagnosticPlan`], evidence: [PLAN_A19], status: 'SIM_PASS'},
  {ids: ['A21'], impl: [`${PLANS}#confirmDiagnosticPlan`, `${CTRL}#createDiagnosticsController`], evidence: [PLAN_A19, FIX_CANCEL], status: 'SIM_PASS'},
  {ids: ['A22'], impl: [`${PLANS}#buildDiagnosticPlan`], evidence: [PLAN_A22], status: 'SIM_PASS'},
  {ids: ['A23'], impl: [`${SCAN}#scan`], evidence: [PLAN_A22], status: 'SIM_PASS'},
  {ids: ['A24'], impl: [`${PLANS}#executeConfirmedDiagnosticPlan`], evidence: [PLAN_A22, FIX_EXEC], status: 'SIM_PASS'},
  {ids: ['A25'], impl: [`${PLANS}#previewRestore`], evidence: [PLAN_A19], status: 'SIM_PASS'},
  {ids: ['A26'], impl: [`${PLANS}#recheckDiagnosticAction`], evidence: [PLAN_A19], status: 'SIM_PASS'},
  {ids: ['A27'], impl: [`${REPORTS}#redactDiagnostic`], evidence: [A_EXPORT, FIX_TOKEN], status: 'SIM_PASS'},
  {ids: ['A28'], impl: [`${SCAN}#scan`, 'src/core/ai/index.mjs#startNetworkDiagnosis'], evidence: [UI_J3, UI_J3B], status: 'PARTIAL',
    note: '标准与 AI 两条路径分别有结果，但开源候选对照与截图对照需要真实环境，留 T10。'},
];
