const CLASSIFIER = 'src/core/audit/routeClassifier.mjs';
const TRAFFIC = 'src/core/audit/traffic.mjs';
const ARCHIVE = 'src/core/audit/archive.mjs';
const DAILY = 'src/core/audit/dailyReport.mjs';
const PIPELINE = 'src/core/audit/pipeline.mjs';
const AUDIT_STORE = 'src/adapters/audit/fixtureStore.mjs';
const PROTECT = 'src/core/network/protection.mjs';
const OBSERVE = 'src/core/network/observe.mjs';
const EMERGENCY = 'src/core/network/emergency.mjs';
const LIFE = 'src/core/network/lifecycle.mjs';
const CONTROL_NET = 'services/control/network.mjs';
const UI_SESSION = 'apps/desktop-ui/session.mjs';
const UI_COMPOSE = 'apps/desktop-ui/compose.mjs';

const ARCH = ['tests/audit/archiveReport.test.mjs', 'FD-04/F23-F28 archives approved fixture logs by SHA-256 without mutating sources'];
const REPORTPAIR = ['tests/audit/archiveReport.test.mjs', 'FD-04/F29-F44 creates one factual report pair, repairs only a missing mate, and keeps delayed AI notes separate'];
const PIPE = ['tests/audit/archiveReport.test.mjs', 'FD-04/F02-F06,F09-F13,F23-F37 consumes synthetic logs and counters into an archived report pair'];
const DAILYPASS = ['tests/audit/archiveReport.test.mjs', 'FD-04/A36 accepts DAILY_PASS only from a complete, source-bound collection window'];
const ROUTE = ['tests/audit/routeClassifier.test.mjs', 'FD-04/F09-F13 preserves legacy v2 categories and declares product scope'];
const ROUTE_UNKNOWN = ['tests/audit/routeClassifier.test.mjs', 'FD-04/F12 keeps missing route evidence unknown instead of passing it'];
const TRAF = ['tests/audit/traffic.test.mjs', 'FD-04/F02-F06 accumulates core deltas once and records reset or gaps'];
const TRAF_QUOTA = ['tests/audit/traffic.test.mjs', 'FD-04/F05 carries server quota snapshots without rebuilding a client ledger'];
const NET_PROTECT = ['tests/network/protection.test.mjs', 'FD-04/A06-A11 A16-A20 即时保护与事件引用'];
const NET_EMERGENCY = ['tests/network/emergency.test.mjs', 'FD-04/F22 RUNTIME §2 手动应急'];
const NET_SEC = ['tests/network/security.test.mjs', 'BLOCK5 当前连接经 T2 分类后立即保护'];
const CEVENTS = ['tests/control/events.test.mjs', 'FD-03/A32-A33 FD-04/A20 最小事件隔离、幂等与秘密拒绝'];
const AI_DAILY = ['tests/ai/aiSynthetic.test.mjs', 'daily analysis writes a fact-referenced T2 note without changing the standard report and network keeps applied separate from failed verification'];
const UI_J5 = ['tests/ui/journeys.test.mjs', '旅程5 日报来自 T2 实际产物'];
const UI_AI = ['tests/ui/journeys.test.mjs', '模型能力来自 T4 服务端能力接口'];
const UI_J7 = ['tests/ui/journeys.test.mjs', '旅程7 无服务降级'];
const X07 = ['tests/delivery/x06-x11.test.mjs', 'X07 固定出口故障后终止内核'];
const X12 = ['tests/delivery/x12-x16.test.mjs', 'X12 未知进程与短连接缺测保留'];
const X13 = ['tests/delivery/x12-x16.test.mjs', 'X13 日报 FAIL 与覆盖不足并列'];
const X14 = ['tests/delivery/x12-x16.test.mjs', 'X14 源日志意外含秘密作为异常处理'];
const X15 = ['tests/delivery/x12-x16.test.mjs', 'X15 休眠错过 09:00 后首次唤醒补做一次'];
const X18 = ['tests/delivery/x17-x20.test.mjs', 'X18 AI 离线、模型失败与预算耗尽'];
const X20 = ['tests/delivery/x17-x20.test.mjs', 'X20 节点重启与资源版本更新后账目连续'];
const GAP_AUDIT = ['tests/delivery/gaps.test.mjs', 'FD-04/F40 A39 本地清理不覆盖监控证据与已交付日报'];
const GAP_ENV = ['tests/delivery/gaps.test.mjs', 'FD-02/N03 FD-04/A05 主机与客体分别标注覆盖'];

const RUNTIME = 'src/adapters/audit/runtime.mjs';
const MONITOR = 'src/core/audit/monitor.mjs';
const SERVICE_LOGS = 'src/adapters/audit/serviceLogs.mjs';
const EXPORTER = 'src/adapters/audit/diagnosticExport.mjs';
const REDACT = 'src/core/audit/redact.mjs';
const HOST_LOGS = 'apps/desktop-host/src-tauri/src/logs.rs';
const UI_APP = 'apps/desktop-ui/app.js';
const RT = (name) => ['tests/delivery/audit-runtime.test.mjs', name];
const RC5_ENABLE = RT('RC5 FD-04/F01 启用前不采集');
const RC5_SCHEDULE = RT('RC5 FD-04/F23-F29/A26/A28 真实格式内核日志经宿主只读归档');
const RC5_PROTECT = RT('RC5 FD-04/F14-F19/A06/A16/A20 实时错误出口');
const RC5_TRAFFIC = RT('RC5 FD-04/F02-F06/F36/A22/A23 日报的本机字节来自内核计数');
const RC5_EXPORT = RT('RC5 FD-04/F38 诊断包');
const RC5_PAGE = RT('RC5 正式页面：点「启用监测与保护」经本地确认');
const RC6_NOTIFY_HIDDEN = RT('RC6 FD-04/F17 窗口隐藏时');
const RC6_NOTIFY_FAIL = RT('RC6 FD-04/F17 窗口可见时');
const RC6_NOTIFY_PAGE = ['tests/ui/journeys.test.mjs', 'RC6 旅程：窗口隐藏时危急事件'];
const RC6_COLLECT = ['tests/delivery/release-candidate.test.mjs', 'RC6 R09 统一日志收集'];
const RC5_PAUSE = RT('RC5 Round 2 FD-04/A36 同一分钟内停顿 30 秒');
const RC5_JOURNAL_RETRY = RT('RC5 Round 2 FD-04/A36 分钟记录写失败');
const REAL = (name) => ['tests/audit/real-logs.test.mjs', name];
const REAL_FORMAT = REAL('FD-04/F09-F12 Mihomo 真实行格式');
const REAL_SCOPE = REAL('FD-04/F12/A02 只计 Claude 相关记录');
const REAL_ROTATE = REAL('FD-04/F25-F27/A34 轮转');
const REAL_GAP = REAL('FD-04/A25 两次归档之间轮转两次');
const REAL_SECRET = REAL('FD-04/F39/A37 源日志含秘密');
const REAL_SOURCES = REAL('FD-04/F24/A25 可选来源缺席不算缺口');
const REAL_INCR = REAL('FD-04/F28/A26-A27 每轮只数新增部分的 WRONG_ROUTE');
const REAL_DELIVERED = REAL('FD-04/F30-F31 读回日报');
const MON = (name) => ['tests/audit/monitor.test.mjs', name];
const MON_CONT = MON('FD-04/F06/A36 全程每秒观测');
const MON_GAPS = MON('FD-04/F06/R10 睡眠停顿');
const MON_ATTR = MON('FD-04/F03-F04/A22 归属按连接增量');
const MON_RESET = MON('FD-04/F06/A22 窗口计数交给 accumulateTraffic');
const MON_PAUSE = MON('RC5 Round 2 FD-04/A36 同一分钟内超过阈值的停顿');
const RC5_RUST = 'Rust 宿主（logs.rs）与安装器的日志目录只读授权未编译、未运行。';

export const FD04 = [
  {ids: ['R01'], impl: [PIPELINE, PROTECT], evidence: [PIPE, NET_PROTECT], status: 'SIM_PASS'},
  {ids: ['R02'], impl: [`${PROTECT}#handleProtectionEvent`], evidence: [NET_PROTECT, X07], status: 'SIM_PASS'},
  {ids: ['R03'], impl: [`${PROTECT}#handleProtectionEvent`], evidence: [NET_PROTECT, X07], status: 'SIM_PASS'},
  {ids: ['R04'], impl: [`${PROTECT}#handleProtectionEvent`], evidence: [NET_PROTECT, X07], status: 'SIM_PASS'},
  {ids: ['R05'], impl: [CONTROL_NET], evidence: [CEVENTS], status: 'SIM_PASS'},
  {ids: ['R06'], impl: ['src/core/ai/tools.mjs#executeClientTool'], evidence: [AI_DAILY, X13], status: 'SIM_PASS'},
  {ids: ['R07'], impl: ['src/core/network/apply.mjs#authorizationAllows'], evidence: [NET_EMERGENCY, NET_PROTECT], status: 'SIM_PASS'},
  {ids: ['R08'], impl: [`${CLASSIFIER}#classifyRoute`], evidence: [ROUTE, ROUTE_UNKNOWN], status: 'SIM_PASS'},
  {ids: ['R09'], impl: [`${CLASSIFIER}#classifyRoute`], evidence: [ROUTE], status: 'SIM_PASS',
    note: '归档元数据冻结当时的 mapping，回放按事件当时方案判定。'},
  {ids: ['R10'], impl: [`${ARCHIVE}#archiveLogs`, `${PIPELINE}#collectAuditEvidence`], evidence: [ARCH, X12], status: 'SIM_PASS'},
  {ids: ['R11'], impl: [`${ARCHIVE}#planArchive`], evidence: [ARCH], status: 'SIM_PASS'},
  {ids: ['R12'], impl: ['src/core/audit/time.mjs', `${DAILY}#evaluateDailyDue`], evidence: [X15, REPORTPAIR], status: 'SIM_PASS'},
  {ids: ['R13'], impl: [`${ARCHIVE}#archiveLogs`], evidence: [ARCH, X14], status: 'SIM_PASS'},
  {ids: ['R14'], impl: [`${DAILY}#evaluateDailyDue`], evidence: [X15], status: 'SIM_PASS'},
  {ids: ['R15'], impl: [`${DAILY}#deliverDailyReport`], evidence: [REPORTPAIR, X13, X15], status: 'SIM_PASS'},
  {ids: ['R16'], impl: [`${DAILY}#selectWindow`, `${DAILY}#buildDailyReport`], evidence: [REPORTPAIR, PIPE], status: 'SIM_PASS'},
  {ids: ['R17'], impl: [`${CLASSIFIER}#classifyRoute`], evidence: [ROUTE], status: 'SIM_PASS'},
  {ids: ['R18'], impl: [`${PIPELINE}#collectAuditEvidence`], evidence: [PIPE, X14], status: 'SIM_PASS'},
  {ids: ['R19'], impl: [`${DAILY}#buildDailyReport`], evidence: [PIPE, UI_J5], status: 'SIM_PASS'},
  {ids: ['R20'], impl: [`${TRAFFIC}#accumulateTraffic`], evidence: [TRAF, TRAF_QUOTA, X12], status: 'SIM_PASS'},
  {ids: ['R21'], impl: [`${CLASSIFIER}#classifyRoute`], evidence: [ROUTE], status: 'SIM_PASS'},
  {ids: ['R22'], impl: [`${DAILY}#buildDailyReport`], evidence: [X13, UI_J5], status: 'SIM_PASS'},
  {ids: ['R23'], impl: [CONTROL_NET, `${DAILY}#buildDailyReport`], evidence: [CEVENTS], status: 'SIM_PASS'},
  {ids: ['R24'], impl: [`${ARCHIVE}#archiveLogs`, AUDIT_STORE], evidence: [ARCH], status: 'SIM_PASS'},
  {ids: ['R25'], impl: [`${ARCHIVE}#archiveLogs`], evidence: [X14], status: 'SIM_PASS'},
  {ids: ['R26'], impl: ['src/core/diagnostics/rules.mjs#scoreNetwork'], evidence: [['tests/diagnostics/score.test.mjs', 'FD-02/A15-A18 危急封顶、同根因只扣一次、信誉不默认扣分、字体不扣分']], status: 'SIM_PASS',
    note: '没有另建流量安全分；需要完整重评时调用 FD-02 评分。'},

  {ids: ['F01'], impl: [`${PIPELINE}#collectAuditEvidence`, `${RUNTIME}#createAuditRuntime`], evidence: [PIPE, RC5_ENABLE, RC5_PAGE], status: 'SIM_PASS',
    note: `RC5：用户点「启用监测与保护」后才采集，本地确认框写明采集、自动保护与上报范围。${RC5_RUST}`},
  {ids: ['F02', 'F03', 'F04', 'F05', 'F06'], impl: [`${TRAFFIC}#accumulateTraffic`, `${UI_SESSION}#refreshTraffic`, `${MONITOR}#createMonitorJournal`, `${MONITOR}#journalTraffic`, `${UI_APP}#renderMonitor`], evidence: [TRAF, TRAF_QUOTA, PIPE, X12, UI_J5, MON_ATTR, MON_RESET, RC5_TRAFFIC], status: 'SIM_PASS',
    note: 'RC5：本机字节来自每分钟的内核累计计数；归属按两次读取之间的连接增量分到路由、A/B 出口与进程，短连接差额与无进程字段的连接单列；服务端额度快照另记。真实内核计数未在真机读取。'},
  {ids: ['F07'], impl: [`${OBSERVE}#observeNetworkEvidence`, `${OBSERVE}#consumeLiveNetwork`], evidence: [NET_SEC, RC5_PROTECT], status: 'SIM_PASS'},
  {ids: ['F08'], impl: [`${ARCHIVE}#archiveLogs`, `${CLASSIFIER}#classifyRoute`, `${OBSERVE}#productAuditMapping`], evidence: [ROUTE, ARCH, RC5_PROTECT], status: 'SIM_PASS',
    note: 'RC5：产品批准路线按「最外层组 CLAUDE-FIXED + 叶子 EXIT-A」核对；连接 chains 按 Mihomo 叶子在前的顺序解读，与日志 CLAUDE-FIXED[EXIT-A] 同一结论。'},
  {ids: ['F09', 'F10', 'F11', 'F12', 'F13'], impl: [`${CLASSIFIER}#classifyRoute`, `${CLASSIFIER}#parseRouteLogLine`], evidence: [ROUTE, ROUTE_UNKNOWN, PIPE, REAL_FORMAT, REAL_SCOPE], status: 'SIM_PASS',
    note: 'RC5：解析先取 logrus 的 msg 正文，路由名不再粘上引号；四类计数只计 Claude 相关记录。行格式按仓库内 Mihomo v1.19.30 源码构造，未读真实日志。'},
  {ids: ['F14'], impl: [`${OBSERVE}#consumeLiveNetwork`, `${RUNTIME}#createAuditRuntime`], evidence: [NET_PROTECT, NET_SEC, RC5_PROTECT], status: 'SIM_PASS'},
  {ids: ['F15'], impl: [`${PROTECT}#handleProtectionEvent`], evidence: [NET_PROTECT, X07, RC5_PROTECT], status: 'SIM_PASS'},
  {ids: ['F16'], impl: [`${PROTECT}#handleProtectionEvent`], evidence: [NET_PROTECT, X07, RC5_PROTECT], status: 'SIM_PASS'},
  {ids: ['F17'], impl: [`${PROTECT}#handleProtectionEvent`, `${RUNTIME}#createAuditRuntime`, `${RUNTIME}#systemNotice`, `${UI_APP}#renderMonitor`, 'apps/desktop-host/src-tauri/src/lifecycle.rs#notify_critical'], evidence: [NET_PROTECT, RC5_PROTECT, RC5_PAGE, RC6_NOTIFY_HIDDEN, RC6_NOTIFY_FAIL, RC6_NOTIFY_PAGE], status: 'SIM_PASS',
    note: 'RC5：危急提示在保护完成前出现，同一事件归并计数。RC6：窗口隐藏时经宿主 NotifyCritical 发固定文案的系统通知，结果记在提示上，弹不出不报已通知；宿主 lifecycle.rs 未编译，真实通知待 E53。'},
  {ids: ['F18'], impl: [CONTROL_NET, `${PROTECT}#flushEventOutbox`], evidence: [CEVENTS, RC5_PROTECT], status: 'SIM_PASS'},
  {ids: ['F19'], impl: [CONTROL_NET, `${PROTECT}#flushEventOutbox`], evidence: [CEVENTS, RC5_PROTECT], status: 'SIM_PASS',
    note: 'RC5：上报没被确认就在本地待报，后续唤醒按同一 event_ref 补报。'},
  {ids: ['F20'], impl: [CONTROL_NET], evidence: [CEVENTS], status: 'SIM_PASS'},
  {ids: ['F21'], impl: ['src/core/ai/index.mjs#startDailyAnalysis'], evidence: [AI_DAILY, UI_J5], status: 'SIM_PASS'},
  {ids: ['F22'], impl: [`${EMERGENCY}#requestEmergencyAccess`, `${LIFE}#executeLifecycle`], evidence: [NET_EMERGENCY, X07], status: 'SIM_PASS'},
  {ids: ['F23', 'F24', 'F25', 'F26', 'F27', 'F28'], impl: [`${ARCHIVE}#archiveLogs`, `${ARCHIVE}#planArchive`, `${ARCHIVE}#rotationFamily`, `${RUNTIME}#createAuditRuntime`, `${SERVICE_LOGS}#createServiceLogSource`, `${HOST_LOGS}#log_read`], evidence: [ARCH, PIPE, REAL_ROTATE, REAL_GAP, REAL_SOURCES, REAL_INCR, RC5_SCHEDULE], status: 'SIM_PASS',
    note: `RC5：正式路径每两小时经宿主只读取得产品网络服务的 core.log / core.1.log，活动日志按当地时间戳快照，轮转续接不重复计数，接不上记缺口。${RC5_RUST}`},
  {ids: ['F29'], impl: [`${DAILY}#evaluateDailyDue`, `${RUNTIME}#createAuditRuntime`], evidence: [X15, REPORTPAIR, RC5_SCHEDULE], status: 'SIM_PASS'},
  {ids: ['F30'], impl: [`${DAILY}#deliverDailyReport`, `${DAILY}#readDeliveredReport`], evidence: [REPORTPAIR, X13, REAL_DELIVERED], status: 'SIM_PASS'},
  {ids: ['F31'], impl: [`${DAILY}#selectWindow`, `${DAILY}#findPriorValidReport`], evidence: [REPORTPAIR, PIPE, REAL_DELIVERED, RC5_TRAFFIC], status: 'SIM_PASS'},
  {ids: ['F32'], impl: [`${PIPELINE}#collectAuditEvidence`, `${MONITOR}#journalCoverage`], evidence: [DAILYPASS, PIPE, MON_CONT, MON_GAPS, RC5_TRAFFIC], status: 'SIM_PASS',
    note: 'RC5：采集连续性由监测记录推出；应用未运行、睡眠、服务不可达、内核未运行都是带起止的缺口。'},
  {ids: ['F33'], impl: [`${DAILY}#renderMarkdown`, `${DAILY}#serializeReport`], evidence: [REPORTPAIR, UI_J5], status: 'SIM_PASS'},
  {ids: ['F34'], impl: [`${DAILY}#buildDailyReport`], evidence: [X13, UI_J5], status: 'SIM_PASS'},
  {ids: ['F35'], impl: [`${DAILY}#buildDailyReport`, `${PROTECT}#handleProtectionEvent`, `${RUNTIME}#createAuditRuntime`], evidence: [PIPE, NET_PROTECT, RC5_PROTECT], status: 'SIM_PASS'},
  {ids: ['F36'], impl: [`${DAILY}#buildDailyReport`, `${MONITOR}#journalTraffic`], evidence: [TRAF_QUOTA, PIPE, UI_J5, RC5_TRAFFIC], status: 'SIM_PASS'},
  {ids: ['F37'], impl: [`${DAILY}#deliverDailyReport`], evidence: [REPORTPAIR, X13], status: 'SIM_PASS'},
  {ids: ['F38'], impl: ['src/core/diagnostics/reports.mjs#redactDiagnostic', `${DAILY}#serializeReport`, `${EXPORTER}#createDiagnosticExport`, `${REDACT}#redactSecrets`, 'tools/release/collect-logs.ps1#Redact'], evidence: [['tests/diagnostics/a-scenarios.test.mjs', 'FD-02/A27 导出脱敏且不含 cookie 值'], UI_J5, RC5_EXPORT, RC5_PAGE, RC6_COLLECT], status: 'SIM_PASS',
    note: `RC5：诊断包先预览、确认后逐个脱敏写入本机日志目录，清单最后写，写失败明说未生成；不自动上传。RC6：发布包内的统一日志收集脚本按同一规则逐文件脱敏（用例逐样本比对），界面起不来时也能用。${RC5_RUST}`},
  {ids: ['F39'], impl: [`${ARCHIVE}#archiveLogs`, `${REDACT}#inspectSecrets`], evidence: [X14, REAL_SECRET], status: 'SIM_PASS',
    note: 'RC5：含秘密的源不进普通归档；能定位到秘密值时另存脱敏派生件，带自己的哈希，只声明来源哈希。'},
  {ids: ['F40'], impl: ['src/core/local/index.mjs#discover', 'src/adapters/audit/fixtureStore.mjs'], evidence: [GAP_AUDIT], status: 'SIM_PASS',
    note: '扫描范围与清理清单都不含 audit/ 子树，执行后已交付日报与归档字节不变；真实用户目录下的落点留 T10。'},
  {ids: ['F41'], impl: [AUDIT_STORE, `${ARCHIVE}#archiveLogs`, `${SERVICE_LOGS}#createServiceLogSource`], evidence: [ARCH, RC5_SCHEDULE], status: 'SIM_PASS'},
  {ids: ['F42'], impl: [`${UI_SESSION}#aiDailyAnalysis`, UI_COMPOSE], evidence: [UI_AI, UI_J7, X18], status: 'SIM_PASS'},
  {ids: ['F43'], impl: [`${UI_SESSION}#refreshTraffic`, CONTROL_NET, `${UI_APP}#renderMonitor`], evidence: [UI_J5, CEVENTS, RC5_TRAFFIC], status: 'SIM_PASS'},
  {ids: ['F44'], impl: [`${CLASSIFIER}#classifyRoute`], evidence: [ROUTE], status: 'SIM_PASS',
    note: '旧口径 classification_version=2 的历史样例作为回归夹具保留。'},

  {ids: ['A01'], impl: [`${PIPELINE}#collectAuditEvidence`], evidence: [PIPE], status: 'SIM_PASS'},
  {ids: ['A02'], impl: [`${CLASSIFIER}#classifyRoute`], evidence: [X12], status: 'SIM_PASS'},
  {ids: ['A03'], impl: [`${CLASSIFIER}#classifyRoute`], evidence: [ROUTE], status: 'SIM_PASS'},
  {ids: ['A04'], impl: [`${CLASSIFIER}#classifyRoute`], evidence: [ROUTE], status: 'SIM_PASS'},
  {ids: ['A05'], impl: [`${PIPELINE}#collectAuditEvidence`, `${DAILY}#environmentCoverage`], evidence: [GAP_ENV, DAILYPASS], status: 'SIM_PASS',
    note: '主机与客体分别标注覆盖，未覆盖环境进 COLLECTION_ENVIRONMENT_NOT_COVERED 且 whole_machine_claim 为 false；真实覆盖差异留 T10。'},
  {ids: ['A06'], impl: [`${PROTECT}#handleProtectionEvent`], evidence: [NET_PROTECT, RC5_PROTECT], status: 'SIM_PASS'},
  {ids: ['A07'], impl: [`${PROTECT}#handleProtectionEvent`], evidence: [NET_PROTECT], status: 'SIM_PASS'},
  {ids: ['A08'], impl: [`${PROTECT}#handleProtectionEvent`], evidence: [NET_PROTECT], status: 'SIM_PASS'},
  {ids: ['A09'], impl: [`${PROTECT}#handleProtectionEvent`], evidence: [NET_PROTECT, X07], status: 'SIM_PASS'},
  {ids: ['A10'], impl: [`${CLASSIFIER}#classifyRoute`], evidence: [ROUTE], status: 'SIM_PASS'},
  {ids: ['A11'], impl: [`${CLASSIFIER}#classifyRoute`], evidence: [ROUTE], status: 'SIM_PASS'},
  {ids: ['A12'], impl: [`${CLASSIFIER}#parseRouteLogLine`], evidence: [ROUTE_UNKNOWN], status: 'SIM_PASS'},
  {ids: ['A13'], impl: [`${CLASSIFIER}#parseRouteLogLine`], evidence: [ROUTE_UNKNOWN, X12], status: 'SIM_PASS'},
  {ids: ['A14'], impl: [`${CLASSIFIER}#parseRouteLogLine`], evidence: [ROUTE], status: 'SIM_PASS'},
  {ids: ['A15'], impl: ['src/core/network/compile.mjs#compileNetworkPlan'], evidence: [['tests/delivery/x06-x11.test.mjs', 'X06 三模式依次切换']], status: 'SIM_PASS'},
  {ids: ['A16'], impl: [`${PROTECT}#handleProtectionEvent`], evidence: [NET_PROTECT, RC5_PROTECT], status: 'SIM_PASS'},
  {ids: ['A17'], impl: [CONTROL_NET], evidence: [CEVENTS], status: 'SIM_PASS'},
  {ids: ['A18'], impl: ['src/core/network/apply.mjs#authorizationAllows'], evidence: [['tests/control/events.test.mjs', 'FD-03/A08 A25 模板更新不覆盖分配，敏感 A 变更需确认']], status: 'SIM_PASS'},
  {ids: ['A19'], impl: ['src/core/diagnostics/plans.mjs#recheckDiagnosticAction'], evidence: [['tests/diagnostics/plan.test.mjs', 'FD-02/A19-A26 确认、漂移暂停、应用成功仍异常、恢复冲突']], status: 'SIM_PASS'},
  {ids: ['A20'], impl: [CONTROL_NET, `${PROTECT}#flushEventOutbox`], evidence: [CEVENTS, RC5_PROTECT], status: 'SIM_PASS'},
  {ids: ['A21'], impl: ['src/core/network/quota.mjs#applyQuotaOperation'], evidence: [['tests/delivery/x06-x11.test.mjs', 'X11 上游池耗尽、用户超额与后台失联']], status: 'SIM_PASS'},
  {ids: ['A22'], impl: [`${TRAFFIC}#accumulateTraffic`, `${MONITOR}#journalTraffic`], evidence: [TRAF, X12, MON_RESET, RC5_TRAFFIC], status: 'SIM_PASS'},
  {ids: ['A23'], impl: [`${TRAFFIC}#accumulateTraffic`, `${DAILY}#buildDailyReport`], evidence: [TRAF_QUOTA, X20], status: 'SIM_PASS'},
  {ids: ['A24'], impl: [`${ARCHIVE}#archiveLogs`], evidence: [ARCH, REAL_ROTATE, RC5_SCHEDULE], status: 'SIM_PASS'},
  {ids: ['A25'], impl: [`${PIPELINE}#collectAuditEvidence`, `${ARCHIVE}#archiveLogs`], evidence: [ARCH, PIPE, REAL_GAP, REAL_SOURCES], status: 'SIM_PASS'},
  {ids: ['A26'], impl: [`${DAILY}#evaluateDailyDue`, `${ARCHIVE}#archiveLogs`], evidence: [X15, REAL_INCR, RC5_SCHEDULE], status: 'SIM_PASS'},
  {ids: ['A27'], impl: [`${PROTECT}#handleProtectionEvent`, `${ARCHIVE}#archiveLogs`], evidence: [NET_PROTECT, ARCH], status: 'SIM_PASS'},
  {ids: ['A28'], impl: [`${DAILY}#evaluateDailyDue`, `${RUNTIME}#createAuditRuntime`], evidence: [X15, RC5_SCHEDULE], status: 'SIM_PASS'},
  {ids: ['A29'], impl: [`${DAILY}#deliverDailyReport`], evidence: [REPORTPAIR, X13], status: 'SIM_PASS'},
  {ids: ['A30'], impl: [`${DAILY}#deliverDailyReport`], evidence: [REPORTPAIR], status: 'SIM_PASS'},
  {ids: ['A31'], impl: [`${DAILY}#deliverDailyReport`], evidence: [REPORTPAIR, X13], status: 'SIM_PASS'},
  {ids: ['A32'], impl: [`${DAILY}#evaluateDailyDue`, `${DAILY}#deliverDailyReport`], evidence: [X15], status: 'SIM_PASS'},
  {ids: ['A33'], impl: [`${DAILY}#selectWindow`], evidence: [REPORTPAIR], status: 'SIM_PASS'},
  {ids: ['A34'], impl: [`${DAILY}#buildDailyReport`], evidence: [REPORTPAIR, PIPE, REAL_ROTATE], status: 'SIM_PASS'},
  {ids: ['A35'], impl: [`${DAILY}#buildDailyReport`], evidence: [X13, UI_J5], status: 'SIM_PASS'},
  {ids: ['A36'], impl: [`${PIPELINE}#collectAuditEvidence`, `${MONITOR}#journalCoverage`, `${RUNTIME}#createAuditRuntime`], evidence: [DAILYPASS, MON_CONT, MON_PAUSE, RC5_PAUSE, RC5_JOURNAL_RETRY], status: 'SIM_PASS'},
  {ids: ['A37'], impl: [`${ARCHIVE}#archiveLogs`, 'src/core/ai/evidence.mjs#redactForModel'], evidence: [X14, ['tests/delivery/x01-x05.test.mjs', 'X04 客户端包与上传内容不含模型配置']], status: 'SIM_PASS'},
  {ids: ['A38'], impl: ['src/core/ai/tools.mjs#executeClientTool'], evidence: [['tests/delivery/x01-x05.test.mjs', 'X02 模型越权请求被客户端拒绝']], status: 'SIM_PASS'},
  {ids: ['A39'], impl: [AUDIT_STORE, 'src/core/local/index.mjs#discover'], evidence: [GAP_AUDIT, ARCH], status: 'SIM_PASS',
    note: '清理与监控并存时互不影响；真实目录下的并存验证仍留 T10。'},
  {ids: ['A40'], impl: [`${CLASSIFIER}#classifyRoute`], evidence: [ROUTE], status: 'PARTIAL',
    note: '用户所贴的 7/2/9、1247/0/36 原始样例未纳入本仓库夹具；现有回归用等价的合成日志。'},
  {ids: ['A41'], impl: [`${DAILY}#renderMarkdown`, `${DAILY}#serializeReport`], evidence: [REPORTPAIR, UI_J5, X15], status: 'SIM_PASS'},
  {ids: ['A42'], impl: [`${UI_SESSION}#aiDailyAnalysis`], evidence: [UI_AI, X13, X18], status: 'SIM_PASS'},
];
