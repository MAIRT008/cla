import {activeWhitelist} from '../../src/core/network/index.mjs';
import {loadAiNotes, loadAuditReports} from '../../src/adapters/audit/reports.mjs';

const MODE_LABELS = {
  daily_single_ip: '日常单 IP',
  claude_single_ip: 'Claude 专用单 IP',
  claude_dual_ip: 'Claude 专用双 IP',
};

function errorInfo(error) {
  return {code: error?.code || 'UI_FAILED', message: error?.reason || error?.message || String(error)};
}

function cancelledError() {
  return Object.assign(new Error('cancelled'), {code: 'CANCELLED'});
}

function waitAbortable(ms, signal) {
  if (!ms) return Promise.resolve();
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(cancelledError());
      return;
    }
    const timer = setTimeout(resolve, ms);
    signal?.addEventListener('abort', () => {
      clearTimeout(timer);
      reject(cancelledError());
    }, {once: true});
  });
}

function authenticate(compose, token) {
  if (!token || !compose.controlAuth?.authenticate) return null;
  try {
    const request = new Request('https://application.synthetic.invalid/api/session', {
      headers: {authorization: `Bearer ${token}`},
    });
    return compose.controlAuth.authenticate(request);
  } catch {
    return null;
  }
}

function sessionRecordId(userRef) {
  return `ui-session:${userRef || 'anonymous'}`;
}

export function createDesktopSession(compose, options = {}) {
  const token = options.sessionToken || compose.sessionToken || null;
  const identity = authenticate(compose, token);
  const ai = compose.createAi?.({sessionToken: token, userRef: identity?.user_ref}) || null;
  const inflight = {local: null, execute: null, generation: {local: 0, diag: 0, network: 0, traffic: 0, admin: 0, discovery: 0, monitor: 0}};
  const state = {
    view: 'inspect',
    inspectTab: 'local',
    sessionToken: token,
    userRef: identity?.user_ref || null,
    username: identity?.username || null,
    role: identity?.role || 'anonymous',
    sessionRef: identity?.session_ref || null,
    env: compose.env,
    profileRef: 'Default',
    mode: 'daily_single_ip',
    local: {scan: null, classification: null, plan: null, confirmation: null, operation: null, rechecks: [], restore: null, answers: {}, error: null, busy: false, executing: false, progress: null, export: null, selectedRecs: null, devSample: null},
    diag: {result: null, browser: null, accepted: null, plan: null, executed: null, recheck: null, restore: null, ai: null, error: null},
    discovery: {view: null, error: null},
    network: {preview: null, apply: null, whitelist: null, emergency: null, readback: null, lifecycle: null, protection: null, maintenance: null, error: null},
    traffic: {quota: null, events: [], daily: null, history: [], notes: [], export: null, error: null},
    monitor: {preview: null, export: null, folder: null, error: null},
    ai: {capabilities: null, task: null, error: null},
    admin: {
      users: null, selectedUserRef: null, sessions: null, modelConfig: null, quotaAdapter: null, probeServices: null, resources: null, sources: null,
      templates: null, assignment: null, credentials: null, usage: null, pool: null, events: null, serviceState: null,
      subscription: null, last: null, notice: null, error: null, completed: {name: null, seq: 0},
    },
    settings: {theme: 'default', lang: 'zh-CN'},
    disconnected: compose.disconnected === true,
    aiAvailable: compose.aiAvailable !== false,
    nativeBridge: compose.nativeBridge !== false,
  };

  function persist() {
    compose.store.saveRecord('ui_session', sessionRecordId(state.userRef), {
      user_ref: state.userRef,
      scan_id: state.local.scan?.scan_id || null,
      plan_id: state.local.plan?.plan_id || null,
      operation_id: state.local.operation?.operation_id || null,
      diagnostic_task_id: state.diag.result?.task_id || null,
      diagnostic_plan_id: state.diag.plan?.plan_id || null,
      env: state.env,
      profile_ref: state.profileRef,
      mode: state.mode,
    });
  }

  function hydrate() {
    const saved = compose.store.getRecord(sessionRecordId(state.userRef), 'ui_session');
    if (!saved || saved.user_ref !== state.userRef) return;
    const scan = saved.scan_id ? compose.store.getRecord(saved.scan_id, 'scan') : null;
    if (scan) {
      state.local.scan = scan;
      const answers = {};
      for (const identityItem of scan.identities || []) {
        const recorded = (compose.store.listRecords('account_answer') || []).find((item) => item.identity_ref === identityItem.identity_ref && item.scan_id === scan.scan_id);
        if (recorded) answers[identityItem.identity_ref] = recorded.status;
      }
      state.local.answers = answers;
    }
    const classification = scan ? (compose.store.listRecords('classification') || []).find((item) => item.scan_id === scan.scan_id) : null;
    if (classification) state.local.classification = classification;
    const plan = saved.plan_id ? compose.store.getRecord(saved.plan_id, 'plan') : null;
    if (plan) {
      state.local.plan = plan;
      state.local.confirmation = compose.store.getRecord(`confirmation:${plan.plan_id}`, 'confirmation');
    }
    const operation = saved.operation_id ? compose.store.getRecord(saved.operation_id, 'operation') : null;
    if (operation && (!plan || operation.plan_id === plan.plan_id)) state.local.operation = operation;
    const diag = saved.diagnostic_task_id ? compose.store.getRecord(saved.diagnostic_task_id, 'diagnostic_result') : null;
    if (diag) state.diag.result = diag;
    const diagPlan = saved.diagnostic_plan_id ? compose.store.getRecord(saved.diagnostic_plan_id, 'diagnostic_plan') : null;
    if (diagPlan) state.diag.plan = diagPlan;
    if (saved.env) state.env = saved.env;
    if (saved.profile_ref) state.profileRef = saved.profile_ref;
    if (saved.mode) state.mode = saved.mode;
  }

  hydrate();

  function currentWhitelist() {
    if (!state.userRef) return null;
    return state.network.whitelist?.whitelist || compose.network.getWhitelist(state.userRef);
  }

  function notesFor(reportId) {
    return (state.traffic.notes || []).filter((item) => item.reportId === reportId);
  }

  function snapshot() {
    const local = state.local;
    const classification = local.classification;
    const adminVisible = state.role === 'admin';
    return {
      view: state.view,
      inspectTab: state.inspectTab,
      userRef: state.userRef,
      username: state.username,
      role: state.role,
      sessionRef: state.sessionRef,
      account: compose.account ? {...compose.account, notice: compose.accountNotice?.() ?? compose.account.notice ?? null} : null,
      env: state.env,
      profileRef: state.profileRef,
      disconnected: state.disconnected,
      aiAvailable: state.aiAvailable,
      nativeBridge: state.nativeBridge,
      notice: state.nativeBridge === false ? '原生桥接未接入' : null,
      local: {
        status: local.busy ? 'RUNNING' : (local.executing ? 'EXECUTING' : (local.scan?.status || (local.scan ? 'SCANNED' : 'IDLE'))),
        busy: local.busy,
        executing: local.executing,
        scan_id: local.scan?.scan_id || null,
        identities: local.scan?.identities || [],
        object_count: local.scan?.objects?.length || 0,
        progress: local.progress,
        score: classification?.score?.score ?? classification?.score ?? null,
        score_status: classification?.score?.status || null,
        categories: classification?.result_groups || classification?.results || classification?.categories || [],
        problems: classification?.problems || [],
        gaps: classification?.coverage?.gaps || local.scan?.coverage?.gaps || [],
        protections: (local.scan?.objects || []).filter((item) => (item.protected_paths || []).length).map((item) => ({path: item.relative_path, protected_paths: item.protected_paths})),
        recommendations: classification?.recommendations || [],
        selectedRecs: local.selectedRecs,
        plan_id: local.plan?.plan_id || null,
        plan_status: local.confirmation ? 'CONFIRMED' : (local.plan ? (local.plan.status || 'AWAITING_CONFIRMATION') : null),
        operation_id: local.operation?.operation_id || null,
        operation_status: local.operation?.status || null,
        receipts: local.operation?.receipts || [],
        restore: local.restore,
        restorables: (local.operation?.receipts || []).filter((item) => item.backup_ref).map((item) => {
          const action = (local.plan?.actions || []).find((entry) => entry.action_id === item.action_id);
          return {backup_ref: item.backup_ref, action_id: item.action_id, kind: action?.kind || null, relative_path: action?.relative_path || null};
        }),
        export: local.export,
        devSample: local.devSample,
        error: local.error,
        answers: {...local.answers},
      },
      discovery: {
        attached: Boolean(compose.discovery),
        status: state.discovery.view?.environment?.status || null,
        candidates: state.discovery.view?.discovered?.candidates || [],
        environments: state.discovery.view?.discovered?.environments || [],
        default_browser: state.discovery.view?.discovered?.default_browser || null,
        authorized_roots: state.discovery.view?.authorized_roots || [],
        stale_roots: state.discovery.view?.environment?.stale_roots || [],
        scopes: state.discovery.view?.environment?.scopes || [],
        gaps: state.discovery.view?.environment?.gaps || [],
        error: state.discovery.error,
      },
      diag: {
        task_id: state.diag.result?.task_id || null,
        status: state.diag.result?.status || null,
        score: state.diag.result?.scoring?.score ?? null,
        issues: state.diag.result?.issues || [],
        receipt: Boolean(state.diag.accepted?.ok) || Boolean((state.diag.result?.observations || []).some((item) => item.check_id === 'browser.session-sample')),
        browser: state.diag.browser,
        plan_id: state.diag.plan?.plan_id || null,
        executed: state.diag.executed?.status || null,
        recheck: state.diag.recheck?.status || null,
        restore: state.diag.restore?.status || null,
        ai: state.diag.ai,
        error: state.diag.error,
        env: state.env,
        profileRef: state.profileRef,
      },
      network: {
        modes: MODE_LABELS,
        currentMode: state.mode,
        currentModeLabel: MODE_LABELS[state.mode] || state.mode,
        whitelistActive: activeWhitelist(currentWhitelist(), state.mode),
        whitelistRetained: (currentWhitelist()?.entries || []).length,
        preview: state.network.preview,
        apply: state.network.apply,
        whitelist: state.network.whitelist || (state.userRef ? compose.network.getWhitelist(state.userRef) : null),
        whitelistEntries: currentWhitelist()?.entries || [],
        emergency: state.network.emergency,
        readback: state.network.readback,
        lifecycle: state.network.lifecycle,
        protection: state.network.protection,
        maintenance: state.network.maintenance,
        error: state.network.error,
      },
      traffic: {
        quota: state.traffic.quota,
        events: state.traffic.events,
        dailyPath: state.traffic.dailyPath || null,
        daily: state.traffic.daily && {
          reportId: state.traffic.daily.reportId,
          reportDate: state.traffic.daily.reportDate,
          routeResult: state.traffic.daily.routeResult,
          coverageStatus: state.traffic.daily.coverageStatus,
          routeCounts: state.traffic.daily.routeCounts,
          late_ai_note: notesFor(state.traffic.daily.reportId).at(-1) || null,
          totals: state.traffic.daily.traffic?.totals || null,
          applications: state.traffic.daily.traffic?.byProcess || state.traffic.daily.traffic?.applications || null,
          egress: state.traffic.daily.traffic?.byEgress || null,
          unattributed: state.traffic.daily.traffic ? {
            process: state.traffic.daily.traffic.unattributedProcess || null,
            shortLived: state.traffic.daily.traffic.shortLivedUnattributed || null,
          } : null,
          connectionLines: state.traffic.daily.traffic?.connectionLines || null,
          window: {start: state.traffic.daily.windowStart, end: state.traffic.daily.windowEnd},
          collectionGaps: state.traffic.daily.collectionEvidence?.gaps || [],
          protectionEvents: state.traffic.daily.protection?.events || [],
          quota: state.traffic.daily.quota || null,
          archiveEntries: (state.traffic.daily.archive?.entries || []).map((entry) => ({archivePath: entry.archivePath, sourceStreamId: entry.sourceStreamId, sha256: entry.sha256, status: entry.status})),
          coverageIssues: state.traffic.daily.coverageIssues || state.traffic.daily.traffic?.coverageIssues || [],
        },
        history: state.traffic.history,
        notes: state.traffic.notes,
        export: state.traffic.export,
        error: state.traffic.error,
      },
      monitor: {
        attached: Boolean(compose.auditRuntime),
        ...(compose.auditRuntime ? compose.auditRuntime.status() : {enabled: false, alerts: []}),
        log_root: compose.logRoot || null,
        preview: state.monitor.preview,
        export: state.monitor.export,
        folder: state.monitor.folder,
        error: state.monitor.error,
      },
      ai: {
        available: state.aiAvailable && Boolean(ai),
        unavailable: compose.aiUnavailable || null,
        capabilities: state.ai.capabilities,
        task: state.ai.task,
        error: state.ai.error,
      },
      admin: adminSnapshot(adminVisible),
      settings: state.settings,
    };
  }

  /**
   * 管理区快照只含服务端回来的记录与状态；密码、Key、令牌、订阅链接这些输入从不进 state。
   * 非管理员会话一律为空：页面隐藏只是展示，授权由控制端判定。
   */
  function adminSnapshot(visible) {
    const admin = state.admin;
    const pick = (value) => (visible ? value : null);
    const selectedUser = (admin.users || []).find((user) => user.user_ref === admin.selectedUserRef) || null;
    return {
      visible,
      users: pick(admin.users),
      selectedUserRef: pick(admin.selectedUserRef),
      selectedUser: pick(selectedUser),
      sessions: pick(admin.sessions),
      modelConfig: pick(admin.modelConfig),
      quotaAdapter: pick(admin.quotaAdapter),
      probeServices: pick(admin.probeServices),
      resources: pick(admin.resources),
      sources: pick(admin.sources),
      templates: pick(admin.templates),
      assignment: pick(admin.assignment),
      credentials: pick(admin.credentials),
      usage: pick(admin.usage),
      pool: pick(admin.pool),
      events: pick(admin.events),
      serviceState: pick(admin.serviceState),
      subscription: pick(admin.subscription),
      last: pick(admin.last),
      notice: pick(admin.notice),
      completed: admin.completed,
      error: admin.error,
    };
  }

  async function control(method, pathname, body) {
    const request = new Request(`https://application.synthetic.invalid${pathname}`, {
      method,
      headers: {'content-type': 'application/json', authorization: `Bearer ${state.sessionToken || ''}`},
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    let response;
    try {
      response = await compose.handler.handle(request);
    } catch (error) {
      throw Object.assign(new Error('无法连接控制端'), {code: 'CONTROL_UNREACHABLE', cause: error});
    }
    const text = await response.text();
    let json = null;
    try {
      json = text ? JSON.parse(text) : null;
    } catch {
      json = {code: 'CONTROL_RESPONSE_INVALID', reason: '控制端返回的内容无法解析'};
    }
    return {status: response.status, body: json};
  }

  /** 管理请求：HTTP 4xx/5xx 或业务 ok:false 都转成带码的错误，由 run 显示；不在本地假装成功。 */
  async function adminRequest(method, pathname, body) {
    const result = await control(method, pathname, body);
    if (result.status >= 400 || result.body?.ok === false) {
      throw Object.assign(new Error(result.body?.reason || '管理操作没有完成'), {
        code: result.body?.code || `CONTROL_HTTP_${result.status}`,
        reason: result.body?.reason || '管理操作没有完成',
        request_ref: result.body?.request_ref || null,
        body: result.body,
      });
    }
    return result.body;
  }

  function adminTarget() {
    const userRef = state.admin.selectedUserRef;
    if (!userRef) throw Object.assign(new Error('先在用户列表里选择一个用户'), {code: 'ADMIN_TARGET_REQUIRED'});
    return userRef;
  }

  function adminQuery(userRef) {
    return `user_ref=${encodeURIComponent(userRef)}`;
  }

  function trimmed(value) {
    return typeof value === 'string' ? value.trim() : '';
  }

  function optionalNumber(value) {
    const text = trimmed(value === undefined || value === null ? '' : String(value));
    if (!text) return undefined;
    const number = Number(text);
    if (!Number.isFinite(number)) throw Object.assign(new Error(`不是有效数字：${text}`), {code: 'ADMIN_INPUT_INVALID'});
    return number;
  }

  /** 管理动作统一收尾：记录完成序号；出错时显示错误码与请求引用，便于对照控制端日志。 */
  function runAdmin(name, work) {
    return run('admin', async ({commit}) => {
      commit(() => { state.admin.notice = null; });
      try {
        await work({commit});
      } catch (error) {
        const info = errorInfo(error);
        commit(() => {
          if (error?.body) state.admin.last = error.body;
          state.admin.error = {code: info.code, message: info.message, request_ref: error?.request_ref || null};
        });
      }
      commit(() => { state.admin.completed = {name, seq: state.admin.completed.seq + 1}; });
      return snapshot();
    });
  }

  async function loadSelectedUser(commit, userRef) {
    const failures = [];
    const load = async (key, pathname) => {
      try {
        const body = await adminRequest('GET', pathname);
        commit(() => { state.admin[key] = body; });
      } catch (error) {
        commit(() => { state.admin[key] = null; });
        failures.push(error);
      }
    };
    await load('sessions', `/api/admin/sessions?${adminQuery(userRef)}`);
    await load('assignment', `/api/admin/assignments?${adminQuery(userRef)}`);
    await load('credentials', `/api/admin/credentials?${adminQuery(userRef)}`);
    await load('events', `/api/admin/events?${adminQuery(userRef)}`);
    return failures;
  }

  async function reloadUsers(commit) {
    const body = await adminRequest('GET', '/api/admin/users');
    commit(() => {
      state.admin.users = body.users || [];
      if (!state.admin.users.some((user) => user.user_ref === state.admin.selectedUserRef)) state.admin.selectedUserRef = null;
    });
  }

  function localInProgress() {
    if (state.local.busy) return {code: 'SCAN_IN_PROGRESS', message: '扫描进行中：先等扫描结束或点取消'};
    if (state.local.executing) return {code: 'OPERATION_IN_PROGRESS', message: '批量处理进行中：先等执行结束或点取消'};
    return null;
  }

  /** 诊断端口由宿主的受管探测服务派生；没有就点名未接入，不让调用崩成内部错误。 */
  function requireDiagnostics() {
    if (!compose.diagnostics) {
      throw Object.assign(
        new Error('诊断能力未接入：宿主没有回报受管探测服务'),
        {code: 'DIAGNOSTICS_NOT_ATTACHED'},
      );
    }
    return compose.diagnostics;
  }

  function requireDiscovery() {
    if (!compose.discovery) throw Object.assign(new Error('真实发现未接入：当前组合根只有合成工作区'), {code: 'DISCOVERY_NOT_ATTACHED'});
    return compose.discovery;
  }

  function rootRefList(value) {
    const list = (Array.isArray(value) ? value : [value]).filter((item) => typeof item === 'string' && item);
    if (!list.length) throw Object.assign(new Error('先选择要授权或撤销的位置'), {code: 'ROOTS_NOT_SELECTED'});
    return list;
  }

  async function run(bucket, work, options = {}) {
    if (options.needsSettledLocal) {
      const blocked = localInProgress();
      if (blocked) {
        state.local.error = blocked;
        return snapshot();
      }
    }
    const generation = (inflight.generation[bucket] += 1);
    const isCurrent = () => generation === inflight.generation[bucket];
    state[bucket].error = null;
    const commit = (apply) => {
      if (!isCurrent()) return false;
      apply();
      return true;
    };
    try {
      const result = await work({commit, isCurrent});
      if (!isCurrent()) return snapshot();
      persist();
      return result;
    } catch (error) {
      if (!isCurrent()) return snapshot();
      state[bucket].error = errorInfo(error);
      // 流程失败落本地应用日志：只记区块与错误码，不记输入或返回内容。
      compose.appLog?.('error', 'ui.action_failed', {bucket, code: state[bucket].error.code});
      return snapshot();
    }
  }

  function requireMonitor() {
    if (!compose.auditRuntime) throw Object.assign(new Error('监测与审计未接入：当前组合根没有产品审计运行时'), {code: 'MONITOR_NOT_ATTACHED'});
    return compose.auditRuntime;
  }

  function requireLogExport() {
    if (!compose.diagnosticExport) throw Object.assign(new Error('本地日志导出未接入：当前组合根没有宿主日志能力'), {code: 'LOG_EXPORT_NOT_ATTACHED'});
    return compose.diagnosticExport;
  }

  function runLocal(work) {
    return run('local', work, {needsSettledLocal: true});
  }

  async function previewRestoreFor(backupRef) {
    const receipts = (state.local.operation?.receipts || []).filter((item) => item.backup_ref);
    const receipt = (backupRef && receipts.find((item) => item.backup_ref === backupRef)) || receipts[0];
    if (!receipt?.backup_ref) return {status: 'NO_BACKUP'};
    try {
      return await compose.local.previewRestore({backupRef: receipt.backup_ref});
    } catch (error) {
      return {status: 'PREVIEW_FAILED', backup_ref: receipt.backup_ref, recoverable: false, conflicts: [{code: error?.code || 'RESTORE_CONFLICT', message: error?.reason || error?.message}]};
    }
  }

  const actions = {
    snapshot,
    setView(name) {
      state.view = name;
      return snapshot();
    },
    setInspectTab(name) {
      state.inspectTab = name;
      return snapshot();
    },
    async localScan(mode = 'deep') {
      if (state.local.executing) {
        state.local.error = {code: 'OPERATION_IN_PROGRESS', message: '批量处理进行中：先等执行结束或点取消'};
        return snapshot();
      }
      inflight.local?.abort();
      const ac = new AbortController();
      inflight.local = ac;
      state.local.busy = true;
      state.local.error = null;
      const profileRef = state.profileRef;
      return run('local', async ({commit}) => {
        try {
          if (state.disconnected) throw Object.assign(new Error('本地服务未接入'), {code: 'SERVICE_UNAVAILABLE'});
          await waitAbortable(compose.scanDelayMs || 0, ac.signal);
          const scan = await compose.local.discover({
            mode,
            profileRefs: [profileRef],
            signal: ac.signal,
            onProgress: (info) => { commit(() => { state.local.progress = info; }); },
          });
          commit(() => { state.local.scan = ac.signal.aborted ? {...scan, status: 'cancelled', cancelled: true} : scan; });
        } finally {
          if (inflight.local === ac) state.local.busy = false;
        }
        return snapshot();
      });
    },
    async localAnswer(identityRef, status) {
      return runLocal(async ({commit}) => {
        if (!identityRef) throw Object.assign(new Error('identity is required'), {code: 'IDENTITY_REQUIRED'});
        const scan = state.local.scan;
        const identity = scan?.identities?.find((item) => item.identity_ref === identityRef);
        if (!scan || !identity) throw Object.assign(new Error('identity is not in this scan'), {code: 'IDENTITY_NOT_FOUND'});
        compose.local.recordAccountAnswer({
          scanId: scan.scan_id,
          identityRef: identity.identity_ref,
          identityFingerprint: identity.identity_fingerprint,
          status,
        });
        commit(() => { state.local.answers[identity.identity_ref] = status; });
        return snapshot();
      });
    },
    async localClassify() {
      return runLocal(async ({commit}) => {
        const classification = compose.local.classify({scanId: state.local.scan.scan_id});
        commit(() => {
          state.local.classification = classification;
          state.local.selectedRecs = (classification.recommendations || []).map((item) => item.recommendation_id);
        });
        return snapshot();
      });
    },
    async localToggleRecommendation(recommendationId, enabled) {
      const current = new Set(state.local.selectedRecs || []);
      if (enabled) current.add(recommendationId);
      else current.delete(recommendationId);
      state.local.selectedRecs = [...current];
      return snapshot();
    },
    async localDecide(problemId, decision, reason = 'user-adjusted') {
      return runLocal(async ({commit}) => {
        compose.local.recordProblemDecision({scanId: state.local.scan.scan_id, problemId, decision, reason});
        const classification = compose.local.classify({scanId: state.local.scan.scan_id});
        commit(() => { state.local.classification = classification; });
        return snapshot();
      });
    },
    async localBuildPlan() {
      return runLocal(async ({commit}) => {
        const recs = state.local.selectedRecs || (state.local.classification?.recommendations || []).map((item) => item.recommendation_id);
        const plan = await compose.local.buildActionPlan({scanId: state.local.scan.scan_id, recommendationIds: recs});
        commit(() => {
          state.local.plan = plan;
          state.local.confirmation = null;
        });
        return snapshot();
      });
    },
    async localConfirm(actionIds) {
      return runLocal(async ({commit}) => {
        const plan = state.local.plan;
        const ids = actionIds || plan.actions.map((item) => item.action_id);
        const confirmation = await compose.local.confirmActionPlan({planId: plan.plan_id, version: plan.version, actionIds: ids, source: 'local-user'});
        commit(() => { state.local.confirmation = confirmation; });
        return snapshot();
      });
    },
    async localExecute() {
      const blockedByScan = state.local.busy ? {code: 'SCAN_IN_PROGRESS', message: '扫描进行中：先等扫描结束或点取消'} : null;
      if (blockedByScan) {
        state.local.error = blockedByScan;
        return snapshot();
      }
      inflight.execute?.abort();
      const ac = new AbortController();
      inflight.execute = ac;
      state.local.executing = true;
      const operationId = compose.store.newId('ui-op');
      return run('local', async ({commit}) => {
        const plan = state.local.plan;
        const total = (plan.actions || []).length;
        const poll = setInterval(() => {
          const live = compose.store.getRecord(operationId, 'operation');
          if (!live) return;
          commit(() => {
            state.local.operation = live;
            state.local.progress = {stage: 'execute', done: (live.receipts || []).filter((item) => item.status !== 'STARTED').length, total};
          });
        }, 10);
        try {
          const operation = await compose.local.executeConfirmedPlan({
            planId: plan.plan_id,
            version: plan.version,
            operationId,
            signal: ac.signal,
          });
          commit(() => { state.local.operation = operation; });
        } finally {
          clearInterval(poll);
          commit(() => { state.local.progress = null; });
          if (inflight.execute === ac) state.local.executing = false;
        }
        return snapshot();
      }).finally(() => { if (inflight.execute === ac) state.local.executing = false; });
    },
    async localRecheck() {
      return runLocal(async ({commit}) => {
        const plan = state.local.plan;
        const ids = state.local.confirmation?.action_ids || plan.actions.map((item) => item.action_id);
        const rechecks = [];
        for (const actionId of ids) rechecks.push(await compose.local.recheckAction({planId: plan.plan_id, actionId}));
        commit(() => { state.local.rechecks = rechecks; });
        return snapshot();
      });
    },
    async localPreviewRestore(backupRef) {
      return runLocal(async ({commit}) => {
        const preview = await previewRestoreFor(backupRef);
        commit(() => { state.local.restore = preview; });
        return snapshot();
      });
    },
    async localRestore() {
      return runLocal(async ({commit}) => {
        const preview = state.local.restore?.preview_id ? state.local.restore : await previewRestoreFor();
        if (!preview?.preview_id) {
          commit(() => { state.local.restore = preview; });
          return snapshot();
        }
        compose.local.confirmRestore({previewId: preview.preview_id, source: 'local-user'});
        const restored = await compose.local.restoreChange({previewId: preview.preview_id});
        commit(() => { state.local.restore = restored; });
        return snapshot();
      });
    },
    async devSample() {
      return runLocal(async ({commit}) => {
        const scan = state.local.scan;
        const sample = scan
          ? {source: 'local-service', scan_id: scan.scan_id, objects: (scan.objects || []).map((item) => ({relative_path: item.relative_path, kind: item.kind}))}
          : {source: 'none', note: '开发合成入口：先扫描，再查看服务返回的对象清单'};
        commit(() => { state.local.devSample = sample; });
        return snapshot();
      });
    },
    async localExport() {
      return runLocal(async ({commit}) => {
        const report = await compose.local.getReport({scanId: state.local.scan.scan_id, operationId: state.local.operation?.operation_id});
        commit(() => { state.local.export = report; });
        return snapshot();
      });
    },
    async localResume() {
      return runLocal(async ({commit}) => {
        if (!state.local.operation?.operation_id) throw Object.assign(new Error('no operation to resume'), {code: 'OPERATION_MISSING'});
        const operation = await compose.local.resumeOperation({operationId: state.local.operation.operation_id});
        commit(() => { state.local.operation = operation; });
        return snapshot();
      });
    },
    async cancelLocal() {
      inflight.local?.abort();
      inflight.execute?.abort();
      state.local.busy = false;
      if (state.local.scan) state.local.scan = {...state.local.scan, status: 'cancelled', cancelled: true};
      state.local.error = {code: 'CANCELLED', message: 'cancelled'};
      return snapshot();
    },
    async discoverEnvironment() {
      return run('discovery', async ({commit}) => {
        const view = await requireDiscovery().refresh();
        commit(() => { state.discovery.view = view; });
        return snapshot();
      });
    },
    async authorizeRoots(rootRefs) {
      return run('discovery', async ({commit}) => {
        const view = await requireDiscovery().authorize(rootRefList(rootRefs));
        commit(() => { state.discovery.view = view; });
        return snapshot();
      }, {needsSettledLocal: true});
    },
    async revokeRoots(rootRefs) {
      return run('discovery', async ({commit}) => {
        const view = await requireDiscovery().revoke(rootRefList(rootRefs));
        commit(() => { state.discovery.view = view; });
        return snapshot();
      }, {needsSettledLocal: true});
    },
    async diagScan(mode = 'deep', scope = {}) {
      return run('diag', async ({commit}) => {
        const environmentRef = scope.environmentRef || state.env;
        const profileRef = scope.profileRef || state.profileRef;
        const result = await requireDiagnostics().startScan({mode, environmentRef, profileRef});
        commit(() => {
          state.env = environmentRef;
          state.profileRef = profileRef;
          state.diag.result = result;
        });
        return snapshot();
      });
    },
    /** 在系统默认浏览器里打开诊断页；结果由用户浏览器回传，WebView 不再自己拼样本。 */
    async diagOpenBrowser() {
      return run('diag', async ({commit}) => {
        if (!compose.browserDiag) throw Object.assign(new Error('默认浏览器诊断未接入：宿主没有提供本机回环监听'), {code: 'BROWSER_DIAG_NOT_ATTACHED'});
        const browser = await compose.browserDiag.open({taskRef: state.diag.result?.task_id, environmentRef: state.env});
        commit(() => {
          state.diag.browser = browser;
          state.diag.accepted = null;
        });
        return snapshot();
      });
    },
    async diagCheckBrowser() {
      return run('diag', async ({commit}) => {
        if (!compose.browserDiag) throw Object.assign(new Error('默认浏览器诊断未接入：宿主没有提供本机回环监听'), {code: 'BROWSER_DIAG_NOT_ATTACHED'});
        const checked = await compose.browserDiag.check();
        const taskId = state.diag.result?.task_id;
        const refreshed = checked.accepted?.ok && taskId ? requireDiagnostics().result(taskId) : null;
        commit(() => {
          state.diag.browser = checked.view;
          if (checked.accepted) state.diag.accepted = checked.accepted;
          if (refreshed) state.diag.result = refreshed;
        });
        return snapshot();
      });
    },
    async diagBuildPlan() {
      return run('diag', async ({commit}) => {
        const plan = requireDiagnostics().buildPlan(state.diag.result.task_id, [{
          issue_kind: 'PROTECTED_BYPASS_A',
          kind: 'apply_network',
          payload: {userRef: state.userRef, environmentRef: state.env, mode: 'claude_single_ip', operation_id: `ui-diag-${state.diag.result.task_id}`, authorization: compose.auth(state.userRef)},
          restore_payload: {userRef: state.userRef, environmentRef: state.env, mode: 'daily_single_ip', operation_id: `ui-diag-restore-${state.diag.result.task_id}`, authorization: compose.auth(state.userRef)},
        }]);
        commit(() => { state.diag.plan = plan; });
        return snapshot();
      });
    },
    async diagConfirm() {
      return run('diag', async ({commit}) => {
        const plan = state.diag.plan;
        const ids = plan.actions.filter((item) => item.supported).map((item) => item.action_id);
        const confirmed = requireDiagnostics().confirm(plan.plan_id, ids, 'ui-local-user');
        commit(() => { state.diag.plan = confirmed; });
        return snapshot();
      });
    },
    async diagExecute() {
      return run('diag', async ({commit}) => {
        const executed = await requireDiagnostics().execute(state.diag.plan.plan_id);
        commit(() => { state.diag.executed = executed; });
        return snapshot();
      });
    },
    async diagRecheck() {
      return run('diag', async ({commit}) => {
        const rescan = await requireDiagnostics().startScan({mode: 'quick', previous: state.diag.result, environmentRef: state.env, profileRef: state.profileRef});
        const actionId = state.diag.plan.confirmed_action_ids?.[0] || state.diag.plan.actions[0]?.action_id;
        const recheck = await requireDiagnostics().recheck(state.diag.plan.plan_id, actionId, rescan);
        commit(() => { state.diag.recheck = recheck; });
        return snapshot();
      });
    },
    async diagAiMode() {
      return run('diag', async ({commit}) => {
        if (!ai) {
          commit(() => { state.diag.ai = {status: 'AI_NOT_ATTACHED', note: 'AI 模式未接入；标准诊断结果与缺测仍在'}; });
          return snapshot();
        }
        const result = state.diag.result;
        if (!result) throw Object.assign(new Error('先做一次标准诊断'), {code: 'DIAGNOSTIC_RESULT_MISSING'});
        const plan = state.diag.plan;
        const task = await ai.startNetworkDiagnosis({networkFacts: {
          diagnostic_task_id: result.task_id,
          diagnostic_plan_id: plan?.plan_id || null,
          environment: {environment_ref: result.environment_ref, status: result.status},
          profile: {profile_ref: result.profile_ref},
          configuration: result.scoring,
          history: result.requests,
          dns: (result.observations || []).filter((item) => item.check_id.startsWith('dns.')),
          exit: (result.observations || []).filter((item) => item.check_id.startsWith('exit.')),
          issues: result.issues,
          supported_actions: (plan?.actions || []).filter((item) => item.supported).map((item) => ({
            action_id: item.action_id,
            environment_ref: result.environment_ref,
            profile_ref: result.profile_ref || 'Default',
            status: 'SUPPORTED',
          })),
        }});
        commit(() => { state.diag.ai = task; });
        return snapshot();
      });
    },
    async diagAiConfirm() {
      return run('diag', async ({commit}) => {
        const taskId = state.diag.ai?.taskId;
        if (!taskId) throw Object.assign(new Error('没有等待确认的 AI 网络建议'), {code: 'AI_TASK_MISSING'});
        const record = compose.store.getRecord(taskId, 'ai_task_v1');
        const planId = record?.network_plan?.plan_id;
        if (!planId) throw Object.assign(new Error('AI 还没有给出可确认的网络计划'), {code: 'AI_NETWORK_PLAN_MISSING'});
        ai.confirmNetwork({taskId, planId});
        const resumed = await ai.resume({taskId});
        commit(() => { state.diag.ai = resumed; });
        return snapshot();
      });
    },
    async diagRestore() {
      return run('diag', async ({commit}) => {
        const restore = await requireDiagnostics().restore(state.diag.plan.plan_id, true);
        commit(() => { state.diag.restore = restore; });
        return snapshot();
      });
    },
    async networkPreview(mode) {
      return run('network', async ({commit}) => {
        const preview = await compose.network.previewModeChange({userRef: state.userRef, environmentRef: state.env, mode});
        commit(() => { state.network.preview = preview; });
        return snapshot();
      });
    },
    async networkApply(mode) {
      return run('network', async ({commit}) => {
        const apply = await compose.network.confirmAndApply({
          operation_id: compose.store.newId('ui-net'),
          userRef: state.userRef,
          environmentRef: state.env,
          mode,
          authorization: compose.auth(state.userRef),
        });
        const readback = await compose.network.readState({userRef: state.userRef, environmentRef: state.env});
        commit(() => {
          state.network.apply = apply;
          state.network.readback = readback;
          if (['APPLIED_VERIFIED', 'APPLIED_UNVERIFIED'].includes(apply?.overall)) state.mode = mode;
        });
        return snapshot();
      });
    },
    async networkMaintenance(mode) {
      return run('network', async ({commit}) => {
        const maintenance = await compose.network.confirmAndApply({
          operation_id: compose.store.newId('ui-maint'),
          userRef: state.userRef,
          environmentRef: state.env,
          mode,
          authorization: compose.auth(state.userRef, {kind: 'MAINTENANCE_SCOPE', allow_sensitive: false}),
        });
        commit(() => {
          state.network.maintenance = maintenance;
          if (['APPLIED_VERIFIED', 'APPLIED_UNVERIFIED'].includes(maintenance?.overall)) state.mode = mode;
        });
        return snapshot();
      });
    },
    async networkLifecycle(type) {
      return run('network', async ({commit}) => {
        const lifecycle = await compose.network.executeLifecycle({user_ref: state.userRef, environment_ref: state.env}, {type});
        commit(() => { state.network.lifecycle = lifecycle; });
        return snapshot();
      });
    },
    async networkProtect() {
      return run('network', async ({commit}) => {
        const protection = await compose.network.handleProtection({user_ref: state.userRef, environment_ref: state.env}, {classification: 'WRONG_ROUTE', live: true});
        commit(() => { state.network.protection = protection; });
        return snapshot();
      });
    },
    async networkRestore() {
      return run('network', async ({commit}) => {
        const restoreRef = state.network.apply?.stages?.restore_saved?.restore_ref || state.network.apply?.restore_ref;
        const restored = await compose.network.restore({
          operation_id: compose.store.newId('ui-net-restore'),
          userRef: state.userRef,
          environmentRef: state.env,
          restore_ref: restoreRef,
          authorization: compose.auth(state.userRef),
        });
        commit(() => { state.network.apply = restored; });
        return snapshot();
      });
    },
    async networkWhitelist(action, payload) {
      return run('network', async ({commit}) => {
        const current = compose.network.getWhitelist(state.userRef);
        if ((action === 'enable' || action === 'disable') && payload && !payload.entry_id) {
          const entry = (current?.entries || []).find((item) => item.host === payload.host || item.input === payload.host);
          payload = {...payload, entry_id: entry?.entry_id};
        }
        const whitelist = await compose.network.updateWhitelist({
          userRef: state.userRef,
          action,
          payload,
          mode: state.mode,
          authorization: compose.auth(state.userRef),
          environmentRef: state.env,
          operation_id: compose.store.newId('ui-wl'),
        });
        commit(() => { state.network.whitelist = whitelist; });
        return snapshot();
      });
    },
    async networkEmergency(on, options = {}) {
      return run('network', async ({commit}) => {
        let emergency;
        if (on) {
          const minutes = Number(options.minutes);
          emergency = await compose.network.requestEmergency({
            user_ref: state.userRef,
            environment_ref: state.env,
            mode: state.mode,
            purpose: 'temporary_web_access',
            duration_minutes: Number.isFinite(minutes) && minutes > 0 ? minutes : 30,
            targets: (options.targets || []).filter(Boolean).map((host) => ({host, match: 'subdomains'})),
            confirmation: {confirmed: options.confirmed === true, confirmation_id: compose.store.newId('ui-emergency-confirm')},
          });
        } else {
          emergency = await compose.network.endEmergency({
            session_id: state.network.emergency?.session_id,
            user_ref: state.userRef,
            environment_ref: state.env,
          });
        }
        commit(() => { state.network.emergency = emergency; });
        return snapshot();
      });
    },
    async refreshTraffic() {
      return run('traffic', async ({commit}) => {
        const loaded = await control('GET', '/api/network/quota');
        const events = await control('GET', '/api/network/events');
        const reports = await loadAuditReports(compose.auditStore);
        const notes = await loadAiNotes(compose.auditStore);
        const current = reports.at(-1) || null;
        commit(() => {
          state.traffic.quota = loaded.body?.quota || loaded.body;
          state.traffic.events = events.body?.events || [];
          state.traffic.daily = current?.report || null;
          state.traffic.dailyPath = current?.path || null;
          state.traffic.history = reports.map((item) => ({
            reportId: item.report.reportId,
            reportDate: item.report.reportDate,
            routeResult: item.report.routeResult,
            coverageStatus: item.report.coverageStatus,
            sourceRefs: (item.report.archive?.entries || []).map((entry) => entry.archivePath || entry.sourcePath),
            path: item.path,
          }));
          state.traffic.notes = notes.map((item) => ({path: item.path, ...item.note}));
        });
        return snapshot();
      });
    },
    async exportDaily(format = 'json') {
      return run('traffic', async ({commit}) => {
        const reports = await loadAuditReports(compose.auditStore);
        const current = reports.at(-1);
        if (!current) throw Object.assign(new Error('没有可导出的日报产物'), {code: 'REPORT_MISSING'});
        const sourceJson = current.path;
        const sourceMd = current.path.replace(/daily-audit\.json$/, 'daily-audit.md');
        const jsonText = await compose.auditStore.readText(sourceJson);
        const mdText = await compose.auditStore.readText(sourceMd);
        const jsonPath = await compose.writeExport(`${current.report.reportId}.json`, jsonText);
        const mdPath = await compose.writeExport(`${current.report.reportId}.md`, mdText);
        commit(() => {
          state.traffic.export = {format, jsonPath, mdPath, reportId: current.report.reportId, sourceJson, sourceMd};
        });
        return snapshot();
      });
    },
    /** 读管理数据：用户、模型配置、配额适配、资源与订阅、模板、服务状态。单项失败不挡其他项，第一个错误显示出来。 */
    async adminRefresh() {
      return runAdmin('adminRefresh', async ({commit}) => {
        const failures = [];
        const load = async (pathname, apply) => {
          try {
            const body = await adminRequest('GET', pathname);
            commit(() => apply(body));
          } catch (error) {
            failures.push(error);
          }
        };
        try {
          await reloadUsers(commit);
        } catch (error) {
          failures.push(error);
        }
        await load('/api/admin/model-config', (body) => { state.admin.modelConfig = body; });
        await load('/api/admin/quota-adapter', (body) => { state.admin.quotaAdapter = body.adapter || null; });
        await load('/api/admin/probe-services', (body) => { state.admin.probeServices = body.probe_services || []; });
        await load('/api/admin/resources', (body) => {
          state.admin.resources = body.resources || [];
          state.admin.sources = body.sources || [];
        });
        await load('/api/admin/templates', (body) => { state.admin.templates = body.templates || []; });
        await load('/api/admin/service-state', (body) => { state.admin.serviceState = body; });
        if (state.admin.selectedUserRef) failures.push(...await loadSelectedUser(commit, state.admin.selectedUserRef));
        if (failures.length) throw failures[0];
      });
    },
    /** 只能选服务端用户列表里存在的用户；管理目标切换不改变当前登录身份。 */
    async adminSelectUser(userRef) {
      return runAdmin('adminSelectUser', async ({commit}) => {
        if (!state.admin.users) await reloadUsers(commit);
        const target = (state.admin.users || []).find((user) => user.user_ref === userRef);
        if (!target) throw Object.assign(new Error('该用户不在服务端用户列表里；先刷新管理数据再选择'), {code: 'ADMIN_TARGET_UNKNOWN'});
        commit(() => {
          state.admin.selectedUserRef = target.user_ref;
          state.admin.usage = null;
        });
        const failures = await loadSelectedUser(commit, target.user_ref);
        if (failures.length) throw failures[0];
      });
    },
    async adminCreateUser(username, password) {
      return runAdmin('adminCreateUser', async ({commit}) => {
        const created = await adminRequest('POST', '/api/admin/users', {username: String(username ?? ''), password: String(password ?? '')});
        await reloadUsers(commit);
        commit(() => {
          state.admin.selectedUserRef = created.user?.user_ref || state.admin.selectedUserRef;
          state.admin.last = created;
          state.admin.notice = `已创建普通用户 ${created.user?.username || ''}`;
        });
        await loadSelectedUser(commit, state.admin.selectedUserRef);
      });
    },
    async adminSetUserStatus(status) {
      return runAdmin('adminSetUserStatus', async ({commit}) => {
        const userRef = adminTarget();
        const result = await adminRequest('POST', '/api/admin/users/status', {user_ref: userRef, status});
        await reloadUsers(commit);
        await loadSelectedUser(commit, userRef);
        commit(() => {
          state.admin.last = result;
          state.admin.notice = status === 'DISABLED' ? `已停用，撤销会话 ${result.revoked_sessions} 条` : '已启用';
        });
      });
    },
    async adminResetPassword(password) {
      return runAdmin('adminResetPassword', async ({commit}) => {
        const userRef = adminTarget();
        const result = await adminRequest('POST', '/api/admin/users/password-reset', {user_ref: userRef, password: String(password ?? '')});
        await loadSelectedUser(commit, userRef);
        commit(() => {
          state.admin.last = result;
          state.admin.notice = `密码已重置，撤销会话 ${result.revoked_sessions} 条`;
        });
      });
    },
    async adminRevokeSessions(sessionRef) {
      return runAdmin('adminRevokeSessions', async ({commit}) => {
        const userRef = adminTarget();
        const body = sessionRef ? {session_ref: sessionRef} : {user_ref: userRef};
        const result = await adminRequest('POST', '/api/admin/sessions/revoke', body);
        await reloadUsers(commit);
        await loadSelectedUser(commit, userRef);
        commit(() => {
          state.admin.last = result;
          state.admin.notice = `已撤销会话 ${result.revoked} 条`;
        });
      });
    },
    /** 模型配置：Key 只写。留空表示不改；保存后显示的是服务端回读的配置状态，不是调用成功。 */
    async adminSaveModelConfig(input = {}) {
      return runAdmin('adminSaveModelConfig', async ({commit}) => {
        const body = {task_type: trimmed(input.task_type)};
        if (typeof input.enabled === 'boolean') body.enabled = input.enabled;
        for (const key of ['base_url', 'model', 'policy_version']) if (trimmed(input[key])) body[key] = trimmed(input[key]);
        for (const key of ['max_model_calls', 'max_total_tokens', 'max_output_tokens', 'timeout_ms']) {
          const value = optionalNumber(input[key]);
          if (value !== undefined) body[key] = value;
        }
        if (typeof input.secret === 'string' && input.secret) body.api_key = input.secret;
        if (input.clear_secret === true) body.clear_api_key = true;
        const result = await adminRequest('PUT', '/api/admin/model-config', body);
        const config = await adminRequest('GET', '/api/admin/model-config');
        commit(() => {
          state.admin.modelConfig = config;
          state.admin.last = result;
          state.admin.notice = `模型配置已保存（${result.task?.status || '状态未知'}，验证状态 ${result.task?.verification || '未知'}）`;
        });
      });
    },
    async adminSaveQuotaAdapter(input = {}) {
      return runAdmin('adminSaveQuotaAdapter', async ({commit}) => {
        const body = {kind: 'remnawave'};
        if (typeof input.enabled === 'boolean') body.enabled = input.enabled;
        if (trimmed(input.base_url)) body.base_url = trimmed(input.base_url);
        if (typeof input.token === 'string' && input.token) body.token = input.token;
        const timeout = optionalNumber(input.timeout_ms);
        if (timeout !== undefined) body.timeout_ms = timeout;
        const result = await adminRequest('PUT', '/api/admin/quota-adapter', body);
        commit(() => {
          state.admin.quotaAdapter = result.adapter || null;
          state.admin.last = result;
          state.admin.notice = `配额适配已保存（${result.adapter?.configured ? '已配置' : '未配置完整'}，验证状态 ${result.adapter?.verification || '未知'}）`;
        });
      });
    },
    /** 分环境探测服务：地址由控制端校验（https、不带账号密码、STUN 只收 stun:）；这里只整理表单。 */
    async adminSaveProbeServices(input = {}) {
      return runAdmin('adminSaveProbeServices', async ({commit}) => {
        const body = {environment_ref: trimmed(input.environment_ref)};
        for (const key of ['echo_url', 'doh_url', 'probe_base_url', 'intel_url']) {
          if (trimmed(input[key])) body[key] = trimmed(input[key]);
        }
        const stun = String(input.stun_urls ?? '').split(',').map((item) => item.trim()).filter(Boolean);
        if (stun.length) body.stun_urls = stun;
        if (trimmed(input.client_kind)) body.client_kind = trimmed(input.client_kind);
        // 带上管理员看到的那一版：别人在这之后改过，服务端回 409，不静默覆盖。还没读过列表就先读一次。
        const seen = state.admin.probeServices ?? (await adminRequest('GET', '/api/admin/probe-services')).probe_services ?? [];
        body.expected_version = seen.find((item) => item.environment_ref === body.environment_ref)?.version ?? 0;
        let result;
        try {
          result = await adminRequest('PUT', '/api/admin/probe-services', body);
        } catch (error) {
          if (error?.code === 'PROBE_SERVICES_CONFLICT') {
            const latest = await adminRequest('GET', '/api/admin/probe-services').catch(() => null);
            if (latest) commit(() => { state.admin.probeServices = latest.probe_services || []; });
          }
          throw error;
        }
        const listed = await adminRequest('GET', '/api/admin/probe-services');
        commit(() => {
          state.admin.probeServices = listed.probe_services || [];
          state.admin.last = result;
          state.admin.notice = `探测服务已保存：${result.probe_services?.environment_ref}（版本 ${result.probe_services?.version}）`;
        });
      });
    },
    async adminRemoveProbeServices(environmentRef) {
      return runAdmin('adminRemoveProbeServices', async ({commit}) => {
        const result = await adminRequest('POST', '/api/admin/probe-services/remove', {environment_ref: trimmed(environmentRef)});
        const listed = await adminRequest('GET', '/api/admin/probe-services');
        commit(() => {
          state.admin.probeServices = listed.probe_services || [];
          state.admin.last = result;
          state.admin.notice = `已删除 ${result.removed} 的探测服务配置`;
        });
      });
    },
    async adminResources() {
      return runAdmin('adminResources', async ({commit}) => {
        const body = await adminRequest('GET', '/api/admin/resources');
        commit(() => {
          state.admin.resources = body.resources || [];
          state.admin.sources = body.sources || [];
        });
      });
    },
    async adminSaveResource(input = {}) {
      return runAdmin('adminSaveResource', async ({commit}) => {
        const body = {resource_id: trimmed(input.resource_id), role: trimmed(input.role), host: trimmed(input.host)};
        const port = optionalNumber(input.port);
        if (port !== undefined) body.port = port;
        for (const key of ['sharing', 'status', 'expires_at', 'credential_ref']) if (trimmed(input[key])) body[key] = trimmed(input[key]);
        const result = await adminRequest('PUT', '/api/admin/resources', body);
        const listed = await adminRequest('GET', '/api/admin/resources');
        commit(() => {
          state.admin.resources = listed.resources || [];
          state.admin.sources = listed.sources || [];
          state.admin.last = result;
          state.admin.notice = `资源 ${result.resource?.resource_id || ''} 已保存为第 ${result.resource?.version ?? '?'} 版`;
        });
      });
    },
    async adminSubscriptions() {
      return runAdmin('adminSubscriptions', async ({commit}) => {
        const body = await adminRequest('GET', '/api/admin/subscriptions');
        commit(() => { state.admin.sources = body.sources || []; });
      });
    },
    async adminSaveSubscription(input = {}) {
      return runAdmin('adminSaveSubscription', async ({commit}) => {
        const body = {source_id: trimmed(input.source_id)};
        if (trimmed(input.format)) body.format = trimmed(input.format);
        if (trimmed(input.status)) body.status = trimmed(input.status);
        if (trimmed(input.url)) body.url = trimmed(input.url);
        const result = await adminRequest('PUT', '/api/admin/subscriptions', body);
        const listed = await adminRequest('GET', '/api/admin/subscriptions');
        commit(() => {
          state.admin.sources = listed.sources || [];
          state.admin.last = result;
          state.admin.notice = `订阅源 ${result.source?.source_id || ''} 已保存`;
        });
      });
    },
    /** 刷新订阅：结果（含解析失败、格式不支持、拉取失败）如实显示；失败时抛错码。 */
    async adminRefreshSubscription(sourceId, bodyText) {
      return runAdmin('adminRefreshSubscription', async ({commit}) => {
        const request = {source_id: trimmed(sourceId)};
        if (typeof bodyText === 'string' && bodyText.trim()) request.body = bodyText;
        const result = await control('POST', '/api/admin/subscriptions/refresh', request);
        const listed = await adminRequest('GET', '/api/admin/subscriptions');
        commit(() => {
          state.admin.subscription = result.body;
          state.admin.sources = listed.sources || [];
        });
        if (result.status >= 400 || result.body?.ok !== true) {
          throw Object.assign(new Error(result.body?.reason || '订阅刷新没有成功'), {code: result.body?.code || `CONTROL_HTTP_${result.status}`, request_ref: result.body?.request_ref || null});
        }
        commit(() => { state.admin.notice = `订阅已刷新：${result.body.source?.proxy_count ?? 0} 个节点`; });
      });
    },
    async adminTemplates() {
      return runAdmin('adminTemplates', async ({commit}) => {
        const body = await adminRequest('GET', '/api/admin/templates');
        commit(() => { state.admin.templates = body.templates || []; });
      });
    },
    /** 模板在高级编辑区以 JSON 编辑；JSON 语法错误在本地说明，结构错误由服务端给出出错位置。 */
    async adminSaveTemplate(templateId, templateText, published = false) {
      return runAdmin('adminSaveTemplate', async ({commit}) => {
        let template;
        try {
          template = JSON.parse(String(templateText ?? ''));
        } catch (error) {
          throw Object.assign(new Error(`模板不是有效 JSON：${error.message}`), {code: 'TEMPLATE_JSON_INVALID'});
        }
        const result = await adminRequest('PUT', '/api/admin/templates', {template_id: trimmed(templateId), template, published: published === true});
        const listed = await adminRequest('GET', '/api/admin/templates');
        commit(() => {
          state.admin.templates = listed.templates || [];
          state.admin.last = result;
          state.admin.notice = `模板 ${result.template?.template_id || ''} 已保存为 ${result.template?.version || ''}`;
        });
      });
    },
    /** 为所选用户保存候选分配；资源只提交编号，属性以服务端资源表为准。 */
    async adminSaveAssignment(input = {}) {
      return runAdmin('adminSaveAssignment', async ({commit}) => {
        const userRef = adminTarget();
        const roles = {};
        for (const [role, key] of [['A', 'a'], ['B', 'b'], ['front', 'front']]) if (trimmed(input[key])) roles[role] = trimmed(input[key]);
        const body = {
          userRef,
          allowedModes: Array.isArray(input.allowed_modes) ? input.allowed_modes.filter(Boolean) : [],
          resources: [...new Set(Object.values(roles))],
          roles,
          validUntil: trimmed(input.valid_until),
        };
        if (trimmed(input.environment_ref)) body.environmentRef = trimmed(input.environment_ref);
        if (trimmed(input.account_class)) body.accountClass = trimmed(input.account_class);
        if (trimmed(input.template_id)) body.templateId = trimmed(input.template_id);
        const result = await adminRequest('POST', '/api/admin/assignments', body);
        await loadSelectedUser(commit, userRef);
        commit(() => {
          state.admin.last = result;
          state.admin.notice = `候选分配已保存（第 ${result.assignment?.assignment_version ?? '?'} 版，${result.ready ? '可发布' : '尚不可发布'}）`;
        });
      });
    },
    async adminPublish(confirmed = false) {
      return runAdmin('adminPublish', async ({commit}) => {
        const userRef = adminTarget();
        const body = {userRef};
        if (confirmed === true) body.confirmation = {confirmed: true};
        const result = await adminRequest('POST', '/api/admin/assignments/publish', body);
        await loadSelectedUser(commit, userRef);
        commit(() => {
          state.admin.last = result;
          state.admin.notice = `分配已发布（第 ${result.receipt?.assignment_version ?? '?'} 版）${result.sensitive ? '，含已确认的敏感变更' : ''}`;
        });
      });
    },
    async adminRevoke() {
      return runAdmin('adminRevoke', async ({commit}) => {
        const userRef = adminTarget();
        const result = await adminRequest('POST', '/api/admin/assignments/revoke', {userRef});
        await loadSelectedUser(commit, userRef);
        commit(() => {
          state.admin.last = result;
          state.admin.notice = '分配已撤销';
        });
      });
    },
    /** 个人接入凭据：只写。保存后只显示引用、版本与是否存在。 */
    async adminSaveCredential(input = {}) {
      return runAdmin('adminSaveCredential', async ({commit}) => {
        const userRef = adminTarget();
        const body = {user_ref: userRef, credential_ref: trimmed(input.credential_ref), username: String(input.username ?? '')};
        if (typeof input.password === 'string' && input.password) body.password = input.password;
        const result = await adminRequest('PUT', '/api/admin/credentials', body);
        await loadSelectedUser(commit, userRef);
        commit(() => {
          state.admin.last = result;
          state.admin.notice = `凭据 ${result.credential?.credential_ref || ''} 已保存（第 ${result.credential?.version ?? '?'} 版）`;
        });
      });
    },
    async adminRevokeCredential(credentialRef) {
      return runAdmin('adminRevokeCredential', async ({commit}) => {
        const userRef = adminTarget();
        const result = await adminRequest('POST', '/api/admin/credentials/revoke', {user_ref: userRef, credential_ref: trimmed(credentialRef)});
        await loadSelectedUser(commit, userRef);
        commit(() => {
          state.admin.last = result;
          state.admin.notice = `凭据 ${result.credential?.credential_ref || ''} 已撤销`;
        });
      });
    },
    /** 为所选用户建立配额权威身份；额度、单位、周期与到期时间都来自表单，页面不暗中补值。 */
    async adminAllocateQuota(input = {}) {
      return runAdmin('adminAllocateQuota', async ({commit}) => {
        const userRef = adminTarget();
        const body = {
          userRef,
          operation_id: compose.store.newId('ui-alloc'),
          limit_value: optionalNumber(input.limit_value),
          limit_unit: trimmed(input.limit_unit) || 'GB',
          period: trimmed(input.period) || 'MONTH',
        };
        if (trimmed(input.expire_at)) body.expireAt = trimmed(input.expire_at);
        const result = await adminRequest('POST', '/api/admin/quota/allocate', body);
        commit(() => {
          state.admin.last = result;
          state.admin.usage = {ok: true, snapshot: result.snapshot || null};
          state.admin.notice = result.replayed ? '额度身份请求已重放' : `额度身份已就绪（权威编号 ${result.binding?.provider_user_id ?? '?'}）`;
        });
      });
    },
    async adminChangeLimit(input = {}) {
      return runAdmin('adminChangeLimit', async ({commit}) => {
        const userRef = adminTarget();
        const result = await adminRequest('POST', '/api/admin/quota/limit', {
          userRef,
          operation_id: compose.store.newId('ui-limit'),
          limit_value: optionalNumber(input.limit_value),
          limit_unit: trimmed(input.limit_unit) || 'GB',
        });
        commit(() => {
          state.admin.last = result;
          state.admin.usage = {ok: true, snapshot: result.snapshot || null};
          state.admin.notice = result.effective ? '额度已生效（权威回读一致）' : '额度请求已提交，但权威回读与请求不一致';
        });
      });
    },
    async adminSuspend() {
      return runAdmin('adminSuspend', async ({commit}) => {
        const userRef = adminTarget();
        const result = await adminRequest('POST', '/api/admin/quota/suspend', {userRef, operation_id: compose.store.newId('ui-suspend')});
        commit(() => {
          state.admin.last = result;
          state.admin.usage = {ok: true, snapshot: result.snapshot || null};
          state.admin.notice = `已请求停用：权威状态 ${result.snapshot?.status || '未知'}，节点断连 ${result.node_effect?.verified_disconnect || '未知'}`;
        });
      });
    },
    async adminResume() {
      return runAdmin('adminResume', async ({commit}) => {
        const userRef = adminTarget();
        const result = await adminRequest('POST', '/api/admin/quota/resume', {userRef, operation_id: compose.store.newId('ui-resume')});
        commit(() => {
          state.admin.last = result;
          state.admin.usage = {ok: true, snapshot: result.snapshot || null};
          state.admin.notice = `已恢复：权威状态 ${result.snapshot?.status || '未知'}`;
        });
      });
    },
    async adminUsage() {
      return runAdmin('adminUsage', async ({commit}) => {
        const userRef = adminTarget();
        const result = await control('GET', `/api/admin/quota/usage?${adminQuery(userRef)}`);
        commit(() => { state.admin.usage = result.body; });
        if (result.status >= 400 || result.body?.ok !== true) {
          throw Object.assign(new Error(result.body?.reason || '用量读取没有成功，显示的是最后快照'), {code: result.body?.code || `CONTROL_HTTP_${result.status}`, request_ref: result.body?.request_ref || null});
        }
      });
    },
    async adminPool() {
      return runAdmin('adminPool', async ({commit}) => {
        const result = await control('GET', '/api/admin/quota/pool');
        commit(() => { state.admin.pool = result.body; });
        if (result.status >= 400 || result.body?.ok === false) {
          throw Object.assign(new Error(result.body?.reason || '资源池读取没有成功'), {code: result.body?.code || `CONTROL_HTTP_${result.status}`, request_ref: result.body?.request_ref || null});
        }
      });
    },
    async adminEvents() {
      return runAdmin('adminEvents', async ({commit}) => {
        const pathname = state.admin.selectedUserRef ? `/api/admin/events?${adminQuery(state.admin.selectedUserRef)}` : '/api/admin/events';
        const body = await adminRequest('GET', pathname);
        commit(() => { state.admin.events = body; });
      });
    },
    async adminServiceState() {
      return runAdmin('adminServiceState', async ({commit}) => {
        const body = await adminRequest('GET', '/api/admin/service-state');
        commit(() => { state.admin.serviceState = body; });
      });
    },
    async userQuota() {
      return run('traffic', async ({commit}) => {
        const loaded = await control('GET', '/api/network/quota');
        commit(() => { state.traffic.quota = loaded.body?.quota || loaded.body; });
        return snapshot();
      });
    },
    async aiCapabilities() {
      return run('traffic', async ({commit}) => {
        const loaded = await control('GET', '/api/ai/capabilities');
        commit(() => {
          state.ai.capabilities = loaded.status >= 400 ? null : loaded.body;
          state.ai.error = loaded.status >= 400 ? {code: loaded.body?.code || 'CONTROL_FAILED', message: loaded.body?.reason} : null;
        });
        return snapshot();
      });
    },
    async aiDailyAnalysis() {
      return run('traffic', async ({commit}) => {
        if (!ai) {
          commit(() => { state.ai.error = {code: 'AI_NOT_ATTACHED', message: 'AI 会话未接入，标准事实与历史仍可用'}; });
          return snapshot();
        }
        const reports = await loadAuditReports(compose.auditStore);
        const current = reports.at(-1);
        if (!current) throw Object.assign(new Error('没有可分析的日报产物'), {code: 'REPORT_MISSING'});
        const task = await ai.startDailyAnalysis({report: current.report});
        const notes = await loadAiNotes(compose.auditStore);
        commit(() => {
          state.ai.task = task;
          state.ai.error = task?.lastError || (task?.status === 'COMPLETED' ? null : {code: task?.status || 'AI_FAILED', message: 'AI 附注未完成，标准事实不受影响'});
          state.traffic.notes = notes.map((item) => ({path: item.path, ...item.note}));
        });
        return snapshot();
      });
    },
    /** 页面定时读取：只回当前状态，不触发任何采集或写入。 */
    monitorStatus() {
      return snapshot();
    },
    async monitorEnable() {
      return run('monitor', async () => {
        const result = await requireMonitor().enable();
        if (result.ok !== true) throw Object.assign(new Error('监测与保护没有启用'), {code: result.code || 'MONITOR_ENABLE_FAILED'});
        return snapshot();
      });
    },
    async monitorAcknowledge(alertId) {
      return run('monitor', async () => {
        const result = requireMonitor().acknowledge(alertId);
        if (result.ok !== true) throw Object.assign(new Error('没有这条提示'), {code: result.code});
        return snapshot();
      });
    },
    async logExportPreview() {
      return run('monitor', async ({commit}) => {
        const preview = await requireLogExport().preview();
        if (preview.ok !== true) throw Object.assign(new Error(preview.reason || '读不到本地日志清单'), {code: preview.code || 'LOG_SOURCES_UNAVAILABLE'});
        commit(() => { state.monitor.preview = preview; state.monitor.export = null; });
        return snapshot();
      });
    },
    async logExportCreate(include, confirmed) {
      return run('monitor', async ({commit}) => {
        const created = await requireLogExport().create({include: Array.isArray(include) ? include : null, confirmed: confirmed === true});
        commit(() => { state.monitor.export = created; });
        if (created.ok !== true) throw Object.assign(new Error(created.message || '诊断包未生成'), {code: created.code || 'LOG_EXPORT_FAILED'});
        return snapshot();
      });
    },
    async openLogFolder(target = 'logs', exportRef = null) {
      return run('monitor', async ({commit}) => {
        const opened = await requireLogExport().openFolder(target, exportRef);
        commit(() => { state.monitor.folder = opened; });
        if (opened.ok !== true) throw Object.assign(new Error(opened.reason || '没能打开目录'), {code: opened.code || 'LOG_FOLDER_OPEN_FAILED'});
        return snapshot();
      });
    },
    resetPreferences(storage) {
      for (const key of ['steward-theme', 'steward-lang']) storage?.removeItem?.(key);
      state.settings = {theme: 'default', lang: 'zh-CN'};
      return snapshot();
    },
  };

  persist();
  return actions;
}
