import {
  archiveLogs,
  evaluateDailyDue,
  findPriorValidReport,
  planArchive,
  readDeliveredReport,
  runAuditPipeline,
  selectWindow,
} from '../../core/audit/index.mjs';
import {createMonitorJournal, journalCoverage, journalPath, journalPathsFor, journalTraffic, mergeJournalEntries} from '../../core/audit/monitor.mjs';
import {localDateKey, localHour, localTimestampKey} from '../../core/audit/time.mjs';
import {CORE_LOG_REQUEST, SERVICE_LOG_ROOT, createServiceLogSource} from './serviceLogs.mjs';

/**
 * 监测与审计的运行时：页面装配后由它驱动「实时读取 → 分钟记录 → 到期归档 → 到期日报」。
 *
 * - 唤醒：约 1 秒一次的节拍。应用启动后第一拍、睡眠恢复后第一拍各补做一次到期任务；
 *   两拍之间隔太久记为监测停顿缺口，停得像睡眠时按既有生命周期做一次「唤醒」（回读、保护先行、恢复最后有效方案）。
 * - 实时：同一连接、同一行只分类一次；实时 WRONG_ROUTE 立即提示，并串行交给既有预授权保护，读取节拍不等保护。
 * - 归档与日报：沿用核心的 archiveLogs / runAuditPipeline，来源是产品网络服务的内核日志；
 *   日报的采集连续性、本机字节与归属都来自分钟记录，没观测到的时段如实列为缺口。
 * - 只在用户启用「监测与保护」后运行；所有写入都在应用自己的审计目录里。
 */
export const AUDIT_RUNTIME_DEFAULTS = Object.freeze({
  liveIntervalMs: 1000,
  gapThresholdMs: 10_000,
  wakeThresholdMs: 120_000,
  persistEveryMs: 60_000,
  outboxEveryMs: 30_000,
  quotaEveryMs: 30_000,
  dailyCheckEveryMs: 60_000,
  dailyRetryMs: 2 * 60 * 60 * 1000,
  protectionValidityMs: 12 * 60 * 60 * 1000,
});

const STATE = Object.freeze({monitor: 'state/monitor.json', scheduler: 'state/scheduler.json', alerts: 'state/alerts.json'});
const JOURNAL_ROOT = 'monitor';
const DAILY_SUCCESS = new Set(['DELIVERED', 'REPAIRED_MISSING_MATE', 'ALREADY_DELIVERED']);
const MAX_ALERTS = 200;
const EVIDENCE_LIMITS = Object.freeze([
  'Local byte totals come from per-minute core counter samples; window edges resolve to one minute.',
  'Per-application and A/B attribution come from connection deltas between reads; connections opened and closed between reads are listed as short-lived unattributed bytes.',
]);

export const MONITOR_SCOPE_TEXT = [
  '采集：本机产品网络内核的连接、上传/下载累计计数与运行日志（含进程名与访问目标），明细只留在本机。',
  '自动保护：当前受控连接出现错误出口时，按预授权立即阻断受保护程序的新连接并关闭错误连接，再通知你。',
  '上报：只向本应用后台发送事件类型、次数、首末时间与保护状态，不发送访问明细或日志原文。',
  '归档与日报：每两小时只读归档，洛杉矶时间 09:00 后首次可用时生成日报；不改网、不删文件、不发测试流量。',
].join('\n');

function errorCode(error, fallback) {
  const text = String(error?.message ?? error ?? '');
  return error?.code || /^([A-Z][A-Z0-9_]+)/.exec(text)?.[1] || fallback;
}

export function createAuditRuntime({
  invoke,
  confirm = null,
  auditStore,
  network = null,
  mapping,
  environmentRef,
  environments = [],
  userRef = null,
  readQuota = null,
  clock = () => new Date().toISOString(),
  timers = {set: (fn, ms) => setTimeout(fn, ms), clear: (id) => clearTimeout(id)},
  options = {},
  appLog = null,
  sources = null,
  notify = null,
} = {}) {
  if (!auditStore) throw new Error('AUDIT_STORE_REQUIRED: the audit runtime needs the application audit store');
  const settings = {...AUDIT_RUNTIME_DEFAULTS, ...options};
  const logSource = sources || createServiceLogSource({invoke});
  let monitor = {enabled: false};
  let scheduler = {};
  let alerts = [];
  let alertsDirty = false;
  let journal = null;
  let cursor = null;
  let timer = null;
  let stopped = true;
  let ticking = false;
  let lastPersistAt = 0;
  let lastOutboxAt = 0;
  let lastQuotaAt = 0;
  let lastDailyCheckAt = 0;
  let lastTickAt = null;
  let rateBase = null;
  let live = {status: 'NOT_STARTED'};
  let quota = null;
  let lastRun = null;
  let lastWake = null;
  let storage = {status: 'OK'};
  // 没写成功的路径：只有同一路径之后写成功才算恢复，别的文件写成功不算。
  const unsaved = new Map();
  let dueTask = null;
  let protectionChain = Promise.resolve();
  let pendingProtections = 0;
  const pendingNotices = new Set();
  const journalCache = new Map();

  async function log(level, event, fields = {}) {
    try { await appLog?.(level, event, fields); } catch { /* 应用日志写不进时不影响监测 */ }
  }

  async function readJson(path) {
    try {
      if (!(await auditStore.exists(path))) return null;
      return JSON.parse(await auditStore.readText(path));
    } catch {
      return null;
    }
  }

  async function writeJson(path, value, {overwrite = true} = {}) {
    try {
      await auditStore.writeText(path, JSON.stringify(value, null, 2), {overwrite});
      if (unsaved.delete(path)) {
        const remaining = [...unsaved].at(-1);
        storage = remaining ? {status: 'WRITE_FAILED', path: remaining[0], ...remaining[1]} : {status: 'OK', recovered_at: clock()};
      }
      return true;
    } catch (error) {
      const code = errorCode(error, 'AUDIT_STORAGE_WRITE_FAILED');
      unsaved.delete(path);
      unsaved.set(path, {code, at: clock()});
      storage = {status: 'WRITE_FAILED', code, path, at: clock()};
      raiseAlert({key: 'audit-storage', level: 'important', kind: 'AUDIT_STORAGE_WRITE_FAILED', title: '监测记录没能保存', detail: `${code}：${path}`, at: clock()});
      await log('error', 'audit.storage_write_failed', {code, path});
      return false;
    }
  }

  function raiseAlert({key, level, kind, title, detail = null, at, extra = {}}) {
    let alert = alerts.find((item) => item.key === key && !item.acknowledged);
    if (alert) {
      alert.count += 1;
      alert.last_at = at;
      Object.assign(alert, extra);
    } else {
      alert = {id: `alert-${Date.parse(at)}-${alerts.length}`, key, level, kind, title, detail, first_at: at, last_at: at, notified_at: at, count: 1, acknowledged: false, ...extra};
      alerts = [alert, ...alerts].slice(0, MAX_ALERTS);
    }
    alertsDirty = true;
    return alert;
  }

  /**
   * 危急提示新建时请宿主发一次系统通知（同一提示重复计数不再弹）。只给固定事件与提示编号，标题正文由宿主定。
   * 结果单记在 system_notice：已弹出、窗口可见未另弹、失败（带错误码）。不等它、不阻塞保护，也不改 notified_at 与统计。
   */
  function systemNotice(alert, event) {
    if (typeof notify !== 'function' || alert.count !== 1) return;
    alert.system_notice = {status: 'REQUESTED', code: null, at: clock()};
    const task = Promise.resolve()
      .then(() => notify(event, alert.id))
      .then(async (result) => {
        const failed = result?.ok !== true;
        alert.system_notice = {status: failed ? 'FAILED' : result.status || 'SHOWN', code: failed ? result?.code || 'NOTIFY_FAILED' : null, at: clock()};
        if (failed) await log('error', 'monitor.notify_failed', {event, code: alert.system_notice.code});
      })
      .catch(async (error) => {
        alert.system_notice = {status: 'FAILED', code: errorCode(error, 'NOTIFY_FAILED'), at: clock()};
        await log('error', 'monitor.notify_failed', {event, code: alert.system_notice.code});
      })
      .finally(() => {
        alertsDirty = true;
        pendingNotices.delete(task);
      });
    pendingNotices.add(task);
  }

  function environmentCoverageInput() {
    const declared = environments.length ? environments : [{environment_ref: environmentRef, kind: 'host'}];
    return declared.map((item) => ({
      environment_ref: item.environment_ref,
      kind: item.kind || 'unknown',
      covered: item.environment_ref === environmentRef,
      reason: item.environment_ref === environmentRef ? null : 'MONITOR_OBSERVES_HOST_CORE_ONLY',
    }));
  }

  async function loadJournalFile(path) {
    if (journalCache.has(path)) return journalCache.get(path);
    const stored = await readJson(path);
    const entries = Array.isArray(stored?.entries) ? stored.entries : [];
    journalCache.set(path, entries);
    return entries;
  }

  async function loadJournal(window) {
    const entries = [];
    for (const path of journalPathsFor(JOURNAL_ROOT, window.start, window.end)) entries.push(...(await loadJournalFile(path)));
    return mergeJournalEntries(entries, journal ? journal.peek() : []);
  }

  /**
   * 分钟记录落盘：已结束的分钟与当前分钟的快照写进各自当地小时的文件（覆盖写同一小时文件）。
   * 取出的分钟先并进该小时的缓存；写失败的小时文件留在缓存里不淘汰，之后每次落盘都连同缓存整份重写，直到写成功。
   * last_tick_at 是重启后「应用未运行」缺口的起点，所以只在分钟记录全部写成功后才推进。
   */
  async function persistJournal(now) {
    if (!journal) return;
    const tickAt = journal.lastTickAt();
    const {finished, current} = journal.take();
    const byPath = new Map([...unsaved.keys()].filter((path) => path.startsWith(`${JOURNAL_ROOT}/`)).map((path) => [path, []]));
    for (const entry of [...finished, ...(current ? [current] : [])]) {
      const path = journalPath(JOURNAL_ROOT, entry.minute);
      if (!byPath.has(path)) byPath.set(path, []);
      byPath.get(path).push(entry);
    }
    let saved = true;
    for (const [path, incoming] of byPath) {
      const merged = mergeJournalEntries(await loadJournalFile(path), incoming);
      journalCache.set(path, merged);
      if (!(await writeJson(path, {schemaVersion: 1, timezone: 'America/Los_Angeles', entries: merged}))) saved = false;
    }
    if (journalCache.size > 48) {
      const evictable = [...journalCache.keys()].filter((key) => !unsaved.has(key));
      for (const key of evictable.slice(0, journalCache.size - 48)) journalCache.delete(key);
    }
    if (saved) scheduler.last_tick_at = tickAt || scheduler.last_tick_at || null;
    await writeJson(STATE.scheduler, scheduler);
    if (alertsDirty) {
      alertsDirty = false;
      await writeJson(STATE.alerts, {alerts});
    }
    lastPersistAt = Date.parse(now);
  }

  async function quotaSnapshot(now) {
    if (typeof readQuota !== 'function') return {source: 'server', status: 'UNKNOWN', reason: 'CONTROL_NOT_ATTACHED'};
    try {
      const loaded = await readQuota();
      if (!loaded) return {source: 'server', status: 'UNKNOWN', reason: 'QUOTA_UNAVAILABLE', attemptedAt: now};
      quota = {...loaded, readAt: now};
      return quota;
    } catch (error) {
      return {source: 'server', status: 'UNKNOWN', reason: errorCode(error, 'QUOTA_READ_FAILED'), attemptedAt: now};
    }
  }

  function protectionSnapshot(window) {
    const start = Date.parse(window.start);
    const end = Date.parse(window.end);
    const incidents = (network?.listIncidents?.() || []).filter((item) => Date.parse(item.last_at) >= start && Date.parse(item.first_at) < end);
    const notified = new Map(alerts.filter((item) => item.event_ref).map((item) => [item.event_ref, item.notified_at]));
    return {
      status: live.protection?.effective === true ? 'EFFECTIVE' : live.protection?.requested ? 'NOT_EFFECTIVE' : live.protection ? 'NOT_REQUESTED' : 'UNKNOWN',
      events: incidents.map((item) => ({
        eventId: item.event_ref,
        action: 'PREAUTHORIZED_PROTECTION',
        result: item.protection?.status || 'UNKNOWN',
        firstObservedAt: item.first_at,
        lastObservedAt: item.last_at,
        count: item.count,
        effectiveAt: item.protection?.status === 'CONFIRMED' ? item.last_at : null,
        notifiedAt: notified.get(item.event_ref) || null,
        deliveryStatus: item.delivery?.status || 'NOT_ATTEMPTED',
        deliveredAt: item.delivery?.delivered_at || null,
        process: item.process,
        destination: item.destination,
      })),
    };
  }

  function summarizeArchive(archive) {
    return {
      status: archive.status,
      newCount: archive.newCount,
      duplicateCount: archive.duplicateCount,
      verifiedCount: archive.verifiedCount,
      derivedCount: archive.derivedCount || 0,
      wrongRouteCount: archive.wrongRouteCount,
      notification: archive.notification,
      issues: (archive.issues || []).map((item) => ({code: item.code, sourcePath: item.sourcePath || null})),
      restrictedExceptions: (archive.restrictedExceptions || []).map((item) => ({sourcePath: item.sourcePath, reason: item.reason, derivedStatus: item.derivedStatus || null})),
    };
  }

  /** 归档正常且没有错误出口就静默；有错误出口、不可读或轮转缺口就提示。其他模块的告警不受这里影响。 */
  function notifyArchive(archive, at) {
    if (archive.wrongRouteCount > 0) {
      raiseAlert({key: 'archive-wrong-route', level: 'critical', kind: 'ARCHIVE_WRONG_ROUTE', title: '新归档的日志里有错误出口', detail: `本次新证据中 ${archive.wrongRouteCount} 条 WRONG_ROUTE；只读回放不会自行改网`, at});
    }
    if ((archive.issues || []).length || (archive.restrictedExceptions || []).length) {
      const codes = [...new Set([...(archive.issues || []).map((item) => item.code), ...(archive.restrictedExceptions || []).map(() => 'SECRET_MATERIAL')])];
      raiseAlert({key: `archive-issue:${codes.join(',')}`, level: 'important', kind: 'ARCHIVE_ATTENTION', title: '归档不完整', detail: codes.join('、'), at});
    }
  }

  async function dailyDue(now) {
    const date = localDateKey(now);
    if (localHour(now) < 9) return {due: false, reason: 'BEFORE_0900', date};
    if (scheduler.delivered_date === date) return {due: false, reason: 'ALREADY_DELIVERED', date};
    const attempt = scheduler.last_daily_attempt;
    if (attempt?.date === date && !DAILY_SUCCESS.has(attempt.status) && Date.parse(now) - Date.parse(attempt.at) < settings.dailyRetryMs) {
      return {due: false, reason: 'RETRY_AFTER_FAILURE', date};
    }
    const delivered = await readDeliveredReport(auditStore, {reportRoot: 'reports', date});
    const due = evaluateDailyDue(now, [{date, valid: delivered.valid, hasJson: delivered.hasJson, hasMarkdown: delivered.hasMarkdown}]);
    if (!due.due) scheduler.delivered_date = date;
    return due;
  }

  /** 到期才跑：到期归档、到期日报各自判断；日报到期时先归档再按窗口回放（FD-04 §7.2 第 6 步）。 */
  async function runDue(now, {force = false} = {}) {
    const archivePlan = force ? {due: true, reason: 'MANUAL'} : planArchive(now, scheduler.last_archive_at);
    let daily = {due: false, reason: 'NOT_CHECKED', date: localDateKey(now)};
    if (force || archivePlan.due || !lastDailyCheckAt || Date.parse(now) - lastDailyCheckAt >= settings.dailyCheckEveryMs) {
      lastDailyCheckAt = Date.parse(now);
      daily = await dailyDue(now);
    }
    if (!archivePlan.due && !daily.due) return null;
    const record = {kind: daily.due ? 'ARCHIVE_AND_DAILY' : 'ARCHIVE', planned: {archive: archivePlan, daily}, started_at: now};
    const request = {...CORE_LOG_REQUEST, now, timezone: 'America/Los_Angeles', archiveRoot: 'archive', reportRoot: 'reports', mapping};
    try {
      if (daily.due) {
        const prior = await findPriorValidReport(auditStore, {reportRoot: 'reports', beforeDate: daily.date});
        const window = selectWindow(now, prior);
        const entries = await loadJournal(window);
        const coverage = journalCoverage(entries, window, {gapThresholdMs: settings.gapThresholdMs});
        const traffic = journalTraffic(entries, window, {gapThresholdMs: settings.gapThresholdMs});
        const result = await runAuditPipeline({
          ...request,
          window,
          priorValidReport: prior,
          trafficState: {},
          trafficSamples: traffic.samples,
          trafficDetail: traffic.detail,
          quota: await quotaSnapshot(now),
          protection: protectionSnapshot(window),
          collectionEvidence: {
            environmentRef,
            sourceRefs: [`${SERVICE_LOG_ROOT}/core.log`],
            coverageStart: coverage.coverageStart,
            coverageEnd: coverage.coverageEnd,
            continuous: coverage.continuous,
            gaps: coverage.gaps,
            environments: environmentCoverageInput(),
            status: coverage.continuous ? 'MONITOR_JOURNAL_CONTINUOUS' : 'MONITOR_JOURNAL_GAPS',
          },
          evidenceLimits: [...EVIDENCE_LIMITS],
        }, auditStore, {sources: logSource});
        record.archive = summarizeArchive(result.evidence.archive);
        record.daily = {
          status: result.delivery.status,
          reportId: result.report.reportId,
          reportDate: result.report.reportDate,
          routeResult: result.report.routeResult,
          coverageStatus: result.report.coverageStatus,
          window: {start: result.report.windowStart, end: result.report.windowEnd},
          paths: result.delivery.paths,
        };
        scheduler.last_daily_attempt = {date: daily.date, at: now, status: result.delivery.status};
        if (DAILY_SUCCESS.has(result.delivery.status)) scheduler.delivered_date = daily.date;
        else raiseAlert({key: `daily-failed:${daily.date}`, level: 'important', kind: 'DAILY_DELIVERY_FAILED', title: '今天的日报没能交付', detail: result.delivery.status, at: now});
        notifyArchive(result.evidence.archive, now);
      } else {
        const archive = await archiveLogs(request, auditStore, {sources: logSource});
        record.archive = summarizeArchive(archive);
        notifyArchive(archive, now);
      }
      record.status = 'COMPLETED';
    } catch (error) {
      record.status = 'FAILED';
      record.error = {code: errorCode(error, 'AUDIT_RUN_FAILED'), message: String(error?.message || error).slice(0, 300)};
      if (daily.due) scheduler.last_daily_attempt = {date: daily.date, at: now, status: 'RUN_FAILED'};
      raiseAlert({key: 'audit-run-failed', level: 'important', kind: 'AUDIT_RUN_FAILED', title: '归档或日报没能完成', detail: record.error.code, at: now});
      await log('error', 'audit.run_failed', {kind: record.kind, code: record.error.code});
    }
    // 计划与实际分开记：无论成败都留一份运行记录；下一次按实际运行时刻重新计时，不在失败后每拍重试。
    scheduler.last_archive_at = now;
    scheduler.last_archive_status = record.archive?.status || record.status;
    record.finished_at = clock();
    await writeJson(`runs/${localDateKey(now)}/${localTimestampKey(now)}-${record.kind.toLowerCase()}.json`, record, {overwrite: false});
    await writeJson(STATE.scheduler, scheduler);
    if (alertsDirty) {
      alertsDirty = false;
      await writeJson(STATE.alerts, {alerts});
    }
    lastRun = record;
    return record;
  }

  function queueProtection(event, at) {
    const key = `wrong-route:${event.process || ''}:${event.destination || ''}`;
    const alert = raiseAlert({
      key,
      level: 'critical',
      kind: 'WRONG_ROUTE',
      title: 'Claude 相关连接走了错误出口',
      detail: `${event.process || '未知进程'} → ${event.destination || '未知目标'}，路线 ${event.route || '未知'}`,
      at,
      extra: {protection: 'REQUESTING'},
    });
    systemNotice(alert, 'WRONG_ROUTE');
    pendingProtections += 1;
    protectionChain = protectionChain
      .then(() => network.handleProtection({user_ref: userRef, environment_ref: environmentRef, mapping}, {...event, environment_ref: environmentRef}))
      .then((report) => {
        Object.assign(alert, {event_ref: report?.incident?.event_ref || null, protection: report?.protection?.status || 'UNKNOWN', delivery: report?.outbox?.status || null});
        if (report?.protection?.status !== 'CONFIRMED') {
          const unconfirmed = raiseAlert({key: `${key}:unconfirmed`, level: 'critical', kind: 'PROTECTION_NOT_CONFIRMED', title: '阻断没有确认生效', detail: report?.protection?.status || report?.reason || 'UNKNOWN', at: clock()});
          systemNotice(unconfirmed, 'PROTECTION_NOT_CONFIRMED');
        }
      })
      .catch(async (error) => {
        const code = errorCode(error, 'PROTECTION_FAILED');
        Object.assign(alert, {protection: 'FAILED', protection_code: code});
        const failed = raiseAlert({key: `${key}:failed`, level: 'critical', kind: 'PROTECTION_FAILED', title: '阻断失败', detail: code, at: clock()});
        systemNotice(failed, 'PROTECTION_FAILED');
        await log('error', 'monitor.protection_failed', {code});
      })
      .finally(() => {
        pendingProtections -= 1;
        alertsDirty = true;
      });
  }

  async function wake(at, pausedFrom) {
    lastWake = {detected_at: at, paused_from: pausedFrom, status: 'RUNNING'};
    await log('info', 'monitor.wake_detected', {paused_from: pausedFrom});
    if (!network?.executeLifecycle || !live.config?.plan_version) {
      lastWake.status = 'NO_MANAGED_PLAN';
      return;
    }
    try {
      const result = await network.executeLifecycle({user_ref: userRef, environment_ref: environmentRef}, {type: 'wake'});
      lastWake = {...lastWake, status: 'DONE', executed: result?.executed || []};
    } catch (error) {
      lastWake = {...lastWake, status: 'FAILED', code: errorCode(error, 'WAKE_LIFECYCLE_FAILED')};
      await log('error', 'monitor.wake_failed', {code: lastWake.code});
    }
  }

  async function liveTick(now) {
    const nowMillis = Date.parse(now);
    const pausedFrom = lastTickAt;
    if (pausedFrom && nowMillis - Date.parse(pausedFrom) > settings.wakeThresholdMs) wake(now, pausedFrom);
    lastTickAt = now;
    if (!network?.observeLive) {
      journal.tick(now, {ok: false, code: 'NETWORK_NOT_ATTACHED'});
      live = {status: 'NETWORK_NOT_ATTACHED', at: now};
      return;
    }
    let result;
    try {
      result = await network.observeLive({user_ref: userRef, environment_ref: environmentRef, mapping}, {cursor, protect: false});
    } catch (error) {
      const code = errorCode(error, 'LIVE_READ_FAILED');
      journal.tick(now, {ok: false, code});
      live = {...live, status: 'READ_FAILED', code, at: now};
      rateBase = null;
      return;
    }
    cursor = result.cursor || cursor;
    const reading = result.reading || {reachable: result.reason !== 'CORE_UNAVAILABLE', core_running: result.reason !== 'CORE_UNAVAILABLE', core_instance: null};
    const classifications = {};
    for (const event of result.events || []) classifications[event.classification] = (classifications[event.classification] || 0) + 1;
    journal.tick(now, {
      ok: true,
      reachable: reading.reachable,
      core_running: reading.core_running,
      core_instance: reading.core_instance,
      code: reading.service_code,
      snapshot: result.snapshot,
      classifications,
    });
    const observing = reading.reachable && reading.core_running;
    const up = result.snapshot?.uploadTotal;
    const down = result.snapshot?.downloadTotal;
    let rate = null;
    if (observing && Number.isFinite(up) && Number.isFinite(down)) {
      if (rateBase && rateBase.instance === reading.core_instance && up >= rateBase.up && down >= rateBase.down && nowMillis > rateBase.at) {
        const seconds = (nowMillis - rateBase.at) / 1000;
        rate = {uploadBytesPerSecond: Math.round((up - rateBase.up) / seconds), downloadBytesPerSecond: Math.round((down - rateBase.down) / seconds)};
      }
      rateBase = {instance: reading.core_instance, up, down, at: nowMillis};
    } else {
      rateBase = null;
    }
    live = {
      status: !reading.reachable ? 'SERVICE_UNREACHABLE' : !reading.core_running ? 'CORE_NOT_RUNNING' : 'OBSERVING',
      code: observing ? null : reading.service_code || null,
      at: now,
      activeConnections: Array.isArray(result.snapshot?.connections) ? result.snapshot.connections.length : null,
      uploadTotal: Number.isFinite(up) ? up : null,
      downloadTotal: Number.isFinite(down) ? down : null,
      rate,
      config: reading.config || null,
      protection: reading.protection || null,
      lastClassifications: classifications,
    };
    // 连接快照与日志行常是同一次连接的两种观测：同一拍里同一进程与目标只排一次保护。
    const wrong = new Map();
    for (const event of result.events || []) {
      if (event.live && event.classification === 'WRONG_ROUTE') wrong.set(`${event.process || ''}|${event.destination || ''}`, event);
    }
    for (const event of wrong.values()) queueProtection(event, now);
  }

  async function periodic(now) {
    const nowMillis = Date.parse(now);
    if (nowMillis - lastPersistAt >= settings.persistEveryMs) await persistJournal(now);
    if (network?.flushEvents && nowMillis - lastOutboxAt >= settings.outboxEveryMs) {
      lastOutboxAt = nowMillis;
      try {
        const flushed = await network.flushEvents();
        if (flushed?.delivered) alertsDirty = true;
      } catch (error) {
        await log('warning', 'monitor.outbox_flush_failed', {code: errorCode(error, 'OUTBOX_FLUSH_FAILED')});
      }
    }
    if (nowMillis - lastQuotaAt >= settings.quotaEveryMs) {
      lastQuotaAt = nowMillis;
      await quotaSnapshot(now);
    }
  }

  async function tick() {
    if (ticking || stopped) return;
    ticking = true;
    const now = clock();
    try {
      if (monitor.enabled) {
        await liveTick(now);
        await periodic(now);
        if (!dueTask) {
          dueTask = runDue(now).catch(async (error) => {
            await log('error', 'audit.due_failed', {code: errorCode(error, 'AUDIT_DUE_FAILED')});
          }).finally(() => { dueTask = null; });
        }
      }
    } catch (error) {
      live = {...live, error: {code: errorCode(error, 'MONITOR_TICK_FAILED')}};
      await log('error', 'monitor.tick_failed', {code: live.error.code});
    } finally {
      ticking = false;
      schedule(settings.liveIntervalMs);
    }
  }

  function schedule(delay) {
    if (stopped) return;
    if (timer) timers.clear(timer);
    timer = timers.set(() => {
      timer = null;
      tick();
    }, delay);
  }

  function status() {
    return {
      enabled: monitor.enabled === true,
      enabled_at: monitor.enabled_at || null,
      protection_authorization_expires_at: monitor.protection_authorization_expires_at || null,
      protection_authorization_expired: Boolean(monitor.protection_authorization_expires_at && Date.parse(monitor.protection_authorization_expires_at) <= Date.parse(clock())),
      scope_text: MONITOR_SCOPE_TEXT,
      live: structuredClone(live),
      quota: quota ? structuredClone(quota) : null,
      scheduler: {
        last_archive_at: scheduler.last_archive_at || null,
        last_archive_status: scheduler.last_archive_status || null,
        next_archive_due_at: scheduler.last_archive_at ? new Date(Date.parse(scheduler.last_archive_at) + 2 * 60 * 60 * 1000).toISOString() : null,
        delivered_date: scheduler.delivered_date || null,
        last_daily_attempt: scheduler.last_daily_attempt || null,
      },
      last_run: lastRun ? structuredClone(lastRun) : null,
      last_wake: lastWake ? structuredClone(lastWake) : null,
      storage: {...storage},
      alerts: structuredClone(alerts.slice(0, 50)),
      pending_protections: pendingProtections,
    };
  }

  return {
    async start() {
      monitor = (await readJson(STATE.monitor)) || {enabled: false};
      scheduler = (await readJson(STATE.scheduler)) || {};
      alerts = (await readJson(STATE.alerts))?.alerts || [];
      stopped = false;
      if (monitor.enabled) journal = createMonitorJournal({gapThresholdMs: settings.gapThresholdMs, resumeFrom: scheduler.last_tick_at || null});
      schedule(0);
      return status();
    },
    async stop() {
      stopped = true;
      if (timer) timers.clear(timer);
      timer = null;
      await dueTask;
      await protectionChain;
      if (monitor.enabled) await persistJournal(clock());
      return status();
    },
    /** 启用：先说明采集、阻断与上报范围，并经宿主取得预授权保护（弹本地确认），再开始采集。 */
    async enable() {
      if (typeof confirm !== 'function') return {ok: false, code: 'CONFIRMATION_REQUIRED', status: status()};
      let granted;
      try {
        granted = await confirm({
          scope: 'preauthorized_protection',
          environment_ref: environmentRef,
          reuse: true,
          validity_ms: settings.protectionValidityMs,
          summary: MONITOR_SCOPE_TEXT,
        });
      } catch (error) {
        granted = {code: errorCode(error, 'NATIVE_CONFIRMATION_DECLINED')};
      }
      if (!granted?.authorization_ref) return {ok: false, code: granted?.code || 'NATIVE_CONFIRMATION_DECLINED', status: status()};
      const now = clock();
      monitor = {enabled: true, enabled_at: monitor.enabled_at || now, scope_version: 1, protection_authorization_expires_at: granted.expires_at || null};
      if (!(await writeJson(STATE.monitor, monitor))) return {ok: false, code: storage.code, status: status()};
      if (!journal) journal = createMonitorJournal({gapThresholdMs: settings.gapThresholdMs, resumeFrom: null});
      await log('info', 'monitor.enabled', {environment_ref: environmentRef});
      schedule(0);
      return {ok: true, status: status()};
    },
    async disable() {
      if (journal) await persistJournal(clock());
      monitor = {...monitor, enabled: false, disabled_at: clock()};
      journal = null;
      cursor = null;
      lastTickAt = null;
      await writeJson(STATE.monitor, monitor);
      return {ok: true, status: status()};
    },
    tick,
    runDue,
    status,
    acknowledge(alertId) {
      const alert = alerts.find((item) => item.id === alertId);
      if (!alert) return {ok: false, code: 'ALERT_UNKNOWN', status: status()};
      alert.acknowledged = true;
      alert.acknowledged_at = clock();
      alertsDirty = true;
      return {ok: true, status: status()};
    },
    persist: () => persistJournal(clock()),
    /** 等后台任务（到期运行、串行保护、系统通知）结束；测试与退出前用。 */
    async idle() {
      await dueTask;
      await protectionChain;
      await Promise.all([...pendingNotices]);
    },
  };
}
