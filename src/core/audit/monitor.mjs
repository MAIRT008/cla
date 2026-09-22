import {localDateKey, localHour} from './time.mjs';

/**
 * 实时监测的记录与覆盖计算（纯函数，不做 I/O）。
 *
 * - 每次读取（约 1 秒一次）在内存里汇总成「分钟记录」：节拍数、实际观测到的节拍、读不到的原因、
 *   该分钟最后一次内核累计计数、按连接增量归到路由/出口/进程的字节。
 * - 日报的采集连续性从分钟记录推出：相邻节拍间隔不超过阈值才算连着；应用没运行、睡眠、
 *   服务不可达、内核未运行的时段都是带起止与原因的缺口。
 * - 本机字节来自内核累计计数（accumulateTraffic 负责重启、重置与重复）；归属按连接增量，
 *   两次读取之间开了又关的短连接看不见，差额单列为「短连接未归属」，不猜。
 */
export const MONITOR_DEFAULTS = Object.freeze({gapThresholdMs: 10_000});

const EGRESS_OF_LEAF = Object.freeze({'EXIT-A': 'A', 'EXIT-B': 'B', DIRECT: 'DIRECT', REJECT: 'REJECT'});

function minuteOf(iso) {
  const millis = Date.parse(iso);
  return new Date(millis - (millis % 60_000)).toISOString();
}

/** 监测记录按 America/Los_Angeles 当地日期与小时分文件。 */
export function journalPath(root, iso) {
  return `${root}/${localDateKey(iso)}/${String(localHour(iso)).padStart(2, '0')}.json`;
}

/** 覆盖某个时间段需要读的监测文件（按小时逐个列出，去重）。 */
export function journalPathsFor(root, startIso, endIso) {
  const paths = new Set();
  const start = Date.parse(startIso) - (Date.parse(startIso) % 3_600_000) - 3_600_000;
  for (let at = start; at <= Date.parse(endIso); at += 3_600_000) paths.add(journalPath(root, new Date(at).toISOString()));
  return [...paths];
}

function bump(bucket, key, up, down) {
  const item = bucket[key] || (bucket[key] = {uploadBytes: 0, downloadBytes: 0});
  item.uploadBytes += up;
  item.downloadBytes += down;
}

function emptyEntry(minute, at) {
  return {
    minute,
    first_at: at,
    last_at: at,
    ticks: 0,
    observed: 0,
    unobserved: {},
    gaps: [],
    counters: null,
    attribution: {byRoute: {}, byEgress: {}, byProcess: {}, unattributedProcess: {uploadBytes: 0, downloadBytes: 0}, shortLivedUnattributed: {uploadBytes: 0, downloadBytes: 0}},
    connections: {maxActive: 0, fresh: 0},
    classifications: {},
  };
}

/**
 * 内存里的监测记录器：tick() 每次读取调用一次，take() 取走已经结束的分钟与当前分钟的快照交给调用方落盘。
 * resumeFrom 是上次落盘的最后一个节拍：应用重启后先记一段「应用未运行」缺口，再开始计。
 */
export function createMonitorJournal({gapThresholdMs = MONITOR_DEFAULTS.gapThresholdMs, resumeFrom = null} = {}) {
  let entry = null;
  let lastTickAt = null;
  let pendingGap = null;
  let unobservedSince = null;
  let unobservedReason = null;
  const finished = [];
  const lastConnections = new Map();
  let lastCounters = null;
  // 上一次读取是否实际观测到：断开（启动、停顿、读不到、内核换实例）之后的第一次读取只作基线。
  let continuous = false;

  function breakContinuity() {
    continuous = false;
    lastConnections.clear();
    lastCounters = null;
  }

  function roll(at) {
    const minute = minuteOf(at);
    if (entry && entry.minute === minute) return entry;
    if (entry) finished.push(entry);
    entry = emptyEntry(minute, at);
    return entry;
  }

  function closeUnobserved(at) {
    if (!unobservedSince) return;
    roll(at).gaps.push({from: unobservedSince, to: at, reason: unobservedReason});
    unobservedSince = null;
    unobservedReason = null;
  }

  /**
   * reading：{ok, reachable, core_running, core_instance, code, snapshot:{uploadTotal, downloadTotal, connections}, classifications}
   */
  function tick(at, reading = {}) {
    const atMillis = Date.parse(at);
    const current = roll(at);
    if (resumeFrom && lastTickAt === null) {
      if (atMillis - Date.parse(resumeFrom) > gapThresholdMs) current.gaps.push({from: resumeFrom, to: at, reason: 'APP_NOT_RUNNING'});
    } else if (lastTickAt !== null && atMillis - Date.parse(lastTickAt) > gapThresholdMs) {
      // 睡眠、卡顿或后台节流：两次读取之间没有观测，连续性在这里断开。
      current.gaps.push({from: lastTickAt, to: at, reason: 'MONITOR_PAUSED'});
      breakContinuity();
    }
    current.ticks += 1;
    current.last_at = at;
    lastTickAt = at;
    if (pendingGap) {
      current.gaps.push(pendingGap);
      pendingGap = null;
    }

    const reason = reading.ok === false
      ? reading.code || 'LIVE_READ_FAILED'
      : reading.reachable !== true
        ? reading.code || 'SERVICE_UNREACHABLE'
        : reading.core_running !== true ? 'CORE_NOT_RUNNING' : null;
    if (reason) {
      current.unobserved[reason] = (current.unobserved[reason] || 0) + 1;
      if (!unobservedSince) {
        unobservedSince = at;
        unobservedReason = reason;
      }
      breakContinuity();
      return {observed: false, reason};
    }
    closeUnobserved(at);
    current.observed += 1;

    const snapshot = reading.snapshot || {};
    const coreInstance = reading.core_instance || null;
    if (lastCounters && lastCounters.coreInstance !== coreInstance) breakContinuity();
    const baseline = !continuous;
    let totalDelta = null;
    if (Number.isFinite(snapshot.uploadTotal) && Number.isFinite(snapshot.downloadTotal)) {
      current.counters = {uploadTotal: snapshot.uploadTotal, downloadTotal: snapshot.downloadTotal, coreInstance, observedAt: at};
      if (lastCounters && snapshot.uploadTotal >= lastCounters.uploadTotal && snapshot.downloadTotal >= lastCounters.downloadTotal) {
        totalDelta = {up: snapshot.uploadTotal - lastCounters.uploadTotal, down: snapshot.downloadTotal - lastCounters.downloadTotal};
      }
      lastCounters = {uploadTotal: snapshot.uploadTotal, downloadTotal: snapshot.downloadTotal, coreInstance};
    }
    continuous = true;

    const connections = Array.isArray(snapshot.connections) ? snapshot.connections : [];
    current.connections.maxActive = Math.max(current.connections.maxActive, connections.length);
    let attributedUp = 0;
    let attributedDown = 0;
    const seen = new Set();
    for (const connection of connections) {
      if (!connection?.id) continue;
      seen.add(connection.id);
      const upload = Number(connection.upload) || 0;
      const download = Number(connection.download) || 0;
      const previous = lastConnections.get(connection.id);
      lastConnections.set(connection.id, {upload, download});
      if (!previous) {
        current.connections.fresh += 1;
        // 恢复观测后第一次看到的连接不知道字节何时产生，只作基线；连续观测中新出现的连接是两次读取之间开的，字节全部归属。
        if (baseline) continue;
      }
      const up = previous ? upload - previous.upload : upload;
      const down = previous ? download - previous.download : download;
      if (up < 0 || down < 0 || (!up && !down)) continue;
      const chains = Array.isArray(connection.chains) ? connection.chains : [];
      const route = chains.at(-1) || 'UNKNOWN';
      const leaf = chains[0] || 'UNKNOWN';
      bump(current.attribution.byRoute, route, up, down);
      bump(current.attribution.byEgress, EGRESS_OF_LEAF[leaf] || leaf, up, down);
      const process = connection.metadata?.process;
      if (process) bump(current.attribution.byProcess, String(process).split(/[\\/]/).at(-1).toLowerCase(), up, down);
      else {
        current.attribution.unattributedProcess.uploadBytes += up;
        current.attribution.unattributedProcess.downloadBytes += down;
      }
      attributedUp += up;
      attributedDown += down;
    }
    for (const id of [...lastConnections.keys()]) if (!seen.has(id)) lastConnections.delete(id);
    if (totalDelta) {
      current.attribution.shortLivedUnattributed.uploadBytes += Math.max(0, totalDelta.up - attributedUp);
      current.attribution.shortLivedUnattributed.downloadBytes += Math.max(0, totalDelta.down - attributedDown);
    }
    for (const [classification, count] of Object.entries(reading.classifications || {})) {
      current.classifications[classification] = (current.classifications[classification] || 0) + count;
    }
    return {observed: true};
  }

  /** 应用内已知的停顿（如暂停监测）直接记成缺口。 */
  function markGap(from, to, reason) {
    pendingGap = {from, to, reason};
  }

  /** 取走已结束的分钟；当前分钟以快照形式一并交出（还会继续累加，下次覆盖写）。未收口的不可观测段按当前时刻暂记。 */
  function take() {
    const done = finished.splice(0, finished.length);
    if (!entry) return {finished: done, current: null};
    const current = structuredClone(entry);
    if (unobservedSince) current.gaps.push({from: unobservedSince, to: entry.last_at, reason: unobservedReason, open: true});
    return {finished: done, current};
  }

  /** 只看不取：日报读窗口时要连同还没落盘的分钟一起算，但不能把它们从待落盘里拿走。 */
  function peek() {
    const entries = finished.map((item) => structuredClone(item));
    if (entry) {
      const current = structuredClone(entry);
      if (unobservedSince) current.gaps.push({from: unobservedSince, to: entry.last_at, reason: unobservedReason, open: true});
      entries.push(current);
    }
    return entries;
  }

  return {tick, take, peek, markGap, lastTickAt: () => lastTickAt};
}

/** 把同一分钟的多份快照合成一份：后写的覆盖先写的（同一进程内分钟快照只增不减）。 */
export function mergeJournalEntries(existing = [], incoming = []) {
  const byMinute = new Map(existing.map((item) => [item.minute, item]));
  for (const item of incoming) byMinute.set(item.minute, item);
  return [...byMinute.values()].sort((left, right) => left.minute.localeCompare(right.minute));
}

function overlaps(from, to, start, end) {
  return Date.parse(to) > start && Date.parse(from) < end;
}

/**
 * 窗口 [start, end) 的采集连续性：节拍区间按阈值拼接成已观测时段，窗口里没被覆盖的部分都是缺口，
 * 原因取重叠的已记录缺口（应用未运行、监测停顿、服务不可达、内核未运行），都没有就记 NOT_MONITORED。
 * 分钟记录只留首末节拍，分钟内的停顿只在缺口里：已记录的缺口一律从已观测时段里切掉，不能被首末节拍桥接。
 */
export function journalCoverage(entries, window, {gapThresholdMs = MONITOR_DEFAULTS.gapThresholdMs} = {}) {
  const start = Date.parse(window.start);
  const end = Date.parse(window.end);
  const relevant = entries
    .filter((item) => overlaps(item.first_at, new Date(Date.parse(item.last_at) + gapThresholdMs).toISOString(), start - gapThresholdMs, end))
    .sort((left, right) => left.first_at.localeCompare(right.first_at));
  // 缺口记在恢复观测的那一分钟里，那一分钟可能已在窗口之外（如恰好等于窗口终点）：按缺口本身的时段筛。
  const recorded = entries.flatMap((item) => item.gaps || []).filter((gap) => overlaps(gap.from, gap.to, start, end));
  const spans = [];
  for (const item of relevant) {
    if (!item.observed) continue;
    const from = Date.parse(item.first_at);
    const to = Date.parse(item.last_at);
    const last = spans.at(-1);
    if (last && from - last.to <= gapThresholdMs) last.to = Math.max(last.to, to);
    else spans.push({from, to});
  }
  const covered = [];
  for (const span of spans) {
    let pieces = [{from: span.from, to: span.to}];
    for (const gap of recorded) {
      const gapFrom = Date.parse(gap.from);
      const gapTo = Date.parse(gap.to);
      pieces = pieces.flatMap((piece) => {
        if (gapTo <= piece.from || gapFrom >= piece.to) return [piece];
        return [{from: piece.from, to: gapFrom}, {from: gapTo, to: piece.to}].filter((part) => part.to > part.from);
      });
    }
    covered.push(...pieces);
  }
  covered.sort((left, right) => left.from - right.from);
  // 是否算缺口按阈值判断（相邻节拍本来就有间隔）；报出来的起止用实际没有观测的区间，不缩进。
  const holes = [];
  let cursor = start;
  for (const piece of covered) {
    if (piece.to <= cursor) continue;
    if (piece.from - cursor > gapThresholdMs) holes.push({from: cursor, to: Math.min(piece.from, end)});
    cursor = Math.max(cursor, piece.to);
    if (cursor >= end) break;
  }
  if (end - cursor > gapThresholdMs) holes.push({from: cursor, to: end});
  const gaps = holes
    .filter((hole) => hole.to > hole.from)
    .map((hole) => {
      const reasons = [...new Set(recorded.filter((gap) => overlaps(gap.from, gap.to, hole.from, hole.to)).map((gap) => gap.reason))];
      return {code: 'COLLECTION_GAP', from: new Date(hole.from).toISOString(), to: new Date(hole.to).toISOString(), reason: reasons.length ? reasons.join('+') : 'NOT_MONITORED'};
    });
  const firstCovered = covered[0];
  const lastCovered = covered.at(-1);
  return {
    continuous: gaps.length === 0,
    coverageStart: firstCovered ? new Date(firstCovered.from - start <= gapThresholdMs ? start : Math.max(start, firstCovered.from)).toISOString() : null,
    coverageEnd: lastCovered ? new Date(end - lastCovered.to <= gapThresholdMs ? end : Math.min(end, lastCovered.to)).toISOString() : null,
    gaps,
    ticks: relevant.reduce((sum, item) => sum + (item.ticks || 0), 0),
    observedTicks: relevant.reduce((sum, item) => sum + (item.observed || 0), 0),
  };
}

function sumInto(target, source) {
  for (const [key, value] of Object.entries(source || {})) bump(target, key, value.uploadBytes || 0, value.downloadBytes || 0);
}

/**
 * 窗口内的计数样本与归属：样本交给 accumulateTraffic（本函数不自己累加累计值）；
 * 窗口起点前一分钟内的最后一个计数作为已知基线，窗口边缘按一分钟粒度。
 */
export function journalTraffic(entries, window, {gapThresholdMs = MONITOR_DEFAULTS.gapThresholdMs} = {}) {
  const start = Date.parse(window.start);
  const end = Date.parse(window.end);
  const withCounters = entries.filter((item) => item.counters).sort((left, right) => left.minute.localeCompare(right.minute));
  const before = withCounters.filter((item) => Date.parse(item.counters.observedAt) <= start).at(-1);
  const inside = withCounters.filter((item) => {
    const at = Date.parse(item.counters.observedAt);
    return at > start && at < end;
  });
  const baselineUsable = before && start - Date.parse(before.counters.observedAt) <= 60_000 + gapThresholdMs;
  const samples = [
    ...(baselineUsable ? [before] : []),
    ...inside,
  ].map((item, index) => ({
    // 计数来源只有产品内核一个；内核实例变了就是累计计数重置，由 accumulateTraffic 记 COUNTER_RESET。
    sourceKind: 'core',
    coreInstanceId: 'product-core',
    resetId: item.counters.coreInstance || 'unknown-core',
    uploadBytes: item.counters.uploadTotal,
    downloadBytes: item.counters.downloadTotal,
    observedAt: item.counters.observedAt,
    baselineKnown: index === 0 && baselineUsable ? true : undefined,
  }));
  const detail = {
    basis: 'CORE_COUNTERS_PER_MINUTE',
    byRoute: {},
    byEgress: {},
    byProcess: {},
    unattributedProcess: {uploadBytes: 0, downloadBytes: 0},
    shortLivedUnattributed: {uploadBytes: 0, downloadBytes: 0},
    attributionBasis: 'CONNECTION_DELTAS_BETWEEN_READS',
  };
  for (const item of entries) {
    const minute = Date.parse(item.minute);
    if (minute < start || minute >= end) continue;
    sumInto(detail.byRoute, item.attribution?.byRoute);
    sumInto(detail.byEgress, item.attribution?.byEgress);
    sumInto(detail.byProcess, item.attribution?.byProcess);
    for (const key of ['unattributedProcess', 'shortLivedUnattributed']) {
      detail[key].uploadBytes += item.attribution?.[key]?.uploadBytes || 0;
      detail[key].downloadBytes += item.attribution?.[key]?.downloadBytes || 0;
    }
  }
  return {samples, detail};
}
