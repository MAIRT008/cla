import {accumulateTraffic, classifyLogLine, classifyRoute, parseRouteLogLine} from '../audit/index.mjs';
import {CLAUDE_DOMAINS, DEFAULT_MANAGED_BROWSER_PROCESSES, GROUP, PRODUCT_CLASSIFICATION_VERSION, PROOF_SIMULATION} from './constants.mjs';
import {handleProtectionEvent} from './protection.mjs';
import {nowIso} from './time.mjs';

/**
 * 受管配置里 Claude 走 CLAUDE-FIXED → PROXY-A → EXIT-A。Mihomo 日志只打印最外层组与叶子（`CLAUDE-FIXED[EXIT-A]`），
 * 连接 JSON 的 chains 是叶子在前、组在后；批准路线按「最外层组 + 叶子」核对，两种来源结论一致。
 */
export const PRODUCT_FIXED_A = Object.freeze({route: GROUP.CLAUDE, member: GROUP.EXIT_A});

/** 产品分类映射：批准路线固定；Claude 域名与受管浏览器进程取自分配下发的模板。 */
export function productAuditMapping(assignment = null) {
  const template = assignment?.template && typeof assignment.template === 'object' ? assignment.template : {};
  return {
    version: assignment?.classification_version || PRODUCT_CLASSIFICATION_VERSION,
    fixedA: {...PRODUCT_FIXED_A},
    domains: [...(template.claude_domains || CLAUDE_DOMAINS)],
    managedBrowserProcesses: [...(template.managed_browser_processes || DEFAULT_MANAGED_BROWSER_PROCESSES)],
  };
}

function mappingFrom(state, observation) {
  const base = state?.mapping || {};
  return {
    version: observation.classification_version || base.version || state?.expected?.classification_version || PRODUCT_CLASSIFICATION_VERSION,
    fixedA: observation.fixedA || base.fixedA || PRODUCT_FIXED_A,
    domains: observation.domains || base.domains,
    managedBrowserProcesses: observation.managedBrowserProcesses || base.managedBrowserProcesses || state?.managedBrowserProcesses,
  };
}

/** Mihomo 连接的 chains：叶子在前、最外层组在后；换成与日志一致的「组、叶子」两段。 */
function connectionToRecord(connection) {
  const metadata = connection.metadata || {};
  const chains = connection.chains || connection.providerChains || [];
  const route = chains.at(-1) || null;
  const member = chains.length > 1 ? chains[0] : null;
  return {
    process: metadata.process || metadata.processPath || null,
    destination: metadata.host || metadata.destinationIP || null,
    route,
    member,
    chain: [route, member].filter(Boolean),
    outcome: connection.outcome || (chains.length ? 'connected' : ''),
    connection_id: connection.id || null,
    upload: connection.upload,
    download: connection.download,
  };
}

export function observeNetworkEvidence(state, observation = {}, ports = {}) {
  const now = observation.observed_at || nowIso(ports.clock);
  const mapping = mappingFrom(state, observation);
  const events = [];
  const live = observation.live === true;
  let trafficState = observation.traffic_state || state?.traffic || null;

  if (observation.traffic) {
    const sample = {
      ...observation.traffic,
      sourceKind: observation.traffic.sourceKind || 'core',
      observedAt: now,
      coreInstanceId: observation.core_instance_id || state?.core_instance?.instance_id || state?.core_instance?.id,
    };
    const accumulated = accumulateTraffic(trafficState, sample);
    trafficState = accumulated.state;
  }

  const connections = observation.connections || [];
  for (const connection of connections) {
    const record = connectionToRecord(connection);
    const classified = classifyRoute(record, mapping);
    if (connection.upload != null || connection.download != null) {
      const sample = {
        sourceKind: 'connection',
        connectionId: record.connection_id,
        coreInstanceId: observation.core_instance_id || state?.core_instance?.instance_id,
        uploadBytes: connection.upload || 0,
        downloadBytes: connection.download || 0,
        observedAt: now,
        coveredByCore: observation.traffic?.sourceKind === 'core',
        baselineKnown: true,
      };
      const accumulated = accumulateTraffic(trafficState, sample);
      trafficState = accumulated.state;
    }
    events.push({
      live,
      source: live ? 'live' : observation.source || 'unknown',
      classification: classified.classification,
      reason: classified.reason,
      process: classified.process,
      destination: classified.destination,
      route: classified.route,
      member: classified.member,
      connection_id: record.connection_id,
      assignment_version: state?.expected?.assignment_version || observation.assignment_version || null,
      config_version: state?.expected?.plan_version || observation.config_version || null,
      classification_version: mapping.version,
      observed_at: now,
      proof_scope: PROOF_SIMULATION,
      unknown_filled_as_claude: false,
    });
  }

  if (observation.log_line) {
    const classified = ports.audit?.classifyLogLine
      ? ports.audit.classifyLogLine(observation.log_line, mapping)
      : classifyLogLine(observation.log_line, mapping);
    events.push({
      live,
      source: observation.source || 'log',
      classification: classified.classification,
      reason: classified.reason,
      process: classified.process,
      destination: classified.destination,
      route: classified.route,
      assignment_version: state?.expected?.assignment_version || null,
      config_version: state?.expected?.plan_version || null,
      classification_version: mapping.version,
      observed_at: now,
      proof_scope: PROOF_SIMULATION,
    });
  }

  return {
    state: {...state, traffic: trafficState, observed_at: now},
    events,
    traffic: trafficState,
    mapping,
  };
}

const LINE_MEMORY = 2000;

function lineText(line) {
  if (typeof line === 'string') return line;
  return line?.payload ? String(line.payload) : null;
}

/**
 * 实时读取连接、计数与日志尾巴。带游标时同一连接、同一行只分类一次：每秒重读服务给的日志尾巴，
 * 也不会把同一行当成新事件、把事件计数放大。`protect: false` 只分类不保护，由调用方异步保护，
 * 读取节拍不被确认框或服务调用卡住。
 */
export async function consumeLiveNetwork(state, ports = {}, {cursor = null, protect = true} = {}) {
  if (!ports.core?.readLive && !ports.core?.getConnections) {
    return {events: [], protections: [], reason: 'CORE_UNAVAILABLE', live: true, cursor};
  }
  let snapshot;
  let rawLines;
  let traffic = null;
  let reading = null;
  if (ports.core.readLive) {
    const live = await ports.core.readLive();
    reading = {
      reachable: live.reachable === true,
      core_running: live.core_running === true,
      core_instance: live.core_instance || null,
      service_status: live.service_status || null,
      service_code: live.service_code || null,
      config: live.config || null,
      protection: live.protection || null,
      missing: live.missing || [],
    };
    snapshot = live.snapshot || {};
    rawLines = live.lines || [];
    if (Number.isFinite(snapshot.uploadTotal) && Number.isFinite(snapshot.downloadTotal)) {
      traffic = {sourceKind: 'core', uploadBytes: snapshot.uploadTotal, downloadBytes: snapshot.downloadTotal, coreInstanceId: live.core_instance || null, baselineKnown: true};
    }
  } else {
    snapshot = await ports.core.getConnections();
    if (ports.core.getTraffic) {
      const sample = await ports.core.getTraffic();
      traffic = {
        sourceKind: 'core',
        uploadBytes: sample.upTotal ?? sample.uploadTotal ?? 0,
        downloadBytes: sample.downTotal ?? sample.downloadTotal ?? 0,
        coreInstanceId: ports.core.snapshot?.()?.instance_id,
        baselineKnown: true,
      };
    }
    const lines = ports.core.getLogs ? await ports.core.getLogs() : [];
    rawLines = lines.lines || lines || [];
  }
  const allConnections = snapshot.connections || snapshot.body?.connections || [];
  const seenConnections = cursor?.connections || new Set();
  const seenLines = cursor?.lines || new Set();
  const connections = allConnections.filter((connection) => !connection?.id || !seenConnections.has(connection.id));
  const freshLines = rawLines.map(lineText).filter((line) => line && !seenLines.has(line));
  const observed = observeNetworkEvidence(state, {
    live: true,
    source: 'live',
    connections,
    traffic,
    classification_version: state?.expected?.classification_version || state?.mapping?.version || PRODUCT_CLASSIFICATION_VERSION,
    assignment_version: state?.expected?.assignment_version,
    config_version: state?.expected?.plan_version,
  }, ports);
  for (const line of freshLines) {
    const parsed = parseRouteLogLine(line);
    const classified = classifyRoute(parsed, observed.mapping);
    observed.events.push({
      live: true,
      source: 'live',
      classification: classified.classification,
      reason: classified.reason,
      process: classified.process,
      destination: classified.destination,
      route: classified.route,
      member: classified.member,
      logged_at: parsed.timestamp,
      assignment_version: state?.expected?.assignment_version || null,
      config_version: state?.expected?.plan_version || null,
      classification_version: observed.mapping.version,
      observed_at: nowIso(ports.clock),
      proof_scope: PROOF_SIMULATION,
    });
  }
  const nextLines = new Set([...seenLines, ...freshLines]);
  while (nextLines.size > LINE_MEMORY) nextLines.delete(nextLines.values().next().value);
  const nextCursor = {connections: new Set(allConnections.map((connection) => connection?.id).filter(Boolean)), lines: nextLines};
  const protections = [];
  if (protect) {
    for (const event of observed.events) {
      if (event.classification === 'WRONG_ROUTE' || event.kind === 'PROTECTION_FAILED') {
        protections.push(await handleProtectionEvent(state, event, ports));
      }
    }
  }
  return {
    observed,
    events: observed.events,
    protections,
    live: true,
    cursor: nextCursor,
    reading,
    snapshot: {
      uploadTotal: traffic?.uploadBytes ?? null,
      downloadTotal: traffic?.downloadBytes ?? null,
      connections: allConnections,
      freshConnections: connections.length,
      freshLines: freshLines.length,
    },
  };
}
