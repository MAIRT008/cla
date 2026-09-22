import {AUTH_KIND, PROOF_SIMULATION, RECORD} from './constants.mjs';
import {fail} from './errors.mjs';
import {resolveApprovedProtection} from './protectedProcesses.mjs';
import {nowIso} from './time.mjs';

/** 控制端只收字母、数字与 . _ : -，最长 128：进程名或目标里的其他字符换成下划线，同一事件仍得到同一引用。 */
function incidentId(event) {
  const raw = event.event_ref || `incident:${event.environment_ref || 'default'}:${event.classification}:${event.process || ''}:${event.destination || ''}`;
  return raw.replace(/[^A-Za-z0-9._:-]/g, '_').slice(0, 128);
}

/** 待报记录另起 id：工作区记录库以 id 为主键，与事件记录同 id 会把事件记录顶掉。 */
function outboxId(eventRef) {
  return `outbox:${eventRef}`;
}

function accepted(delivery) {
  return delivery?.accepted === true || delivery?.delivered === true;
}

/** 上报没被后台确认的事件留在本地待报；成功后记下确认时刻，事件记录与日报据此显示上报结果。 */
function recordDelivery(ports, eventRef, deliveryEvent, delivery, now, previous = null) {
  const attempts = (previous?.attempts || 0) + 1;
  const done = accepted(delivery);
  const outbox = {
    event_ref: eventRef,
    event: deliveryEvent,
    status: done ? 'DELIVERED' : 'PENDING',
    attempts,
    first_attempt_at: previous?.first_attempt_at || now,
    last_attempt_at: now,
    delivered_at: done ? now : null,
    last_code: done ? null : delivery?.code || (delivery?.control_stuck ? 'CONTROL_NO_ANSWER' : delivery?.status || 'NOT_ACCEPTED'),
  };
  ports.store?.saveRecord?.(RECORD.EVENT, outboxId(eventRef), outbox);
  const incident = ports.store?.getRecord?.(eventRef, RECORD.INCIDENT);
  if (incident) {
    ports.store?.saveRecord?.(RECORD.INCIDENT, eventRef, {
      ...incident,
      delivery: {status: outbox.status, attempts, delivered_at: outbox.delivered_at, last_attempt_at: now, last_code: outbox.last_code},
    });
  }
  return outbox;
}

/**
 * 待报补报：按同一 event_ref 重发（控制端按引用去重合并，不会变成多起事故）。发送尝试与后台确认分开记。
 * 上报走既有控制端通道，不为补报放开任何直连。
 */
export async function flushEventOutbox(ports = {}, {timeoutMs = 5000} = {}) {
  const pending = (ports.store?.listRecords?.(RECORD.EVENT) || []).filter((item) => item.status === 'PENDING' && item.event);
  const summary = {attempted: 0, delivered: 0, pending: 0};
  const deliver = ports.events?.deliver
    ? (event) => ports.events.deliver(event)
    : ports.control?.recordNetworkEvent
      ? (event) => ports.control.recordNetworkEvent(event)
      : null;
  if (!deliver) return {...summary, pending: pending.length, reason: 'EVENT_CHANNEL_UNAVAILABLE'};
  for (const item of pending) {
    const incident = ports.store?.getRecord?.(item.event_ref, RECORD.INCIDENT);
    const event = incident
      ? {...item.event, count: incident.count, last_at: incident.last_at, protection_status: incident.protection?.status || item.event.protection_status}
      : item.event;
    summary.attempted += 1;
    let delivery;
    try {
      delivery = await Promise.race([
        deliver(event),
        new Promise((resolve) => { setTimeout(() => resolve({status: 'PENDING', control_stuck: true}), timeoutMs); }),
      ]);
    } catch (error) {
      delivery = {status: 'PENDING', code: error?.code || 'EVENT_DELIVERY_FAILED'};
    }
    const outbox = recordDelivery(ports, item.event_ref, event, delivery, nowIso(ports.clock), item);
    if (outbox.status === 'DELIVERED') summary.delivered += 1;
    else summary.pending += 1;
  }
  return summary;
}

export async function handleProtectionEvent(state, event = {}, ports = {}) {
  const now = nowIso(ports.clock);
  const live = event.live === true && event.source !== 'archive' && event.source !== 'replay';
  const report = {
    proof_scope: PROOF_SIMULATION,
    observed_at: now,
    live,
    classification: event.classification,
    action: 'REPORT_ONLY',
    protection: {requested: false, os_readback: null, new_connections_restricted: false, status: 'NOT_REQUESTED'},
    incident: null,
    delivery: null,
  };

  if (!live) {
    report.reason = 'HISTORICAL_REPLAY_DOES_NOT_PROTECT';
    return report;
  }
  if (event.classification === 'SAFE_REJECT') {
    report.reason = 'SAFE_REJECT_NOT_CRITICAL';
    return report;
  }
  if (event.classification === 'ROUTE_ERROR') {
    report.action = 'KEEP_EXISTING_PROTECTION';
    report.reason = 'FIXED_ROUTE_HEALTH';
    report.protection.status = state?.protection?.status || 'RETAINED';
    return report;
  }

  const critical = event.classification === 'WRONG_ROUTE' || event.kind === 'PROTECTION_FAILED' || event.protection_failed === true;
  if (!critical) {
    report.reason = 'NOT_CRITICAL';
    return report;
  }

  const eventRef = incidentId(event);
  const existing = ports.store?.getRecord?.(eventRef, RECORD.INCIDENT);
  const incident = existing
    ? {
      ...existing,
      last_at: now,
      count: (existing.count || 1) + 1,
      event_ref: existing.event_ref,
    }
    : {
      event_ref: eventRef,
      first_at: now,
      last_at: now,
      count: 1,
      classification: event.classification,
      environment_ref: event.environment_ref || state?.environment_ref,
      process: event.process || null,
      destination: event.destination || null,
      assignment_version: event.assignment_version || state?.expected?.assignment_version || null,
      config_version: event.config_version || state?.expected?.plan_version || null,
      authorization_kind: AUTH_KIND.PROTECTION,
      resolved: false,
    };

  report.action = 'PREAUTHORIZED_PROTECTION';
  report.protection.requested = true;
  if (!ports.protection?.requestProtection) throw fail('PROTECTION_PORT_UNAVAILABLE', 'protection port is required for live WRONG_ROUTE');
  const started = Date.now();
  const scope = await resolveApprovedProtection({state, event, control: ports.control, userRef: state?.user_ref || event.user_ref});
  const result = await Promise.race([
    ports.protection.requestProtection({
      action: 'block_new',
      close_existing: true,
      environment_ref: incident.environment_ref,
      authorization_kind: AUTH_KIND.PROTECTION,
      event_ref: eventRef,
      processes: scope.processes,
      loopback_policy: scope.loopback_policy,
    }),
    new Promise((resolve) => {
      setTimeout(() => resolve({status: 'REQUESTED', requested: true, delayed: true, new_connections_restricted: false}), 20);
    }),
  ]);
  const waitedMs = Date.now() - started;
  report.protection = {
    requested: true,
    os_readback: result.os_readback || null,
    new_connections_restricted: result.new_connections_restricted === true,
    existing_closed: result.existing_closed === true,
    reconnect_allowed: result.reconnect_allowed === true,
    status: result.new_connections_restricted === true ? 'CONFIRMED' : result.requested ? 'UNCONFIRMED' : 'FAILED',
    waited_for_ai: false,
    waited_for_control: false,
    waited_for_archive: false,
    command_success_without_new_connection_block: result.effective === true && result.new_connections_restricted !== true,
  };
  if (report.protection.command_success_without_new_connection_block) {
    report.protection.status = 'UNCONFIRMED';
    report.reason = 'NEW_CONNECTIONS_STILL_ALLOWED';
  }
  incident.protection = report.protection;
  incident.waited_ms = waitedMs;
  ports.store?.saveRecord?.(RECORD.INCIDENT, eventRef, incident);
  report.incident = incident;

  const deliveryEvent = {
    event_ref: eventRef,
    kind: 'PROTECTION',
    classification: event.classification,
    environment_ref: incident.environment_ref,
    count: incident.count,
    first_at: incident.first_at,
    last_at: incident.last_at,
    protection_status: report.protection.status,
    proof_scope: PROOF_SIMULATION,
  };
  const deliver = ports.events?.deliver
    ? ports.events.deliver(deliveryEvent)
    : ports.control?.recordNetworkEvent
      ? ports.control.recordNetworkEvent(deliveryEvent)
      : Promise.resolve({status: 'PENDING', event_ref: eventRef, accepted: false});
  report.delivery = await Promise.race([
    deliver,
    new Promise((resolve) => {
      setTimeout(() => resolve({status: 'PENDING', event_ref: eventRef, accepted: false, control_stuck: true}), 20);
    }),
  ]);
  report.outbox = recordDelivery(ports, eventRef, deliveryEvent, report.delivery, now, ports.store?.getRecord?.(outboxId(eventRef), RECORD.EVENT));
  if (report.delivery?.control_stuck) {
    // 竞速之后才到的确认照样记下，不必等下一轮补报。
    Promise.resolve(deliver).then((late) => {
      const current = ports.store?.getRecord?.(outboxId(eventRef), RECORD.EVENT);
      if (accepted(late) && current?.status === 'PENDING') recordDelivery(ports, eventRef, deliveryEvent, late, nowIso(ports.clock), current);
    }, () => {});
  }
  if (report.delivery?.accepted !== true) {
    report.delivery = {...report.delivery, protection_lifted: false, extra_direct: false};
  }
  report.ai_or_control_stuck_still_protected = true;
  return report;
}
