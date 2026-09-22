function unknown(reason) {
  return {status: 'UNKNOWN', reason: reason || 'upstream field is not provided'};
}

export function readQuotaView(snapshot, {localBytes = null} = {}) {
  if (!snapshot) {
    return {
      status: 'UNKNOWN',
      authority_status: 'UNKNOWN',
      node_new_limit_judgment: 'UNAVAILABLE',
      used_bytes: null,
      limit_bytes: null,
      remaining_bytes: null,
      unlimited: false,
      period: null,
      observed_at: null,
      measured_at: null,
      split: {A: unknown(), B: unknown(), devices: unknown(), upload: unknown(), download: unknown()},
      local_bytes: localBytes ? {...localBytes, scope: 'T2_CLIENT_ONLY'} : {scope: 'T2_CLIENT_ONLY', status: 'UNKNOWN'},
      next_action: 'WAIT_FOR_SNAPSHOT',
    };
  }
  const unlimited = snapshot.unlimited === true || snapshot.limit_bytes === 0;
  const used = snapshot.used_bytes ?? null;
  const limit = unlimited ? 0 : (snapshot.limit_bytes ?? null);
  const remaining = unlimited || used == null || snapshot.limit_bytes == null ? null : Math.max(0, snapshot.limit_bytes - used);
  const paused = ['LIMITED', 'DISABLED', 'EXPIRED'].includes(snapshot.status);
  let nextAction = 'NONE';
  if (snapshot.status === 'LIMITED') nextAction = 'KEEP_APPROVED_DIRECT_STOP_PROXY';
  else if (snapshot.status === 'DISABLED') nextAction = 'WAIT_ADMIN_RESUME';
  else if (snapshot.status === 'EXPIRED') nextAction = 'WAIT_RENEWAL';
  else if (snapshot.authority_status === 'OFFLINE' || snapshot.stale) nextAction = 'KEEP_LAST_SNAPSHOT_AND_PROTECTION';
  return {
    user_ref: snapshot.user_ref || null,
    status: snapshot.status || 'UNKNOWN',
    used_bytes: used,
    limit_bytes: limit,
    remaining_bytes: remaining,
    unlimited,
    period: snapshot.period || null,
    last_traffic_reset_at: snapshot.last_traffic_reset_at || null,
    expire_at: snapshot.expire_at || null,
    observed_at: snapshot.observed_at || null,
    measured_at: snapshot.measured_at ?? null,
    metering_layer: snapshot.metering_layer || null,
    unit: snapshot.unit || 'bytes',
    authority_status: snapshot.authority_status || 'UNKNOWN',
    control_status: snapshot.control_status || 'UNKNOWN',
    node_new_limit_judgment: snapshot.authority_status === 'AVAILABLE' ? (snapshot.node_new_limit_judgment || 'UNKNOWN') : 'UNAVAILABLE',
    stale: snapshot.stale === true,
    proxy_paused: paused,
    degrade_forbidden: true,
    unknown_direct_forbidden: true,
    split: {
      A: snapshot.split_ab || unknown(),
      B: snapshot.split_ab || unknown(),
      devices: snapshot.devices || unknown(),
      upload: snapshot.upload_bytes || unknown(),
      download: snapshot.download_bytes || unknown(),
    },
    local_bytes: localBytes ? {...localBytes, scope: 'T2_CLIENT_ONLY'} : {scope: 'T2_CLIENT_ONLY', status: 'UNKNOWN'},
    node_remove: snapshot.node_remove || null,
    next_action: nextAction,
  };
}

export function deriveQuotaNotice(snapshot, previous = null, {thresholds = [80, 95, 100], pool = null} = {}) {
  const view = readQuotaView(snapshot);
  const notices = [];
  if (view.unlimited || view.limit_bytes == null || view.used_bytes == null || view.limit_bytes === 0) {
    return {notices, view};
  }
  const ratio = view.used_bytes / view.limit_bytes;
  for (const threshold of thresholds) {
    if (ratio * 100 >= threshold) {
      const key = `${view.user_ref}:${view.period || 'NO_RESET'}:${view.last_traffic_reset_at || 'none'}:${threshold}`;
      if (previous?.sent?.includes(key)) continue;
      notices.push({kind: 'USER_THRESHOLD', threshold, key, status: view.status});
    }
  }
  if (view.status === 'LIMITED') notices.push({kind: 'USER_LIMITED', key: `${view.user_ref}:limited`});
  if (pool?.exhausted) notices.push({kind: 'POOL_EXHAUSTED', key: `pool:${pool.pool_id || 'default'}`, user_over_quota: false});
  if (view.authority_status === 'OFFLINE' || view.stale) notices.push({kind: 'SYNC_STALE', key: `${view.user_ref}:stale`});
  return {notices, view};
}

export function applyQuotaOperation(snapshot) {
  const view = readQuotaView(snapshot);
  return {
    view,
    proxy_paused: view.proxy_paused,
    whitelist_daily_direct_only: snapshot?.status === 'LIMITED',
    dedicated_no_whitelist: true,
    no_degrade: true,
    no_borrow: true,
  };
}

export function publicQuota(snapshot) {
  if (!snapshot) return null;
  const unlimited = snapshot.unlimited === true || snapshot.limit_bytes === 0;
  const used = snapshot.used_bytes ?? null;
  const limit = unlimited ? 0 : (snapshot.limit_bytes ?? null);
  return {
    user_ref: snapshot.user_ref,
    status: snapshot.status,
    used_bytes: used,
    limit_bytes: limit,
    unlimited,
    remaining_bytes: unlimited || used == null || snapshot.limit_bytes == null ? null : Math.max(0, snapshot.limit_bytes - used),
    period: snapshot.period || null,
    last_traffic_reset_at: snapshot.last_traffic_reset_at || null,
    expire_at: snapshot.expire_at || null,
    observed_at: snapshot.observed_at || null,
    measured_at: snapshot.measured_at ?? null,
    metering_layer: snapshot.metering_layer || null,
    unit: snapshot.unit || 'bytes',
    authority_ref: snapshot.authority_ref || null,
    authority_status: snapshot.authority_status || 'UNKNOWN',
    control_status: snapshot.control_status || 'UNKNOWN',
    node_new_limit_judgment: snapshot.authority_status === 'AVAILABLE' ? snapshot.node_new_limit_judgment || 'UNKNOWN' : 'UNAVAILABLE',
    stale: snapshot.stale === true,
    upload_bytes: snapshot.upload_bytes && typeof snapshot.upload_bytes === 'object' ? snapshot.upload_bytes : {status: 'UNKNOWN'},
    download_bytes: snapshot.download_bytes && typeof snapshot.download_bytes === 'object' ? snapshot.download_bytes : {status: 'UNKNOWN'},
    split_ab: snapshot.split_ab && typeof snapshot.split_ab === 'object' ? snapshot.split_ab : {status: 'UNKNOWN'},
    devices: snapshot.devices && typeof snapshot.devices === 'object' ? snapshot.devices : {status: 'UNKNOWN'},
    node_remove: snapshot.node_remove ? {
      requested: snapshot.node_remove.requested === true,
      accepted: snapshot.node_remove.accepted === true,
      in_flight: snapshot.node_remove.in_flight || 'UNKNOWN',
      verified_disconnect: snapshot.node_remove.verified_disconnect || 'UNKNOWN',
    } : null,
    proof_scope: snapshot.proof_scope || null,
  };
}
