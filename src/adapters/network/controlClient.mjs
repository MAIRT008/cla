import {publicQuota} from '../../core/network/quota.mjs';

function jsonRequest(method, path, token, body) {
  const headers = {authorization: `Bearer ${token}`, accept: 'application/json'};
  const init = {method, headers};
  if (body !== undefined) {
    headers['content-type'] = 'application/json';
    init.body = JSON.stringify(body);
  }
  return new Request(`https://application.synthetic.invalid${path}`, init);
}

function offlineQuota(cached, userRef) {
  if (!cached) {
    return publicQuota({user_ref: userRef, status: 'UNKNOWN', authority_status: 'UNKNOWN', control_status: 'OFFLINE', stale: true, node_new_limit_judgment: 'UNAVAILABLE'});
  }
  return {
    ...cached,
    control_status: 'OFFLINE',
    stale: true,
    node_new_limit_judgment: cached.authority_status === 'AVAILABLE' ? cached.node_new_limit_judgment : 'UNAVAILABLE',
  };
}

export function createHttpControlPort({handler, sessionToken, clock} = {}) {
  let offline = false;
  const cache = {assignment: new Map(), quota: new Map()};
  async function send(method, path, body) {
    if (offline) return {ok: false, code: 'CONTROL_OFFLINE'};
    const response = await handler.handle(jsonRequest(method, path, sessionToken, body));
    const payload = await response.json();
    return {ok: response.status < 400, status: response.status, body: payload};
  }
  return {
    kind: 'http-control',
    setOffline(value) { offline = value; },
    async getAssignment(userRef) {
      if (offline) {
        const cached = cache.assignment.get(userRef) || null;
        return {ok: false, code: 'CONTROL_OFFLINE', assignment: cached, used_cached: Boolean(cached), control_status: 'OFFLINE'};
      }
      const result = await send('GET', '/api/network/assignment');
      if (result.code === 'CONTROL_OFFLINE') {
        const cached = cache.assignment.get(userRef) || result.body?.assignment || null;
        return {ok: false, code: 'CONTROL_OFFLINE', assignment: cached, used_cached: Boolean(cached), control_status: 'OFFLINE'};
      }
      if (result.body?.assignment?.user_ref && result.body.assignment.user_ref !== userRef) {
        return {ok: false, code: 'CONTROL_FORBIDDEN', assignment: null};
      }
      if (result.body?.assignment) cache.assignment.set(userRef, result.body.assignment);
      return {ok: result.ok, assignment: result.body?.assignment || cache.assignment.get(userRef) || null};
    },
    async getQuotaSnapshot(userRef) {
      if (offline) {
        const cached = cache.quota.get(userRef) || null;
        return {ok: false, code: 'CONTROL_OFFLINE', snapshot: offlineQuota(cached, userRef), used_cached: Boolean(cached), control_status: 'OFFLINE'};
      }
      const result = await send('GET', '/api/network/quota');
      if (result.code === 'CONTROL_OFFLINE') {
        const cached = cache.quota.get(userRef) || result.body?.quota || null;
        return {ok: false, code: 'CONTROL_OFFLINE', snapshot: offlineQuota(cached, userRef), used_cached: Boolean(cached), control_status: 'OFFLINE'};
      }
      const snapshot = result.body?.quota || publicQuota({user_ref: userRef, status: 'UNKNOWN', authority_status: 'UNKNOWN'});
      if (result.ok && result.body?.quota) cache.quota.set(userRef, result.body.quota);
      return {ok: result.ok, snapshot};
    },
    async saveApplyReceipt(receipt) {
      return send('POST', '/api/network/receipts', receipt);
    },
    async recordNetworkEvent(event) {
      return send('POST', '/api/network/events', event);
    },
    clock,
  };
}
