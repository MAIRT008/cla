import {createHash, randomUUID} from 'node:crypto';
import {
  decodeDeleteConnections,
  decodeGetConfigs,
  decodeGetProxies,
  decodeGetRules,
  decodeGetVersion,
  decodePutConfigs,
  generalFromYaml,
  proxiesFromYaml,
  rulesFromYaml,
} from './mihomoProtocol.mjs';
import {PRODUCT_CLASSIFICATION_VERSION, PROOF_SIMULATION} from '../../core/network/constants.mjs';
import {publicQuota} from '../../core/network/quota.mjs';
import {publicAssignment} from '../../../services/control/network.mjs';

function clone(value) {
  return structuredClone(value);
}

function digest(value) {
  return createHash('sha256').update(typeof value === 'string' ? value : JSON.stringify(value)).digest('hex');
}

export function createCoreFixture(options = {}) {
  const state = {
    instanceId: options.instanceId || `core-${randomUUID()}`,
    alive: true,
    payload: null,
    path: null,
    kernelVersion: options.kernelVersion || 'v1.19.30',
    restartCount: 0,
    lastForce: null,
    inject: {...options.inject},
    connections: [],
    traffic: {up: 0, down: 0, upTotal: 0, downTotal: 0},
    logs: [],
  };

  function currentYaml() {
    return state.payload;
  }

  async function request(encoded) {
    if (state.inject.transportError) {
      const error = Object.assign(new Error(state.inject.transportError), {code: 'CORE_PROTOCOL_ERROR'});
      throw error;
    }
    if (!state.alive && !state.inject.allowDead) {
      return {status: 0, body: {message: 'core instance is not alive'}};
    }
    const url = encoded.url || '';
    if (encoded.method === 'PUT' && url.startsWith('/configs')) {
      const force = url.includes('force=true');
      state.lastForce = force;
      const body = encoded.body || {};
      if (state.inject.parseFail) return {status: 400, body: {message: 'parse error'}};
      if (body.payload) {
        if (state.inject.loadFail) {
          state.inject.loadFail = false;
          return {status: 400, body: {message: 'apply failed'}};
        }
        state.payload = body.payload;
        state.path = null;
        return {status: 204, body: null};
      }
      if (body.path) {
        if (!options.allowedPaths?.includes(body.path)) return {status: 400, body: {message: 'path is not a absolute path'}};
        if (state.inject.loadFail) return {status: 400, body: {message: 'apply failed'}};
        state.path = body.path;
        state.payload = options.pathContents?.[body.path] || state.payload;
        return {status: 204, body: null};
      }
      return {status: 400, body: {message: 'payload or path is required'}};
    }
    if (encoded.method === 'GET' && url.startsWith('/configs')) {
      const yaml = state.inject.oldRulesYaml || currentYaml();
      const general = yaml ? generalFromYaml(yaml) : {mode: null, tun: {enable: false}, ipv6: true};
      if (state.inject.tunLost) general.tun = {enable: false, stack: null};
      return {status: 200, body: general};
    }
    if (encoded.method === 'GET' && url.startsWith('/rules')) {
      const yaml = state.inject.oldRulesYaml || currentYaml();
      return {status: 200, body: {rules: yaml ? rulesFromYaml(yaml) : []}};
    }
    if (encoded.method === 'GET' && url.startsWith('/proxies')) {
      const yaml = currentYaml();
      const proxies = yaml ? proxiesFromYaml(yaml) : {};
      if (state.inject.wrongExit && proxies['CLAUDE-FIXED']) proxies['CLAUDE-FIXED'].now = state.inject.wrongExit;
      return {status: 200, body: {proxies}};
    }
    if (encoded.method === 'GET' && url.startsWith('/version')) {
      return {status: 200, body: {meta: true, version: state.kernelVersion}};
    }
    if (encoded.method === 'GET' && url.startsWith('/connections')) {
      return {status: 200, body: {downloadTotal: state.traffic.downTotal, uploadTotal: state.traffic.upTotal, connections: state.connections, memory: 0}};
    }
    if (encoded.method === 'GET' && url.startsWith('/traffic')) {
      return {status: 200, body: state.traffic};
    }
    if (encoded.method === 'GET' && url.startsWith('/logs')) {
      return {status: 200, body: state.logs};
    }
    if (encoded.method === 'DELETE' && url.startsWith('/connections')) {
      if (url === '/connections') state.connections = [];
      else {
        const id = url.slice('/connections/'.length);
        state.connections = state.connections.filter((item) => item.id !== id);
      }
      return {status: 204, body: null};
    }
    return {status: 404, body: {message: 'not found'}};
  }

  return {
    kind: 'fixture',
    proof_scope: PROOF_SIMULATION,
    state,
    inject(values) { Object.assign(state.inject, values); },
    restart() {
      state.restartCount += 1;
      state.alive = true;
      if (state.inject.restartDropsConfig) state.payload = null;
    },
    crash() { state.alive = false; },
    setConnections(items) { state.connections = clone(items); },
    setTraffic(value) { Object.assign(state.traffic, value); },
    setLogs(lines) { state.logs = clone(lines); },
    async putConfigs(input) {
      const encoded = input.encoded || input.url ? input : null;
      const requestBody = encoded || {method: 'PUT', url: `/configs${input.force === false ? '' : '?force=true'}`, body: input.payload != null ? {payload: input.payload} : {path: input.path}};
      const response = await request(requestBody);
      return {...decodePutConfigs(response), payload_hash: requestBody.body?.payload ? digest(requestBody.body.payload) : null, instance_id: state.instanceId};
    },
    async loadConfig({yaml, path, force = true} = {}) {
      return this.putConfigs({payload: yaml, path, force});
    },
    async getConfigs() { return decodeGetConfigs(await request({method: 'GET', url: '/configs'})); },
    async getRules() { return decodeGetRules(await request({method: 'GET', url: '/rules'})); },
    async getProxies() { return decodeGetProxies(await request({method: 'GET', url: '/proxies'})); },
    async getVersion() { return decodeGetVersion(await request({method: 'GET', url: '/version'})); },
    async getConnections() { return {status: 200, ...(await request({method: 'GET', url: '/connections'})).body}; },
    async getTraffic() { return (await request({method: 'GET', url: '/traffic'})).body; },
    async getLogs() { return {lines: (await request({method: 'GET', url: '/logs'})).body || []}; },
    async deleteConnections(id) { return decodeDeleteConnections(await request({method: 'DELETE', url: id ? `/connections/${id}` : '/connections'})); },
    request,
    loadedPayload() { return state.payload; },
    snapshot() {
      return {
        instance_id: state.instanceId,
        alive: state.alive,
        restart_count: state.restartCount,
        has_payload: Boolean(state.payload),
        kernel_version: state.kernelVersion,
        loaded_version: null,
      };
    },
  };
}

export function createProtectionFixture(options = {}) {
  const state = {
    requested: [],
    effective: false,
    newConnectionsRestricted: false,
    reconnectAllowed: options.reconnectAllowed === true,
    inject: {...options.inject},
    retainedAfterExit: false,
  };
  return {
    kind: 'fixture',
    proof_scope: PROOF_SIMULATION,
    state,
    inject(values) { Object.assign(state.inject, values); },
    async requestProtection(command) {
      state.requested.push(clone(command));
      if (!Array.isArray(command?.processes) || command.processes.length === 0) {
        return {status: 'FAILED', reason: 'EMPTY_PROCESS_SCOPE', requested: false, effective: false, new_connections_restricted: false, code: 'EMPTY_PROCESS_SCOPE'};
      }
      if (state.inject.refuse) return {status: 'REJECTED', requested: true, effective: false, new_connections_restricted: false};
      if (state.inject.delay) return {status: 'REQUESTED', requested: true, effective: false, new_connections_restricted: false, delayed: true};
      if (!state.inject.readbackFail) {
        state.effective = state.inject.commandOnly ? true : !state.inject.reconnectAllowed;
        state.newConnectionsRestricted = state.inject.reconnectAllowed ? false : true;
      }
      state.retainedAfterExit = true;
      return {
        status: state.newConnectionsRestricted ? 'CONFIRMED' : state.effective ? 'UNCONFIRMED' : 'REQUESTED',
        requested: true,
        os_readback: state.inject.readbackFail ? 'UNKNOWN' : state.effective ? 'APPLIED' : 'MISSING',
        effective: state.effective,
        new_connections_restricted: state.newConnectionsRestricted,
        reconnect_allowed: state.inject.reconnectAllowed === true || state.reconnectAllowed,
        existing_closed: command.close_existing !== false,
      };
    },
    async readback() {
      if (state.inject.readbackFail) return {status: 'UNKNOWN', effective: false, new_connections_restricted: false};
      return {status: state.newConnectionsRestricted ? 'CONFIRMED' : state.requested.length ? 'UNCONFIRMED' : 'INACTIVE', effective: state.effective, new_connections_restricted: state.newConnectionsRestricted, retained_after_exit: state.retainedAfterExit};
    },
    markUiExit() { return {protection_retained: state.retainedAfterExit || state.requested.length > 0, core_stopped: false}; },
    snapshot() {
      return {
        requested_count: state.requested.length,
        last_request: state.requested.at(-1) || null,
        effective: state.effective,
        new_connections_restricted: state.newConnectionsRestricted,
      };
    },
  };
}

export function createVerifyFixture(options = {}) {
  const outcomes = {...options.outcomes};
  return {
    kind: 'fixture',
    proof_scope: PROOF_SIMULATION,
    inject(values) { Object.assign(outcomes, values); },
    async verify({mode, environment_ref, checks}) {
      const results = (checks || []).map((check) => {
        const forced = outcomes[check.id] || outcomes[check.target] || outcomes[check.kind];
        if (forced) return {id: check.id, kind: check.kind, target: check.target, ...forced, echoed_plan: false};
        return {
          id: check.id,
          kind: check.kind,
          target: check.target,
          expected: check.expected,
          actual: outcomes.defaultActual || check.expected,
          ok: !outcomes.failAll,
          protocol: check.protocol || 'tcp',
          environment_ref,
          mode,
        };
      });
      return {
        status: results.every((item) => item.ok) ? 'VERIFIED' : 'VERIFY_FAILED',
        results,
        environment_ref,
        mode,
      };
    },
  };
}

export function createEmergencyHostFixture(options = {}) {
  const hosts = clone(options.hosts || [
    {id: 'browser-firefox', kind: 'second_browser', distinguishable: true, process: 'firefox.exe', approved: true},
    {id: 'webview-shared', kind: 'shared_webview', distinguishable: false, process: 'msedgewebview2.exe', approved: false},
    {id: 'chrome-protected', kind: 'protected_browser', distinguishable: false, process: 'chrome.exe', approved: false},
  ]);
  const sessions = new Map();
  const inject = {...options.inject};
  return {
    kind: 'fixture',
    proof_scope: PROOF_SIMULATION,
    hosts,
    inject(values) { Object.assign(inject, values); },
    listCandidates() { return clone(hosts); },
    async open({session_id, host_id, expires_at}) {
      const host = hosts.find((item) => item.id === host_id);
      if (!host) return {ok: false, code: 'EMERGENCY_HOST_UNAVAILABLE'};
      if (host.kind === 'shared_webview' || host.process === 'msedgewebview2.exe') return {ok: false, code: 'EMERGENCY_WEBVIEW_DENIED'};
      if (host.kind === 'protected_browser') return {ok: false, code: 'EMERGENCY_PROTECTED_BROWSER_DENIED'};
      if (!host.distinguishable || !host.approved) return {ok: false, code: 'EMERGENCY_HOST_UNAVAILABLE'};
      if (inject.openFail) return {ok: false, code: 'EMERGENCY_OPEN_FAILED'};
      sessions.set(session_id, {session_id, host_id, process: host.process, expires_at, open: true});
      return {ok: true, session_id, host_id, process: host.process, expires_at};
    },
    async close({session_id}) {
      const session = sessions.get(session_id);
      if (inject.closeFail) return {ok: false, code: 'EMERGENCY_CLOSE_FAILED', session};
      if (session) session.open = false;
      return {ok: true, session_id, open: false, readback: session ? 'CLOSED' : 'MISSING'};
    },
    snapshot(sessionId) { return sessions.get(sessionId) || null; },
  };
}

export function createEventDeliveryFixture() {
  const pending = new Map();
  const confirmed = new Map();
  let offline = false;
  return {
    kind: 'fixture',
    proof_scope: PROOF_SIMULATION,
    setOffline(value) { offline = value; },
    async deliver(event) {
      pending.set(event.event_ref, {event, attempts: (pending.get(event.event_ref)?.attempts || 0) + 1, delivered: false});
      if (offline) return {status: 'PENDING', event_ref: event.event_ref, accepted: false};
      confirmed.set(event.event_ref, {event_ref: event.event_ref, accepted: true});
      pending.get(event.event_ref).delivered = true;
      return {status: 'ACCEPTED', event_ref: event.event_ref, accepted: true};
    },
    async confirm(eventRef) { return confirmed.get(eventRef) || null; },
    pending() { return [...pending.values()]; },
  };
}

export function createControlPort({store, clock} = {}) {
  let offline = false;
  let stale = false;
  return {
    kind: store ? 'control-store' : 'memory',
    proof_scope: PROOF_SIMULATION,
    classification_version: PRODUCT_CLASSIFICATION_VERSION,
    setOffline(value) { offline = value; },
    setStale(value) { stale = value; },
    async getAssignment(userRef) {
      const raw = store?.getAssignment?.(userRef) || null;
      const assignment = publicAssignment(raw);
      if (offline) return {ok: false, code: 'CONTROL_OFFLINE', assignment, used_cached: true};
      return {ok: true, assignment, stale};
    },
    async getQuotaSnapshot(userRef) {
      const snapshot = publicQuota(store.getQuotaSnapshot(userRef));
      if (!snapshot) return {ok: true, snapshot: {user_ref: userRef, status: 'UNKNOWN', authority_status: 'UNKNOWN', node_new_limit_judgment: 'UNKNOWN', proof_scope: PROOF_SIMULATION}};
      if (snapshot.authority_status === 'OFFLINE' || stale) {
        return {ok: true, snapshot: {...snapshot, authority_status: snapshot.authority_status || 'STALE', node_new_limit_judgment: 'UNAVAILABLE', stale: true}};
      }
      return {ok: true, snapshot};
    },
    async saveApplyReceipt(receipt) {
      store.saveApplyReceipt(receipt);
      return {ok: true};
    },
    async recordNetworkEvent(event) {
      store.recordNetworkEvent(event);
      return {ok: !offline, queued: offline};
    },
    clock,
  };
}
