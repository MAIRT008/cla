import {
  decodeGetConfigs,
  decodeGetRules,
  decodePutConfigs,
  encodeGet,
  encodePutConfigs,
} from './mihomoProtocol.mjs';
import {encodeWindowsProtectionCommand, WINDOWS_PROTECTION_APIS} from './windowsProtection.mjs';

const PRODUCT_PIPE = '\\\\.\\pipe\\ai-environmental-steward-service';

export function isDefaultMihomo(base) {
  const value = String(base || '').toLowerCase();
  return value.includes('127.0.0.1:9090') || value.includes('localhost:9090') || value.includes('clash-verge');
}

export function defaultProductHttpSend(baseUrl) {
  return async function productHttpSend(request) {
    if (isDefaultMihomo(baseUrl) || isDefaultMihomo(request.url)) {
      throw Object.assign(new Error('refusing the default Mihomo controller address'), {code: 'CORE_UNAVAILABLE'});
    }
    throw Object.assign(new Error(`CORE_ENDPOINT_NOT_CONFIGURED ${request.method} ${request.url}`), {code: 'CORE_UNAVAILABLE', encoded: request});
  };
}

export function defaultProductWfpInvoke(encoded) {
  return {
    accepted: true,
    effective: false,
    new_connections_restricted: false,
    readback: 'UNVERIFIED',
    api: 'FwpmFilterAdd0',
    sequence: ['FwpmEngineOpen0', 'FwpmSubLayerAdd0', 'FwpmFilterAdd0'],
    apis: WINDOWS_PROTECTION_APIS.map((item) => item.api),
    encoded,
  };
}

export function createProductHttpTransport({send, baseUrl} = {}) {
  const base = baseUrl ?? null;
  const sender = send || defaultProductHttpSend(base);
  async function request(encoded) {
    const response = await sender(encoded);
    return response;
  }
  return {
    kind: 'http-mihomo',
    baseUrl: base,
    async send(encoded) { return request(encoded); },
    async putConfigs(input) { return decodePutConfigs(await request(encodePutConfigs(input))); },
    async loadConfig({yaml, force = true} = {}) { return decodePutConfigs(await request(encodePutConfigs({payload: yaml, force}))); },
    async getConfigs() { return decodeGetConfigs(await request(encodeGet('/configs'))); },
    async getRules() { return decodeGetRules(await request(encodeGet('/rules'))); },
  };
}

export function createProductWfpInvoke({invoke} = {}) {
  const backend = invoke || defaultProductWfpInvoke;
  return {
    kind: 'windows-wfp',
    async invoke(command) {
      const encoded = command?.apis ? command : encodeWindowsProtectionCommand(command);
      return backend(encoded);
    },
  };
}

export function createProductHostAdapters({send, wfpInvoke, baseUrl} = {}) {
  return {
    transport: createProductHttpTransport({send, baseUrl}),
    protection: createProductWfpInvoke({invoke: wfpInvoke}),
  };
}

export function createHostState({windowsUser, adapters, factory = 'product'} = {}) {
  if (!adapters?.transport || !adapters?.protection) throw new Error('product host requires concrete transport and protection adapters');
  return {
    windows_user: windowsUser,
    transport: adapters.transport,
    protection: adapters.protection,
    factory,
    service_pipe: PRODUCT_PIPE,
  };
}

export function createProductHostState({windowsUser = 'synthetic-user', send, wfpInvoke, baseUrl} = {}) {
  return createHostState({
    windowsUser,
    adapters: createProductHostAdapters({send, wfpInvoke, baseUrl}),
    factory: 'product',
  });
}

export async function dispatchHostState(state, op, payload = {}, authorizationRef) {
  if (String(state.service_pipe || PRODUCT_PIPE).includes('clash-verge')) {
    throw Object.assign(new Error('refusing upstream Clash Verge pipe'), {code: 'SERVICE_IDENTITY_DENIED'});
  }
  if (op === 'ApplyNetworkPlan') {
    if (!authorizationRef) return {ok: false, code: 'AUTHORIZATION_REQUIRED', factory: state.factory};
    const encoded = encodePutConfigs({payload: payload.yaml, force: true});
    const sent = await state.transport.send(encoded);
    const decoded = decodePutConfigs({status: sent.status ?? sent.http_status, body: sent.body});
    const generalRaw = await state.transport.send(encodeGet('/configs'));
    const general = decodeGetConfigs({status: generalRaw.status ?? 200, body: generalRaw.body ?? generalRaw}).general;
    return {
      ok: decoded.accepted === true,
      factory: state.factory,
      encoded,
      http_status: decoded.http_status,
      accepted: decoded.accepted === true,
      loaded_version: null,
      general,
    };
  }
  if (op === 'ProtectEnvironment') {
    const processes = Array.isArray(payload.processes) ? payload.processes : [];
    if (!processes.length) {
      return {
        ok: false,
        factory: state.factory,
        requested: true,
        status: 'FAILED',
        reason: 'EMPTY_PROCESS_SCOPE',
        new_connections_restricted: false,
      };
    }
    const encoded = encodeWindowsProtectionCommand({
      environment_ref: payload.environment_ref,
      processes,
      action: payload.action || 'block_new',
      authorization_ref: authorizationRef,
    });
    const result = await state.protection.invoke(encoded);
    return {
      ok: result?.new_connections_restricted === true,
      factory: state.factory,
      requested: true,
      encoded,
      os_readback: result?.readback || 'UNKNOWN',
      effective: Boolean(result?.effective),
      new_connections_restricted: Boolean(result?.new_connections_restricted),
      native_api: result?.api || 'FwpmFilterAdd0',
      status: result?.new_connections_restricted ? 'CONFIRMED' : result?.accepted ? 'UNCONFIRMED' : 'FAILED',
    };
  }
  return {ok: false, code: 'UNSUPPORTED_OP', op, factory: state.factory};
}
