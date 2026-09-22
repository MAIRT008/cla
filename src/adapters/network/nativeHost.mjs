import {
  decodeConnectionsSnapshot,
  decodeGetConfigs,
  decodeGetProxies,
  decodeGetRules,
  decodeGetVersion,
  decodePutConfigs,
  encodeGet,
  encodePutConfigs,
} from './mihomoProtocol.mjs';
import {encodeWindowsProtectionCommand} from './windowsProtection.mjs';

const PRODUCT_PIPE = '\\\\.\\pipe\\ai-environmental-steward-service';

export function createNativeNetworkHost({windowsUser, transport, invoke, servicePipe = PRODUCT_PIPE} = {}) {
  if (String(servicePipe).includes('clash-verge')) {
    throw Object.assign(new Error('refusing upstream Clash Verge pipe'), {code: 'SERVICE_IDENTITY_DENIED'});
  }
  return {
    kind: 'native-host',
    identity: {app_id: 'local.ai-environmental-steward.desktop', service_pipe: servicePipe, windows_user: windowsUser || null},
    compile_status: 'UNVERIFIED',
    async dispatch(op, payload = {}, authorizationRef, windowsUserNow = windowsUser) {
      if (!windowsUserNow) return {ok: false, code: 'WINDOWS_USER_REQUIRED'};
      if (op === 'ReadNetworkState') {
        if (!transport) return {ok: false, code: 'CORE_UNAVAILABLE', loaded_version: null};
        const [general, rules, proxies, version] = await Promise.all([
          transport.getConfigs(),
          transport.getRules(),
          transport.getProxies(),
          transport.getVersion(),
        ]);
        return {
          ok: true,
          identity: 'local.ai-environmental-steward.desktop',
          windows_user: windowsUserNow,
          authorization_ref: authorizationRef || null,
          general: general.general,
          rules: rules.rules,
          proxies: proxies.proxies,
          kernel_version: version.version,
          loaded_version: null,
        };
      }
      if (op === 'ApplyNetworkPlan') {
        if (!authorizationRef) return {ok: false, code: 'AUTHORIZATION_REQUIRED'};
        if (!transport?.putConfigs && !transport?.loadConfig && !transport?.request) return {ok: false, code: 'CORE_UNAVAILABLE'};
        const encoded = encodePutConfigs({payload: payload.yaml, force: true, secret: payload.secret});
        const sent = transport.loadConfig
          ? await transport.loadConfig({yaml: payload.yaml, force: true})
          : transport.request
            ? decodePutConfigs(await transport.request(encoded))
            : await transport.putConfigs(encoded);
        const general = transport.getConfigs ? await transport.getConfigs() : {general: null, loaded_version: null};
        return {
          ok: sent.accepted === true,
          identity: 'local.ai-environmental-steward.desktop',
          windows_user: windowsUserNow,
          authorization_ref: authorizationRef,
          encoded,
          http_status: sent.http_status,
          accepted: sent.accepted === true,
          loaded_version: null,
          general: general.general || null,
        };
      }
      if (op === 'ProtectEnvironment') {
        const processes = Array.isArray(payload.processes) ? payload.processes : [];
        if (!processes.length) {
          return {
            ok: false,
            status: 'FAILED',
            requested: true,
            reason: 'EMPTY_PROCESS_SCOPE',
            effective: false,
            new_connections_restricted: false,
          };
        }
        const encoded = encodeWindowsProtectionCommand({
          environment_ref: payload.environment_ref,
          processes,
          action: payload.action || 'block_new',
          authorization_ref: authorizationRef,
        });
        if (!invoke) return {ok: false, status: 'UNAVAILABLE', requested: false, new_connections_restricted: false, reason: 'NATIVE_INVOKE_NOT_CONFIGURED', encoded};
        const result = await invoke({op: 'wfp_protect', encoded});
        return {
          ok: result?.new_connections_restricted === true,
          status: result?.new_connections_restricted ? 'CONFIRMED' : result?.accepted ? 'UNCONFIRMED' : 'FAILED',
          requested: true,
          encoded,
          os_readback: result?.readback || 'UNKNOWN',
          effective: Boolean(result?.effective),
          new_connections_restricted: Boolean(result?.new_connections_restricted),
          native_api: result?.api || 'FwpmFilterAdd0',
        };
      }
      return {ok: false, code: 'UNSUPPORTED_OP', op};
    },
  };
}
