export const WINDOWS_PROTECTION_APIS = Object.freeze([
  {dll: 'fwpuclnt.dll', api: 'FwpmEngineOpen0', purpose: 'open a WFP engine session owned by this product'},
  {dll: 'fwpuclnt.dll', api: 'FwpmSubLayerAdd0', purpose: 'add the product sublayer if missing'},
  {dll: 'fwpuclnt.dll', api: 'FwpmFilterAdd0', purpose: 'add a block filter that covers new connections in the declared process/environment scope'},
  {dll: 'fwpuclnt.dll', api: 'FwpmFilterDeleteByKey0', purpose: 'remove only filters this product added'},
  {dll: 'fwpuclnt.dll', api: 'FwpmEngineClose0', purpose: 'close the engine session'},
  {dll: 'firewallapi.dll', api: 'INetFwPolicy2::Rules', purpose: 'optional Windows Firewall fallback when WFP is unavailable'},
]);

export function encodeWindowsProtectionCommand({environment_ref, processes, action, authorization_ref, product_sublayer}) {
  return {
    platform: 'windows',
    action,
    environment_ref,
    processes: processes || [],
    authorization_ref,
    product_sublayer: product_sublayer || 'ai-steward-network-protect',
    apis: WINDOWS_PROTECTION_APIS.map((item) => item.api),
    blocks_new_connections: action === 'block_new',
    close_existing: action !== 'observe',
  };
}

export function createWindowsProtectionAdapter({invoke} = {}) {
  if (!invoke) {
    return {
      kind: 'windows-native',
      status: 'unavailable',
      reason: 'NATIVE_INVOKE_NOT_CONFIGURED',
      apis: WINDOWS_PROTECTION_APIS,
      async requestProtection() {
        return {status: 'UNAVAILABLE', requested: false, effective: false, new_connections_restricted: false, reason: 'NATIVE_INVOKE_NOT_CONFIGURED'};
      },
      async readback() {
        return {status: 'UNAVAILABLE', effective: false, new_connections_restricted: false};
      },
    };
  }
  return {
    kind: 'windows-native',
    status: 'configured',
    apis: WINDOWS_PROTECTION_APIS,
    async requestProtection(command) {
      if (!Array.isArray(command?.processes) || command.processes.length === 0) {
        return {status: 'FAILED', reason: 'EMPTY_PROCESS_SCOPE', requested: false, effective: false, new_connections_restricted: false};
      }
      const encoded = encodeWindowsProtectionCommand(command);
      const result = await invoke({op: 'wfp_protect', encoded});
      return {
        status: result?.new_connections_restricted ? 'CONFIRMED' : result?.accepted ? 'UNCONFIRMED' : 'FAILED',
        requested: true,
        os_readback: result?.readback || 'UNKNOWN',
        effective: Boolean(result?.effective),
        new_connections_restricted: Boolean(result?.new_connections_restricted),
        native_api: result?.api || 'FwpmFilterAdd0',
      };
    },
    async readback(scope) {
      const result = await invoke({op: 'wfp_readback', encoded: encodeWindowsProtectionCommand({...scope, action: 'observe'})});
      return {
        status: result?.new_connections_restricted ? 'CONFIRMED' : 'UNCONFIRMED',
        effective: Boolean(result?.effective),
        new_connections_restricted: Boolean(result?.new_connections_restricted),
      };
    },
  };
}
