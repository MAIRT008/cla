(function installStewardBridge(global) {
  function unavailable(result) {
    return {__unavailable__: {
      code: result?.code || 'UI_BACKEND_NOT_ATTACHED',
      reason: result?.reason || '宿主未返回会话状态',
      name: result?.name || null,
    }};
  }

  function tauriInvoke() {
    return global.__TAURI__?.core?.invoke || global.__TAURI_INTERNALS__?.invoke || null;
  }

  async function dispatch(name, args) {
    if (typeof global.__STEWARD_HOST__ !== 'function' && global.__STEWARD_BOOT__) {
      try { await global.__STEWARD_BOOT__; } catch (error) {
        return unavailable({code: error?.code || 'UI_BACKEND_BOOT_FAILED', reason: error?.message, name});
      }
    }
    if (typeof global.__STEWARD_HOST__ === 'function') return global.__STEWARD_HOST__(name, args);
    if (typeof tauriInvoke() === 'function') {
      return unavailable({code: 'UI_BACKEND_BOOT_INCOMPLETE', reason: '受限原生桥在位，但组合根没有装配成功', name});
    }
    return unavailable({code: 'UI_BACKEND_NOT_ATTACHED', reason: '本机没有可用的受限原生桥', name});
  }

  function client() {
    return new Proxy({}, {
      get(_target, name) {
        if (name === 'then') return undefined;
        return (...args) => dispatch(String(name), args);
      },
    });
  }

  if (typeof global.__STEWARD_HOST__ === 'function' || global.__STEWARD_BOOT__ || tauriInvoke()) {
    global.__STEWARD__ = client();
  }
})(typeof globalThis === 'object' ? globalThis : this);
