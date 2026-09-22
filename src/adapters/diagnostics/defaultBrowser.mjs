/**
 * 默认浏览器诊断（FD-02）：证据来自用户系统默认浏览器里运行的诊断页，不是 WebView 自己。
 *
 * 顺序：宿主开一次性回环监听拿到源 → 诊断核心用这个源建会话（nonce 只在这里和宿主之间传）→
 * 宿主把会话注入页面并打开默认浏览器 → 取回唯一一份回传，交核心按源、nonce、任务、环境与期限校验。
 * 页面给不了宿主任何 URL；Profile 不凭 UA 认定，会话按「未绑定」记。
 */
export function createDefaultBrowserDiagnostics({invoke, diagnostics, iceServers = []}) {
  let active = null;

  async function call(op, payload) {
    let result;
    try {
      result = await invoke(op, payload, null);
    } catch (error) {
      throw Object.assign(new Error(error?.message || String(error)), {code: error?.code || 'BROWSER_DIAG_FAILED'});
    }
    if (result?.ok !== true) throw Object.assign(new Error(result?.reason || `${op} failed`), {code: result?.code || 'BROWSER_DIAG_FAILED'});
    return result;
  }

  function view(status, extra = {}) {
    return {
      status,
      origin: active?.origin || null,
      task_ref: active?.task_ref || null,
      session_ref: active?.session_ref || null,
      expires_at: active?.expires_at || null,
      source: 'default_browser',
      ...extra,
    };
  }

  async function close() {
    if (!active) return;
    const listenerRef = active.listener_ref;
    active = null;
    try { await call('BrowserDiagClose', {listener_ref: listenerRef}); } catch {}
  }

  return {
    async open({taskRef, environmentRef}) {
      if (!taskRef) throw Object.assign(new Error('先完成一次诊断扫描，再在默认浏览器里检测'), {code: 'DIAG_TASK_REQUIRED'});
      await close();
      const listened = await call('BrowserDiagListen', {task_ref: taskRef, environment_ref: environmentRef});
      const session = diagnostics.createSession({
        taskRef,
        environmentRef,
        clientRef: 'default-browser',
        profileRef: null,
        origin: listened.origin,
      });
      active = {
        listener_ref: listened.listener_ref,
        origin: listened.origin,
        expires_at: listened.expires_at,
        task_ref: taskRef,
        session_ref: session.session_ref,
      };
      try {
        await call('BrowserDiagLaunch', {
          listener_ref: listened.listener_ref,
          session: {
            session_ref: session.session_ref,
            session_nonce: session.session_nonce,
            script_version: session.script_version,
            task_ref: taskRef,
            environment_ref: environmentRef,
            profile_ref: null,
            ice_servers: iceServers,
          },
        });
      } catch (error) {
        await close();
        throw error;
      }
      return view('WAITING');
    },

    /** 取一次回传；收到就交核心校验并关掉监听，没收到就回报等待或过期。 */
    async check() {
      if (!active) return {view: view('IDLE'), accepted: null};
      const received = await call('BrowserDiagReceive', {listener_ref: active.listener_ref});
      if (received.status === 'WAITING') return {view: view('WAITING'), accepted: null};
      if (received.status !== 'RECEIVED') {
        const expired = view('EXPIRED');
        await close();
        return {view: expired, accepted: null};
      }
      const accepted = diagnostics.acceptReport({headers: {origin: received.origin}, body: received.body});
      const done = view(accepted.ok ? 'RECEIVED' : 'REJECTED', {receipt_ref: accepted.receipt_ref || null, code: accepted.ok ? null : accepted.code});
      await close();
      return {view: done, accepted};
    },

    close,
    active: () => (active ? {...active} : null),
  };
}
