import {randomBytes, webcrypto} from 'node:crypto';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';

export const DIAG_PAGE = readFileSync(new URL('../../apps/desktop-host/diag/index.html', import.meta.url), 'utf8');
const SESSION_PLACEHOLDER = '__STEWARD_DIAG_SESSION__';
const MAX_BODY_BYTES = 64 * 1024;

/** 与 browser_diag.rs 的 inject 同一规则：会话 JSON 里的 < > & 转义后放进页面。 */
export function injectSession(session) {
  const escaped = JSON.stringify(session).replaceAll('<', '\\u003c').replaceAll('>', '\\u003e').replaceAll('&', '\\u0026');
  return DIAG_PAGE.replace(SESSION_PLACEHOLDER, () => escaped);
}

/**
 * 在合成「浏览器」里执行诊断页：navigator、时区、语言与 WebRTC 候选由参数给出，
 * fetch 只交给 respond 处理、不发网络。返回页面发出的请求和页面最后显示的状态。
 */
export async function runDiagPage(html, {origin, browser = {}, respond}) {
  const sessionText = /<script id="steward-session" type="application\/json">([\s\S]*?)<\/script>/.exec(html)?.[1];
  const script = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((match) => match[1]).join('\n');
  const elements = {'steward-session': {textContent: sessionText}, status: {textContent: ''}};
  const timezone = browser.timezone || 'UTC';
  const offset = browser.utc_offset_minutes ?? 0;
  const locale = browser.locale || 'en-US';
  const requests = [];
  const peers = [];
  class BrowserDate extends Date {
    getTimezoneOffset() { return -offset; }
  }
  function DateTimeFormat() {
    const real = new Intl.DateTimeFormat(locale, {timeZone: timezone});
    return {resolvedOptions: () => ({...real.resolvedOptions(), timeZone: timezone, locale})};
  }
  class FakePeer {
    constructor(config) {
      peers.push(config);
      this.onicecandidate = null;
    }
    createDataChannel() {}
    createOffer() { return Promise.resolve({type: 'offer', sdp: ''}); }
    setLocalDescription() {
      setTimeout(() => {
        for (const candidate of browser.candidates || []) this.onicecandidate?.({candidate: {candidate}});
        this.onicecandidate?.({candidate: null});
      }, 0);
      return Promise.resolve();
    }
    close() {}
  }
  const context = vm.createContext({
    document: {
      getElementById: (id) => elements[id] || null,
      createElement: () => ({getContext: (kind) => (kind === '2d' ? {fillText() {}} : null), toDataURL: () => 'data:image/png;base64,c3ludGhldGlj'}),
    },
    navigator: {
      language: locale,
      languages: browser.languages || [locale],
      userAgent: browser.user_agent || 'synthetic-default-browser',
      hardwareConcurrency: 8,
      onLine: true,
      cookieEnabled: true,
    },
    Intl: {DateTimeFormat, NumberFormat: Intl.NumberFormat},
    Date: BrowserDate,
    RTCPeerConnection: browser.webrtc === false ? undefined : FakePeer,
    crypto: webcrypto,
    TextEncoder,
    setTimeout,
    clearTimeout,
    screen: {width: 1920, height: 1080, colorDepth: 24},
    devicePixelRatio: 1,
    fetch: async (url, init) => {
      requests.push({url, init});
      return respond({url, init, origin});
    },
  });
  context.globalThis = context;
  await vm.runInContext(script, context);
  return {requests, peers, status: elements.status.textContent};
}

/**
 * 站在 browser_diag.rs 的位置：同一组四个操作、同一套校验，但不开真实端口、不打开真实浏览器。
 * 「打开浏览器」就是在合成浏览器里执行诊断页；autoRun 为 false 时由用例决定页面什么时候跑。
 */
export function createSyntheticBrowserHost({hostEnvironment = 'windows-host', browser = {}, clock = () => new Date().toISOString(), ttlMs = 10 * 60 * 1000, autoRun = true} = {}) {
  let active = null;
  let counter = 0;
  const opened = [];
  const fail = (code, reason) => ({ok: false, code, reason});
  const now = () => Date.parse(clock());

  function current(listenerRef) {
    return active && active.listener_ref === listenerRef ? active : null;
  }

  function respond({url, init, origin}) {
    const listener = active;
    const path = `/diag/${listener?.token}/report`;
    if (!listener || listener.closed || now() >= listener.expires || url !== path) return {ok: false, status: 404};
    if (origin !== listener.origin) return {ok: false, status: 403};
    if (!String(init?.headers?.['content-type'] || '').toLowerCase().startsWith('application/json')) return {ok: false, status: 415};
    if (String(init?.body || '').length > MAX_BODY_BYTES) return {ok: false, status: 413};
    let body;
    try { body = JSON.parse(init.body); } catch { return {ok: false, status: 400}; }
    if (!body || typeof body !== 'object' || Array.isArray(body)) return {ok: false, status: 400};
    if (listener.report) return {ok: false, status: 409};
    listener.report = {origin, body, received_at: clock()};
    return {ok: true, status: 204};
  }

  async function runOpenedPage({browser: override, origin} = {}) {
    if (!active?.session) throw new Error('no launched diagnostic page');
    return runDiagPage(injectSession(active.session), {origin: origin || active.origin, browser: override || browser, respond});
  }

  async function invoke(op, payload = {}) {
    if (op === 'BrowserDiagListen') {
      if (payload.environment_ref !== hostEnvironment) {
        return fail('BROWSER_DIAG_ENVIRONMENT_MISMATCH', `the default browser runs in ${hostEnvironment}, not ${payload.environment_ref}`);
      }
      if (active) active.closed = true;
      counter += 1;
      const expires = now() + Math.min(Math.max(Number(payload.ttl_ms) || ttlMs, 10_000), 15 * 60 * 1000);
      active = {
        listener_ref: `browser-diag-synthetic-${counter}`,
        token: randomBytes(16).toString('hex'),
        origin: `http://127.0.0.1:${49151 + counter}`,
        task_ref: payload.task_ref,
        environment_ref: payload.environment_ref,
        expires,
        session: null,
        report: null,
        closed: false,
      };
      return {ok: true, listener_ref: active.listener_ref, origin: active.origin, expires_at: new Date(expires).toISOString()};
    }
    if (op === 'BrowserDiagLaunch') {
      const listener = current(payload.listener_ref);
      if (!listener) return fail('BROWSER_DIAG_UNKNOWN', `${payload.listener_ref} is not the active listener`);
      if (listener.closed || now() >= listener.expires) return fail('BROWSER_DIAG_EXPIRED', `${payload.listener_ref} has already closed`);
      const session = payload.session || {};
      for (const field of ['session_ref', 'session_nonce', 'script_version']) {
        if (typeof session[field] !== 'string' || !session[field]) return fail('NATIVE_PAYLOAD_INVALID', `session.${field} is required`);
      }
      if (session.task_ref !== listener.task_ref || session.environment_ref !== listener.environment_ref) {
        return fail('NATIVE_PAYLOAD_INVALID', 'session does not match the listener');
      }
      const iceServers = (Array.isArray(session.ice_servers) ? session.ice_servers : [])
        .map((item) => ({urls: [].concat(item?.urls || []).filter((url) => /^(?:stun|turns?):/.test(url))}))
        .filter((item) => item.urls.length)
        .slice(0, 4);
      listener.session = {
        session_ref: session.session_ref,
        session_nonce: session.session_nonce,
        script_version: session.script_version,
        task_ref: listener.task_ref,
        environment_ref: listener.environment_ref,
        profile_ref: typeof session.profile_ref === 'string' ? session.profile_ref : null,
        ice_servers: iceServers,
        report_path: `/diag/${listener.token}/report`,
      };
      opened.push(`${listener.origin}/diag/${listener.token}`);
      if (autoRun) await runOpenedPage();
      return {ok: true, listener_ref: listener.listener_ref, launched: true};
    }
    if (op === 'BrowserDiagReceive') {
      const listener = current(payload.listener_ref);
      if (!listener) return fail('BROWSER_DIAG_UNKNOWN', `${payload.listener_ref} is not the active listener`);
      if (listener.report) return {ok: true, status: 'RECEIVED', ...listener.report};
      if (listener.closed || now() >= listener.expires) return {ok: true, status: 'EXPIRED'};
      return {ok: true, status: 'WAITING', expires_at: new Date(listener.expires).toISOString()};
    }
    if (op === 'BrowserDiagClose') {
      const listener = current(payload.listener_ref);
      if (listener) {
        listener.closed = true;
        active = null;
      }
      return {ok: true, closed: Boolean(listener)};
    }
    return fail('NATIVE_OP_UNKNOWN', `unknown browser diagnostic op ${op}`);
  }

  return {invoke, opened, runOpenedPage, respond, active: () => active};
}
