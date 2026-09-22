import {createEchoAdapter} from './echo.mjs';
import {createProbeAdapter} from './probe.mjs';
import {createSettingsPort} from './world.mjs';

/**
 * 正式桌面的诊断端口：证据来自 WebView 自己的 fetch、navigator、WebRTC 与 Intl。
 * 探测服务地址由宿主/控制端给出；没有配置的那一类保持 configured=false，
 * 诊断会把它记成覆盖缺口，不用别的证据顶替。
 */
export function createBrowserDiagnosticPorts({
  fetchImpl,
  navigator: navigatorRef,
  rtcPeerConnection = null,
  intl = null,
  services = {},
  clientKind = 'webview',
  iceServers = [],
  systemDns = null,
  networkState = null,
  settings = null,
} = {}) {
  const probeState = {};
  return {
    echo: createEchoAdapter({fetchImpl, url: services.echo_url || null}),
    intel: {url: services.intel_url || null, fetch: fetchImpl, configured: Boolean(fetchImpl && services.intel_url)},
    doh: {url: services.doh_url || null, fetch: fetchImpl, configured: Boolean(fetchImpl && services.doh_url)},
    probe: createProbeAdapter({state: probeState, fetchImpl, baseUrl: services.probe_base_url || null}),
    ipv6: services.ipv6 || {status: 'NO_RESULT'},
    navigator: navigatorRef || null,
    clientKind,
    fingerprint: createBrowserFingerprintPort(),
    peerConnection: rtcPeerConnection,
    iceServers,
    claudeHttp: {url: services.claude_url || 'https://api.anthropic.com/'},
    claude: createClaudeProbePort({fetchImpl, services}),
    intl: intl || (typeof Intl === 'object' ? Intl : null),
    networkState: networkState || {status: 'UNKNOWN', core: 'UNKNOWN', protection: {status: 'UNKNOWN'}, chain_unavailable: false},
    system: {dns: systemDns || {servers: [], status: 'NOT_DECLARED'}},
    settings: settings || createSettingsPort(),
  };
}

/** 指纹取样只读 WebView 自己暴露的画布、WebGL、音频与屏幕参数，不装插件、不读 Profile。 */
function createBrowserFingerprintPort() {
  const documentRef = typeof document === 'object' ? document : null;
  if (!documentRef?.createElement) return null;
  let canvas = null;
  let webgl = null;
  try {
    canvas = documentRef.createElement('canvas').getContext('2d');
    const gl = documentRef.createElement('canvas');
    webgl = gl.getContext?.('webgl') || gl.getContext?.('experimental-webgl') || null;
  } catch {
    canvas = null;
    webgl = null;
  }
  return {
    canvas,
    webgl,
    audio: null,
    screen: typeof screen === 'object'
      ? {width: screen.width, height: screen.height, colorDepth: screen.colorDepth, devicePixelRatio: globalThis.devicePixelRatio || 1}
      : null,
  };
}

/** 四步 Claude 可达性取样：每一步都是一次真实请求，失败按原因码记，不猜。 */
function createClaudeProbePort({fetchImpl, services}) {
  const target = services.claude_url || 'https://api.anthropic.com/';
  if (typeof fetchImpl !== 'function') return null;
  async function timed(url, init) {
    const started = Date.now();
    const response = await fetchImpl(url, init);
    return {ms: Date.now() - started, status: Number(response.status) || 0};
  }
  return {
    async dns({signal} = {}) {
      if (!services.doh_url) return {status: 'NOT_CONFIGURED', ms: null};
      const result = await timed(services.doh_url, {signal, headers: {accept: 'application/dns-json'}});
      return {status: result.status >= 400 ? 'FAILED' : 'OBSERVED', ms: result.ms, http_status: result.status};
    },
    async connect({signal} = {}) {
      const result = await timed(target, {signal, method: 'HEAD'});
      return {status: result.status === 0 ? 'FAILED' : 'OBSERVED', ms: result.ms, http_status: result.status};
    },
    async tls({signal} = {}) {
      const result = await timed(target, {signal, method: 'HEAD'});
      // WebView 不暴露握手细节：只记可达与限制，不伪造 ALPN、证书摘要或 JA3。
      return {status: result.status === 0 ? 'FAILED' : 'OBSERVED', alpn: null, certificate_digest: null, ja3: null, source: 'webview', limitation: 'TLS_DETAIL_NOT_EXPOSED', http_status: result.status};
    },
    async http({signal} = {}) {
      const result = await timed(target, {signal});
      return {status: result.status === 0 ? 'FAILED' : 'OBSERVED', status_code: result.status, ms: result.ms};
    },
  };
}
