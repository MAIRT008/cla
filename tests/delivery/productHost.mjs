import {encodeGet} from '../../src/adapters/network/mihomoProtocol.mjs';

/**
 * 宿主边界替身：只提供真实 WebView 会拿到的东西——一个 fetch。
 * 它按目标主机分流到「控制端」和「受管内核」，不把任何组合根参数塞进页面。
 */
export function createHostFetch({controlBaseUrl, controlHandler, coreControllerUrl, core, probes = {}}) {
  const controlHost = new URL(controlBaseUrl).host;
  const coreHost = coreControllerUrl ? new URL(coreControllerUrl).host : null;
  const calls = [];

  function coreResponse(status, body) {
    const text = body === null || body === undefined ? '' : typeof body === 'string' ? body : JSON.stringify(body);
    return {
      status,
      ok: status < 400,
      async text() { return text; },
      async json() { return text ? JSON.parse(text) : null; },
    };
  }

  /**
   * 受管探测服务的替身：每个环境一段独立的路径前缀，回报各自的出口与解析器。
   * 它站在真实探测服务的位置上，属于宿主边界，不是组合根参数。
   */
  function probeResponse(url) {
    const segment = url.pathname.split('/')[2];
    const profile = probes[segment];
    if (!profile) return coreResponse(404, {message: `no probe service is published at ${url.pathname}`});
    const rest = url.pathname.slice(`/probe/${segment}`.length);
    if (rest.endsWith('/ip') || rest.includes('echo')) {
      return coreResponse(200, {ip: profile.ip, country: 'United States', country_code: 'US', asn: profile.asn, org: profile.org});
    }
    if (rest.includes('dns-query') || rest.includes('doh')) {
      return coreResponse(200, {Status: 0, Answer: [{name: 'api.anthropic.com.', type: 1, data: profile.doh_ip || profile.ip}]});
    }
    if (rest.endsWith('/v1/session')) {
      return coreResponse(200, {token: `probe-${segment}`, dns_name: `${segment}.once.synthetic.invalid.`, expires_in: 30});
    }
    if (rest.includes('/observe')) {
      return coreResponse(200, {ip: profile.ip, country_code: 'US', asn: profile.asn, organization: profile.org});
    }
    if (rest.includes('/dns')) {
      return coreResponse(200, {observed: true, resolver_ip: profile.resolver, country_code: 'US'});
    }
    return coreResponse(404, {message: 'unknown probe endpoint'});
  }

  const fetchImpl = async (input, init = {}) => {
    const url = new URL(String(input));
    calls.push({host: url.host, path: url.pathname, method: init.method || 'GET'});
    if (url.host === controlHost && url.pathname.startsWith('/probe/')) {
      return probeResponse(url);
    }
    if (url.host === controlHost) {
      return controlHandler.handle(new Request(url.href, init));
    }
    if (coreHost && url.host === coreHost) {
      const response = await core.request({
        method: init.method || 'GET',
        url: `${url.pathname}${url.search}`,
        body: init.body ? JSON.parse(init.body) : undefined,
      });
      return coreResponse(response.status, response.body);
    }
    return coreResponse(404, {message: `no host is reachable at ${url.host}`});
  };
  fetchImpl.calls = calls;
  fetchImpl.probeEncoding = encodeGet;
  return fetchImpl;
}

/** 已就绪的控制端状态，形状与 Rust 宿主 ControlSupervisor::status() 一致。 */
export function readyControl(baseUrl) {
  return {status: 'ready', mode: 'managed', protocol: 'steward-control-1', instance_ref: 'ctl-synthetic', base_url: baseUrl, log_status: 'ok', error: null};
}

/**
 * 旧 Node 控制端基线没有首启与身份接口。这是站在 Rust 控制端位置上的替身路由：
 * /api/setup/status 回已初始化，/api/auth/me 用基线自己的会话校验回答身份与服务端角色，
 * 其余请求原样交给基线。它只让四模块既有用例在新的身份接口下继续跑，不证明 Rust 认证已运行。
 */
/**
 * 站在 control-rs 的位置补上 Node 基线没有的接口：首启状态、身份，以及管理员配置好的分环境探测服务地址
 * （probes.rs 的 /api/network/probe-services，登录后才给）。
 */
export function withIdentityRoutes(prepared, {probeServices = {}} = {}) {
  return {
    async handle(request) {
      const {pathname} = new URL(request.url);
      if (request.method === 'GET' && pathname === '/api/setup/status') return Response.json({initialized: true});
      if (request.method === 'GET' && pathname === '/api/network/probe-services') {
        try {
          prepared.controlAuth.authenticate(request);
        } catch {
          return Response.json({code: 'AUTH_SESSION_INVALID', reason: '登录会话已失效，请重新登录'}, {status: 401});
        }
        return Response.json({environments: structuredClone(probeServices)});
      }
      if (request.method === 'GET' && pathname === '/api/auth/me') {
        try {
          const actor = prepared.controlAuth.authenticate(request);
          return Response.json({user_ref: actor.user_ref, username: actor.user_ref, role: actor.role, status: actor.status, expires_at: '2030-01-01T00:00:00.000Z'});
        } catch {
          return Response.json({code: 'AUTH_SESSION_INVALID', reason: '登录会话已失效，请重新登录'}, {status: 401});
        }
      }
      return prepared.handler.handle(request);
    },
  };
}

/** 上次登录后由宿主保管下来的会话；四模块用例从这里开始，不重复走登录流程。 */
export const PERSISTED_MAX_SESSION = Object.freeze({access_token: 'token-max', expires_at: '2030-01-01T00:00:00.000Z', user_ref: 'user-max'});
