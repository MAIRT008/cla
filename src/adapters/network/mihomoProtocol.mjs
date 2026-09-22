import {comparableFromConfig, ruleToComparable} from '../../core/network/compile.mjs';
import {parseMihomoConfig} from '../../core/network/yaml.mjs';

export const MIHOMO_PROTOCOL = Object.freeze({
  source: 'Mihomo v1.19.30',
  commit: 'ac017cdd246ce8bd547653d927e7bf77d7ee73d5',
  files: {
    configs: 'hub/route/configs.go',
    server: 'hub/route/server.go',
    rules: 'hub/route/rules.go',
    proxies: 'hub/route/proxies.go',
    connections: 'hub/route/connections.go',
  },
});

function json(value) {
  if (typeof value === 'string') {
    try { return JSON.parse(value); } catch { return null; }
  }
  return value ?? null;
}

export function encodeAuthorization(secret) {
  if (!secret) return {};
  return {Authorization: `Bearer ${secret}`};
}

export function encodePutConfigs({payload, path, force = true, secret} = {}) {
  const query = force === true || force === 'true' ? '?force=true' : '';
  const body = payload != null && payload !== '' ? {payload: String(payload)} : {path: path || ''};
  return {
    method: 'PUT',
    url: `/configs${query}`,
    headers: {'Content-Type': 'application/json', ...encodeAuthorization(secret)},
    body,
  };
}

export function decodePutConfigs(response) {
  const status = response?.status ?? response?.statusCode;
  if (status === 204) {
    return {http_status: 204, accepted: true, loaded_version: null, body: null};
  }
  return {
    http_status: status || 0,
    accepted: false,
    loaded_version: null,
    error: json(response?.body) || {message: response?.statusText || 'config load failed'},
  };
}

export function encodeGet(path, {secret, query} = {}) {
  const suffix = query ? `?${new URLSearchParams(query).toString()}` : '';
  return {method: 'GET', url: `${path}${suffix}`, headers: encodeAuthorization(secret)};
}

export function decodeGetConfigs(response) {
  const body = json(response?.body) || {};
  const projected = {
    mode: body.mode ?? null,
    port: body.port ?? null,
    'socks-port': body['socks-port'] ?? null,
    'mixed-port': body['mixed-port'] ?? null,
    tun: body.tun ? {enable: Boolean(body.tun.enable), stack: body.tun.stack || null} : null,
    ipv6: body.ipv6 ?? null,
    'find-process-mode': body['find-process-mode'] ?? null,
    'interface-name': body['interface-name'] ?? null,
    'log-level': body['log-level'] ?? null,
  };
  return {
    http_status: response?.status || 200,
    general: projected,
    loaded_version: null,
    sensitive_omitted: ['authentication', 'ss-config', 'vmess-config'],
  };
}

export function decodeGetRules(response) {
  const body = json(response?.body) || {};
  return {http_status: response?.status || 200, rules: Array.isArray(body.rules) ? body.rules : []};
}

export function decodeGetProxies(response) {
  const body = json(response?.body) || {};
  return {http_status: response?.status || 200, proxies: body.proxies && typeof body.proxies === 'object' ? body.proxies : {}};
}

export function decodeGetVersion(response) {
  const body = json(response?.body) || {};
  return {http_status: response?.status || 200, meta: body.meta ?? null, version: body.version ?? null, product_plan_version: null};
}

export function decodeConnectionsSnapshot(response) {
  const body = json(response?.body) || {};
  return {
    http_status: response?.status || 200,
    downloadTotal: body.downloadTotal ?? 0,
    uploadTotal: body.uploadTotal ?? 0,
    memory: body.memory ?? null,
    connections: Array.isArray(body.connections) ? body.connections : [],
  };
}

export function encodeDeleteConnections({id, secret} = {}) {
  return {method: 'DELETE', url: id ? `/connections/${id}` : '/connections', headers: encodeAuthorization(secret)};
}

export function decodeDeleteConnections(response) {
  return {http_status: response?.status || 204, closed_existing: response?.status === 204, blocks_new_connections: false};
}

export function decodeTrafficSample(payload) {
  const body = json(payload) || {};
  return {
    up: body.up ?? null,
    down: body.down ?? null,
    upTotal: body.upTotal ?? null,
    downTotal: body.downTotal ?? null,
    user_quota: null,
  };
}

export function decodeLogLine(payload, {format} = {}) {
  const body = json(payload) || {};
  if (format === 'structured') {
    return {time: body.time || null, level: body.level || null, message: body.message || null, fields: Array.isArray(body.fields) ? body.fields : [], iso_event_time: null};
  }
  return {type: body.type || null, payload: body.payload || null};
}

export function encodeWsUrl(path, {baseUrl, secret, tokenInQuery = false} = {}) {
  if (!baseUrl) throw Object.assign(new Error('Mihomo transport base URL is required'), {code: 'CORE_UNAVAILABLE'});
  const url = new URL(path, baseUrl);
  if (tokenInQuery && secret) url.searchParams.set('token', secret);
  return url.toString();
}

export function comparableFromReadback({general, rules, proxies}) {
  return {
    mode: general?.mode || null,
    ipv6: general?.ipv6 !== false,
    tun: {enable: Boolean(general?.tun?.enable)},
    rules: (rules || []).map((rule, index) => ({index: rule.index ?? index, type: rule.type, payload: rule.payload, proxy: rule.proxy})),
    proxy_names: Object.keys(proxies || {}),
  };
}

export function rulesFromYaml(yaml) {
  const config = typeof yaml === 'string' ? parseMihomoConfig(yaml) : yaml;
  return (config.rules || []).map((rule, index) => {
    const comparable = ruleToComparable(rule, index);
    return {index, type: comparable.type, payload: comparable.payload, proxy: comparable.proxy, size: -1};
  });
}

export function proxiesFromYaml(yaml) {
  const config = typeof yaml === 'string' ? parseMihomoConfig(yaml) : yaml;
  const result = {};
  for (const proxy of config.proxies || []) result[proxy.name] = {name: proxy.name, type: proxy.type, now: undefined, all: undefined};
  for (const group of config['proxy-groups'] || []) result[group.name] = {name: group.name, type: group.type, now: group.proxies?.[0], all: group.proxies};
  return result;
}

export function generalFromYaml(yaml) {
  const config = typeof yaml === 'string' ? parseMihomoConfig(yaml) : yaml;
  return {
    mode: config.mode || 'rule',
    tun: {enable: Boolean(config.tun?.enable), stack: config.tun?.stack || null},
    ipv6: config.ipv6 !== false,
    'find-process-mode': config['find-process-mode'] || 'always',
    'log-level': config['log-level'] || 'info',
    'mixed-port': config['mixed-port'] ?? 0,
    port: config.port ?? 0,
    'socks-port': config['socks-port'] ?? 0,
  };
}

export function digestConfig(yaml) {
  return comparableFromConfig(typeof yaml === 'string' ? parseMihomoConfig(yaml) : yaml);
}
