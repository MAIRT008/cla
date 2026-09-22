import {toAsciiDomain} from '../../adapters/platform/index.mjs';
import {BROAD_LABELS, CLAUDE_DOMAINS} from './constants.mjs';
import {fail} from './errors.mjs';

function isIpv4(host) {
  return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(host) && host.split('.').every((part) => Number(part) <= 255);
}

function isIpv6(host) {
  return host.includes(':') && !host.includes(' ');
}

export function normalizeHost(value) {
  let input = String(value || '').trim();
  if (!input) return {ok: false, code: 'WHITELIST_EMPTY', reason: 'host is empty'};
  if (/\s/.test(input)) return {ok: false, code: 'WHITELIST_INVALID', reason: 'host contains whitespace'};
  if (/[\\^<>{}|]/.test(input)) return {ok: false, code: 'WHITELIST_INVALID', reason: 'host contains illegal characters'};
  if (/@/.test(input) || /^[a-z][a-z0-9+.-]*:\/\/[^/]*:[^@]*@/i.test(input)) {
    return {ok: false, code: 'WHITELIST_CREDENTIALS', reason: 'credentials are not allowed'};
  }
  let match = input;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(match)) {
    try {
      const url = new URL(match);
      if (url.username || url.password) return {ok: false, code: 'WHITELIST_CREDENTIALS', reason: 'credentials are not allowed'};
      match = url.hostname;
    } catch {
      return {ok: false, code: 'WHITELIST_INVALID', reason: 'url is not a usable host'};
    }
  } else {
    match = match.split('/')[0].split('?')[0].split('#')[0];
    if (match.startsWith('[')) {
      const end = match.indexOf(']');
      if (end < 0) return {ok: false, code: 'WHITELIST_INVALID', reason: 'ipv6 host is incomplete'};
      match = match.slice(1, end);
    } else if (match.includes(':') && !isIpv6(match)) {
      const parts = match.split(':');
      if (parts.length === 2 && /^\d+$/.test(parts[1])) match = parts[0];
    }
  }
  match = match.replace(/^\./, '').replace(/\.$/, '').toLowerCase();
  if (!match) return {ok: false, code: 'WHITELIST_INVALID', reason: 'host is empty after normalization'};
  if (isIpv4(match) || isIpv6(match)) return {ok: true, host: match, kind: isIpv4(match) ? 'ipv4' : 'ipv6'};
  let ascii = match;
  try { ascii = toAsciiDomain(match); } catch { return {ok: false, code: 'WHITELIST_IDN', reason: 'internationalized domain is not expressible'}; }
  if (!ascii || ascii === 'invalid') return {ok: false, code: 'WHITELIST_IDN', reason: 'internationalized domain is not expressible'};
  if (ascii.split('.').some((label) => !label || label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) {
    return {ok: false, code: 'WHITELIST_INVALID', reason: 'host labels are invalid'};
  }
  const labels = ascii.split('.');
  if (labels.length < 2 || BROAD_LABELS.has(ascii) || BROAD_LABELS.has(labels.at(-1)) && labels.length === 1) {
    return {ok: false, code: 'WHITELIST_BROAD', reason: 'suffix is too broad to express as a direct exception'};
  }
  return {ok: true, host: ascii, unicode: match !== ascii ? match : undefined, kind: 'domain'};
}

export function matchesHost(host, entry) {
  const normalized = normalizeHost(host);
  if (!normalized.ok) return false;
  if (entry.match === 'exact') return normalized.host === entry.host;
  return normalized.host === entry.host || normalized.host.endsWith(`.${entry.host}`);
}

export function claudeConflict(entry, claudeDomains = CLAUDE_DOMAINS) {
  const domains = claudeDomains.map((domain) => domain.toLowerCase());
  return domains.some((domain) => {
    const coversClaude = entry.host === domain || domain.endsWith(`.${entry.host}`);
    const isClaudeHost = entry.host === domain || entry.host.endsWith(`.${domain}`);
    if (entry.match === 'exact') return isClaudeHost;
    return isClaudeHost || coversClaude;
  });
}

function nextId(entries) {
  const used = new Set(entries.map((entry) => entry.entry_id));
  let index = entries.length + 1;
  while (used.has(`wl-${index}`)) index += 1;
  return `wl-${index}`;
}

function cloneList(list) {
  return {
    whitelist_id: list.whitelist_id,
    user_ref: list.user_ref,
    version: list.version || 1,
    template_version: list.template_version || null,
    user_version: list.user_version || 1,
    entries: (list.entries || []).map((entry) => ({...entry})),
  };
}

export function emptyWhitelist({userRef, whitelistId, templateVersion} = {}) {
  return {
    whitelist_id: whitelistId || `wl-${userRef || 'unknown'}`,
    user_ref: userRef || null,
    version: 1,
    template_version: templateVersion || null,
    user_version: 1,
    entries: [],
  };
}

export function normalizeWhitelist(entries, options = {}) {
  const previous = options.previous ? cloneList(options.previous) : emptyWhitelist(options);
  const incoming = Array.isArray(entries) ? entries : [];
  const normalized = [];
  const errors = [];
  incoming.forEach((raw, index) => {
    const source = typeof raw === 'string' ? {input: raw} : raw || {};
    const matchHint = source.match === 'subdomains' || String(source.input || source.host || '').startsWith('*.') ? 'subdomains' : source.match === 'exact' ? 'exact' : options.defaultMatch || 'exact';
    const input = String(source.input || source.host || '').replace(/^\*\./, '');
    const host = normalizeHost(input);
    if (!host.ok) {
      errors.push({index, input: source.input || source.host || '', code: host.code, reason: host.reason});
      return;
    }
    const entry = {
      entry_id: source.entry_id || nextId([...previous.entries, ...normalized]),
      host: host.host,
      match: matchHint,
      enabled: source.enabled !== false,
      source: source.source || 'user',
      input: source.input || source.host || input,
    };
    if (claudeConflict(entry, options.claudeDomains)) {
      errors.push({index, input: entry.input, code: 'WHITELIST_CLAUDE_CONFLICT', reason: 'Claude protected names cannot be covered by the ordinary whitelist'});
      return;
    }
    if (normalized.some((item) => item.host === entry.host && item.match === entry.match)) return;
    normalized.push(entry);
  });
  if (errors.length && options.replace === true) {
    return {ok: false, code: errors[0].code, reason: errors[0].reason, errors, whitelist: previous};
  }
  const whitelist = cloneList(previous);
  if (options.replace === true) whitelist.entries = normalized;
  whitelist.version = (previous.version || 1) + (options.bump === false ? 0 : 1);
  whitelist.user_version = (previous.user_version || 1) + (options.bump === false ? 0 : 1);
  if (options.replace !== true) whitelist.entries = normalized;
  return {ok: errors.length === 0, errors, whitelist: options.replace === true ? whitelist : {...whitelist, entries: normalized}};
}

export function mutateWhitelist(current, action, payload = {}, options = {}) {
  const list = current ? cloneList(current) : emptyWhitelist(options);
  const original = cloneList(list);
  try {
    if (action === 'add') {
      const parsed = normalizeWhitelist([payload], {previous: list, claudeDomains: options.claudeDomains, defaultMatch: payload.match});
      if (!parsed.ok) throw fail(parsed.errors[0].code, parsed.errors[0].reason, {errors: parsed.errors, whitelist: original});
      const next = parsed.whitelist.entries[0];
      if (list.entries.some((entry) => entry.host === next.host && entry.match === next.match)) return {ok: true, whitelist: original, impact: {unchanged: true}};
      list.entries.push(next);
    } else if (action === 'remove') {
      list.entries = list.entries.filter((entry) => entry.entry_id !== payload.entry_id && !(payload.host && entry.host === payload.host && entry.match === (payload.match || entry.match)));
    } else if (action === 'enable' || action === 'disable') {
      const target = list.entries.find((entry) => entry.entry_id === payload.entry_id);
      if (!target) throw fail('WHITELIST_NOT_FOUND', 'whitelist entry does not exist', {whitelist: original});
      target.enabled = action === 'enable';
    } else if (action === 'restore_default') {
      list.entries = (options.defaultEntries || []).map((entry, index) => ({
        entry_id: entry.entry_id || `wl-default-${index + 1}`,
        host: normalizeHost(entry.host).host,
        match: entry.match || 'exact',
        enabled: entry.enabled !== false,
        source: 'template',
        input: entry.input || entry.host,
      }));
    } else {
      throw fail('WHITELIST_ACTION_INVALID', `unsupported whitelist action ${action}`, {whitelist: original});
    }
  } catch (error) {
    if (error.whitelist) throw error;
    throw fail(error.code || 'WHITELIST_INVALID', error.message, {whitelist: original, errors: error.errors});
  }
  list.version += 1;
  list.user_version += 1;
  return {
    ok: true,
    whitelist: list,
    impact: {
      enabled_in_daily: list.entries.filter((entry) => entry.enabled),
      retained_in_dedicated: true,
      active_in_current_mode: options.mode === 'daily_single_ip',
    },
  };
}

export function activeWhitelist(list, mode) {
  if (mode !== 'daily_single_ip') return [];
  return (list?.entries || []).filter((entry) => entry.enabled);
}
