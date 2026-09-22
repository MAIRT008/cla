const IPV4 = /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
const IPV6 = /^(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}$/i;

export function parseIPv4(value) {
  const text = String(value || '').trim();
  return IPV4.test(text) ? text : null;
}

export function parseIPv6(value) {
  const text = String(value || '').trim();
  if (!text || text.includes('.')) return null;
  return IPV6.test(text) ? text : null;
}

export function parseIP(value) {
  return parseIPv4(value) || parseIPv6(value);
}

export function parsePublicIPBody(text, limit = 8192) {
  const raw = String(text || '').slice(0, limit).trim();
  if (!raw) return {ok: false, code: 'EMPTY_BODY'};
  const direct = parseIP(raw.split(/\s+/)[0]);
  if (direct) return {ok: true, ip: direct, format: 'text'};
  try {
    const json = JSON.parse(raw);
    const ip = parseIP(json.ip || json.query || json.origin || json.address);
    if (!ip) return {ok: false, code: 'IP_MISSING', json};
    return {
      ok: true,
      ip,
      format: 'json',
      country: json.country || json.country_name || null,
      country_code: json.country_code || json.countryCode || json.country_code2 || null,
      asn: normalizeAsn(json.asn || json.connection?.asn),
      organization: json.org || json.organization || json.connection?.org || json.connection?.isp || json.isp || null,
      success: json.success,
    };
  } catch {
    return {ok: false, code: 'UNPARSEABLE'};
  }
}

export function normalizeAsn(value) {
  if (value == null || value === '') return null;
  const text = String(value).replace(/^AS/i, '');
  const n = Number(text);
  return Number.isFinite(n) ? `AS${n}` : null;
}

export function parseDoHJSON(body) {
  if (!body || typeof body !== 'object') return {ok: false, code: 'INVALID_DOH', status: null, answers: []};
  const status = Number.isFinite(body.Status) ? body.Status : null;
  const answers = Array.isArray(body.Answer) ? body.Answer.map((item) => ({name: item.name, type: item.type, data: item.data})).filter((item) => item.data) : [];
  if (status !== 0) return {ok: false, code: 'DOH_STATUS', status, answers, error: true};
  if (!answers.length) return {ok: false, code: 'DOH_NO_ANSWER', status, answers};
  return {ok: true, status, answers, ips: answers.map((item) => parseIP(item.data)).filter(Boolean)};
}

export function parseTlsInfo(value) {
  if (!value || typeof value !== 'object') return {status: 'UNAVAILABLE', alpn: null, certificate_digest: null, ja3: 'UNAVAILABLE', ja4: 'UNAVAILABLE'};
  return {
    status: 'OBSERVED',
    alpn: value.alpn || value.negotiatedProtocol || null,
    certificate_digest: value.certificate_digest || value.fingerprint || null,
    issuer: value.issuer || null,
    ja3: value.ja3 || 'UNAVAILABLE',
    ja4: value.ja4 || 'UNAVAILABLE',
    source: value.source || null,
  };
}

export function timezoneMatch({iana, offsetMinutes, expectedIana, expectedOffsetMinutes}) {
  const name = iana && expectedIana ? iana === expectedIana : null;
  const offset = Number.isFinite(offsetMinutes) && Number.isFinite(expectedOffsetMinutes) ? offsetMinutes === expectedOffsetMinutes : null;
  return {
    iana_equal: name,
    offset_equal: offset,
    same_zone: name === true,
    offset_only_not_same_zone: offset === true && name !== true,
  };
}

export function classifyIceCandidate(candidate) {
  const text = typeof candidate === 'string' ? candidate : candidate?.candidate || '';
  const type = / typ (\w+)/.exec(text)?.[1] || candidate?.type || 'unknown';
  const address = / (\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f:]+|\S+\.local) /.exec(` ${text} `)?.[1] || candidate?.address || null;
  const family = parseIPv6(address) ? 'ipv6' : parseIPv4(address) ? 'ipv4' : address?.endsWith('.local') ? 'mdns' : 'unknown';
  return {type, address, family, host: type === 'host', srflx: type === 'srflx', relay: type === 'relay', mdns: family === 'mdns' || Boolean(address?.endsWith('.local'))};
}
