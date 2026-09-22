/**
 * 日志文本里的秘密：归档的秘密检测与诊断包导出脱敏共用这一份规则。
 * 替换只动秘密本身，行结构、时间、进程、目标与路由保持原样，脱敏派生件仍可按同一分类器回放。
 */
const RULES = Object.freeze([
  {name: 'pem_private_key', pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, replace: '[redacted private key]'},
  {name: 'url_userinfo', pattern: /\b([a-z][a-z0-9+.-]*:\/\/)[^\s/@"']+@/gi, replace: '$1[redacted]@'},
  {name: 'bearer', pattern: /\b(bearer\s+)[A-Za-z0-9._~+/=-]+/gi, replace: '$1[redacted]'},
  // 宿主与控制端日志是 JSON 行：键名里带秘密词的字符串值整体替换（"cookie":"sid=…"、"access_token":"…"）。
  {
    name: 'json_secret_field',
    pattern: /("[A-Za-z0-9_-]*(?:authorization|cookie|token|password|passwd|secret|api[_-]?key|credential|private[_-]?key)[A-Za-z0-9_-]*"\s*:\s*)"(?:[^"\\]|\\.)*"/gi,
    replace: '$1"[redacted]"',
  },
  {
    name: 'keyed_value',
    pattern: /\b((?:proxy-authorization|authorization|set-cookie|cookie|access[_-]?token|refresh[_-]?token|token|api[_-]?key|password|passwd|secret|private[_ -]?key)\s*[:=]\s*)("[^"]*"|[^\s,;&"]+)/gi,
    replace: '$1[redacted]',
  },
  {name: 'query_secret', pattern: /([?&](?:access_token|token|key|secret|sig|signature|password|auth)=)[^&\s"']+/gi, replace: '$1[redacted]'},
  {name: 'api_key', pattern: /\bsk-[A-Za-z0-9_-]{8,}/g, replace: '[redacted]'},
]);

/** 只提示、不替换的旧口径标记：出现即按秘密异常处理，但没有可定位的值可替换。 */
const DETECT_ONLY = Object.freeze([/private[_ -]?key/i, /\bbearer\s+/i]);

export function redactSecrets(text) {
  let output = String(text ?? '');
  let count = 0;
  const rules = [];
  for (const rule of RULES) {
    let hits = 0;
    output = output.replace(rule.pattern, (...args) => {
      hits += 1;
      const groups = args.slice(1, -2);
      return rule.replace.replace(/\$(\d)/g, (_match, index) => groups[Number(index) - 1] ?? '');
    });
    if (hits) {
      count += hits;
      rules.push(rule.name);
    }
  }
  return {text: output, count, rules};
}

/** 归档用：found 为真就不能把原文放进普通归档；redacted 为 null 表示只有提示标记、没有可替换的值。 */
export function inspectSecrets(text) {
  const redacted = redactSecrets(text);
  const flagged = redacted.count > 0 || DETECT_ONLY.some((pattern) => pattern.test(String(text ?? '')));
  return {found: flagged, redacted: redacted.count > 0 ? redacted : null};
}
