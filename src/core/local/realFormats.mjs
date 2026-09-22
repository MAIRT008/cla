/**
 * 真实客户端文件格式的识别规则（FD-01 F09、F12、F14、F15）。
 *
 * 只从宿主发现声明过角色的对象里取事实；取出的是身份的脱敏标签、字段位置和非机密的来源信息，
 * 凭据、Cookie 值、Token 与邮箱原文都不离开这里。
 */

/** 真实格式的 JSON 角色，以及每个角色里允许按字段处理的位置。 */
export const REAL_JSON_ROLES = Object.freeze({
  claude_code_state: ['oauthAccount'],
  claude_code_credentials: ['claudeAiOauth'],
  claude_desktop_config: ['oauth:tokenCache'],
});

function fnv(text) {
  let state = 2166136261;
  for (let index = 0; index < text.length; index += 1) state = Math.imul(state ^ text.charCodeAt(index), 16777619);
  return (state >>> 0).toString(16).padStart(8, '0');
}

export function maskEmail(email) {
  if (typeof email !== 'string' || !email.includes('@')) return null;
  const [name, domain] = email.split('@');
  return `${name.slice(0, 1)}***@${domain}`;
}

function tail(value) {
  return typeof value === 'string' && value.length >= 4 ? `…${value.slice(-4)}` : null;
}

/**
 * Claude Code 登录账号：accountUuid 与 organizationUuid 一起定一个身份。
 * 引用与指纹都由这两个标识派生，同一账号换一次扫描不需要重新回答。
 */
export function claudeAccountIdentity(oauthAccount) {
  if (!oauthAccount || typeof oauthAccount !== 'object') return null;
  const account = typeof oauthAccount.accountUuid === 'string' ? oauthAccount.accountUuid : '';
  const organization = typeof oauthAccount.organizationUuid === 'string' ? oauthAccount.organizationUuid : '';
  if (!account && !organization) return null;
  const stableKey = `claude-account:${account}:${organization}`;
  const email = maskEmail(oauthAccount.emailAddress);
  const organizationTail = tail(organization);
  return {
    identity_ref: `claude-account-${fnv(stableKey)}`,
    kind: 'claude_account',
    label: `Claude 账号 ${email || tail(account) || '（未记录邮箱）'}${organizationTail ? ` · 组织 ${organizationTail}` : ''}`,
    stable_key: stableKey,
  };
}

/** 浏览器 Profile 或 Claude Desktop 里的 Claude 网站登录：Cookie 值加密、读不出账号，按「这个位置的登录」请用户回答。 */
export function siteLoginIdentity(client) {
  const rootRef = String(client?.path_prefix || '').replace(/^roots\//, '');
  if (!rootRef) return null;
  const where = client.label || rootRef;
  return {
    identity_ref: `site-login-${rootRef}`,
    kind: 'site_login',
    label: `${where} 中的 Claude 网站登录`,
    stable_key: `site-login:${rootRef}`,
  };
}

export function endpointHost(url) {
  if (typeof url !== 'string' || !url.trim()) return null;
  try {
    return new URL(url.trim()).hostname.toLowerCase() || null;
  } catch {
    return null;
  }
}

export function isClaudeSiteHost(hostKey, siteHosts) {
  const host = String(hostKey || '').replace(/^\./, '').toLowerCase();
  return siteHosts.some((site) => host === site || host.endsWith(`.${site}`));
}

function hasText(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

/**
 * 按声明角色读一份真实 JSON。
 * - identities：直接写在文件里的身份；
 * - direct_items：直接归属到这些身份的可处理字段；
 * - credential_items：凭据字段，文件里没有账号标识，要在整次扫描里按同一客户端归属，归属不出来就不进推荐；
 * - third_party_sources：第三方端点的来源与是否生效，只报告不清理。
 */
export function readRealJson(role, value) {
  const facts = {identities: [], direct_items: [], credential_items: [], third_party_sources: []};
  if (!value || typeof value !== 'object' || Array.isArray(value)) return facts;
  if (role === 'claude_code_state') {
    const identity = claudeAccountIdentity(value.oauthAccount);
    if (identity) {
      facts.identities.push(identity);
      facts.direct_items.push({field_path: 'oauthAccount', identity_ref: identity.identity_ref, evidence: 'direct'});
    }
  } else if (role === 'claude_code_credentials') {
    if (value.claudeAiOauth && typeof value.claudeAiOauth === 'object') facts.credential_items.push({field_path: 'claudeAiOauth'});
  } else if (role === 'claude_desktop_config') {
    if (hasText(value['oauth:tokenCache'])) facts.credential_items.push({field_path: 'oauth:tokenCache'});
  } else if (role === 'claude_code_settings') {
    const env = value.env && typeof value.env === 'object' ? value.env : {};
    const host = endpointHost(env.ANTHROPIC_BASE_URL);
    if (host) {
      facts.third_party_sources.push({
        source: 'claude_code_settings',
        field_path: 'env.ANTHROPIC_BASE_URL',
        endpoint_host: host,
        active: true,
        credential_present: hasText(env.ANTHROPIC_AUTH_TOKEN) || hasText(env.ANTHROPIC_API_KEY),
      });
    }
  }
  return facts;
}

/** CC Switch Provider 的第三方来源：只取名称、端点主机、是否当前使用和是否带凭据。 */
export function ccSwitchSources(providers = []) {
  return providers
    .filter((provider) => provider.endpoint_host)
    .map((provider) => ({
      source: 'cc_switch',
      provider_id: provider.provider_id,
      app_type: provider.app_type,
      name: provider.name || null,
      endpoint_host: provider.endpoint_host,
      active: provider.is_current === true,
      credential_present: provider.credential_present === true,
    }));
}
