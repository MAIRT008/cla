import {fail} from './errors.mjs';
import {dumpMihomoConfig, parseMihomoConfig} from './yaml.mjs';

export function publicProxies(proxies = []) {
  return proxies.map((proxy) => {
    const copy = {...proxy};
    delete copy.username;
    delete copy.password;
    return copy;
  });
}

export function resolveManagedPayload(config, secrets) {
  if (!config || typeof config !== 'object') throw fail('CONFIG_STATIC_INVALID', 'managed config is required');
  const resolved = structuredClone(config);
  for (const proxy of resolved.proxies || []) {
    const ref = proxy.credential_ref;
    delete proxy.credential_ref;
    if (!ref) throw fail('CREDENTIAL_UNAVAILABLE', `proxy ${proxy.name} has no credential_ref`);
    const cred = secrets?.resolve?.(ref);
    if (!cred || typeof cred.username !== 'string' || !cred.username) {
      throw fail('CREDENTIAL_UNAVAILABLE', `restricted secret for ${ref} is unavailable`);
    }
    proxy.username = cred.username;
    if (typeof cred.password === 'string') proxy.password = cred.password;
  }
  return dumpMihomoConfig(resolved);
}

export function resolveYamlPayload(yaml, secrets) {
  return resolveManagedPayload(typeof yaml === 'string' ? parseMihomoConfig(yaml) : yaml, secrets);
}

export function containsSecretMaterial(text) {
  return /password:\s*(?!ref:)\S+/i.test(String(text || ''));
}
