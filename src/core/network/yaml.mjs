const VENDOR_RELATIVE = '../../../vendor/deps/js-yaml-4.3.0';

let installed = null;
let yamlRoot = VENDOR_RELATIVE;

/**
 * Hosts without node:module (the packaged WebView) install the same fixed js-yaml
 * build before any network configuration is compiled.
 */
export function installYamlLibrary(library, {root = VENDOR_RELATIVE} = {}) {
  if (!library?.dump || !library?.load) throw Object.assign(new Error('yaml library must expose dump and load'), {code: 'YAML_LIBRARY_INVALID'});
  installed = library;
  yamlRoot = root;
  return library;
}

if (typeof process !== 'undefined' && process.versions?.node) {
  const [{createRequire}, nodePath, {fileURLToPath}] = await Promise.all([
    import('node:module'),
    import('node:path'),
    import('node:url'),
  ]);
  const resolved = nodePath.resolve(nodePath.dirname(fileURLToPath(import.meta.url)), VENDOR_RELATIVE);
  installed = createRequire(import.meta.url)(nodePath.join(resolved, 'index.js'));
  yamlRoot = resolved;
}

function library() {
  if (installed) return installed;
  throw Object.assign(new Error('fixed js-yaml build is not installed for this host'), {code: 'YAML_LIBRARY_MISSING'});
}

const yaml = new Proxy({}, {get: (_target, key) => library()[key]});

const DUMP_OPTIONS = Object.freeze({
  lineWidth: -1,
  noRefs: true,
  quotingType: '"',
  forceQuotes: false,
  sortKeys: false,
});

export function dumpYaml(value) {
  return yaml.dump(value, DUMP_OPTIONS).replace(/\n+$/, '');
}

export function dumpMihomoConfig(config) {
  return `${yaml.dump(config, DUMP_OPTIONS)}`;
}

export function parseYaml(text) {
  const value = yaml.load(String(text), {schema: yaml.DEFAULT_SCHEMA, json: true});
  return value == null ? {} : value;
}

export function parseMihomoConfig(text) {
  return parseYaml(text);
}

export const YAML_LIBRARY = Object.freeze({
  name: 'js-yaml',
  version: '4.3.0',
  get root() { return yamlRoot; },
});
