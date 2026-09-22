import {readFile} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import vm from 'node:vm';
import {createDesktopComposition} from '../../apps/desktop-ui/compose.mjs';
import {createStewardHost} from '../../apps/desktop-ui/host.mjs';

class TokenList {
  constructor(value = '') {
    this._set = new Set(String(value).split(/\s+/).filter(Boolean));
  }
  contains(name) { return this._set.has(name); }
  add(name) { this._set.add(name); }
  remove(name) { this._set.delete(name); }
  toggle(name) {
    if (this._set.has(name)) this._set.delete(name);
    else this._set.add(name);
    return this._set.has(name);
  }
  toString() { return [...this._set].join(' '); }
}

class MiniNode {
  constructor(tag, attrs = {}, document = null) {
    this.tagName = String(tag || 'div').toUpperCase();
    this.attrs = {...attrs};
    this.document = document;
    this.children = [];
    this.parent = null;
    this.listeners = {};
    this._text = '';
    this._value = attrs.value || '';
    this.checked = attrs.checked === '' || attrs.checked === 'checked' || attrs.checked === true;
    this.hidden = Object.prototype.hasOwnProperty.call(attrs, 'hidden');
    this.classList = new TokenList(attrs.class || '');
    this.style = {};
    this.dataset = {};
    for (const [key, value] of Object.entries(attrs)) {
      if (key.startsWith('data-')) this.dataset[key.slice(5)] = value;
    }
  }
  get id() { return this.attrs.id || ''; }
  set id(value) { this.attrs.id = String(value ?? ''); }
  get className() { return this.classList.toString(); }
  get textContent() { return this._text || this.children.map((child) => child.textContent).join(''); }
  set textContent(value) { this._text = String(value ?? ''); this.children = []; }
  get value() { return this._value; }
  set value(value) { this._value = String(value ?? ''); this.attrs.value = this._value; }
  get type() { return this.attrs.type || ''; }
  set type(value) { this.attrs.type = String(value ?? ''); }
  get name() { return this.attrs.name || ''; }
  set name(value) { this.attrs.name = String(value ?? ''); }
  addEventListener(type, fn) {
    this.listeners[type] = this.listeners[type] || [];
    this.listeners[type].push(fn);
  }
  click() {
    if (this.tagName === 'INPUT' && (this.type === 'radio' || this.type === 'checkbox')) {
      this.checked = this.type === 'checkbox' ? !this.checked : true;
      const change = {type: 'change', target: this, preventDefault() {}, currentTarget: this};
      for (const fn of this.listeners.change || []) fn(change);
    }
    const event = {type: 'click', target: this, preventDefault() {}, currentTarget: this};
    for (const fn of this.listeners.click || []) fn(event);
  }
  appendChild(node) {
    node.parent = this;
    node.document = this.document;
    this.children.push(node);
    this.document?.register(node);
    return node;
  }
  set innerHTML(html) {
    this.children = [];
    this._text = '';
    const re = /<(\w+)([^>]*)>([^<]*)/g;
    let match;
    while ((match = re.exec(String(html))) ) {
      const attrs = Object.fromEntries([...match[2].matchAll(/([:@\w-]+)(?:=["']([^"']*)["'])?/g)].map((item) => [item[1], item[2] ?? '']));
      const child = new MiniNode(match[1], attrs, this.document);
      if (match[3]) child.textContent = match[3];
      this.appendChild(child);
    }
  }
}

function parseDocument(html) {
  const byId = new Map();
  const all = [];
  const re = /<([a-zA-Z0-9]+)([^>]*)>/g;
  let match;
  while ((match = re.exec(html))) {
    const attrs = Object.fromEntries([...match[2].matchAll(/([:@\w-]+)(?:=["']([^"']*)["'])?/g)].map((item) => [item[1], item[2] ?? '']));
    const node = new MiniNode(match[1], attrs, null);
    all.push(node);
    if (attrs.id) byId.set(attrs.id, node);
  }
  const document = {
    byId,
    all,
    body: byId.get('sidebar') || all[0],
    register(node) {
      if (node?.id) byId.set(node.id, node);
      if (node) all.push(node);
    },
    getElementById(id) { return byId.get(id) || null; },
    querySelectorAll(selector) {
      if (selector.startsWith('.')) {
        const cls = selector.slice(1);
        return all.filter((node) => node.classList.contains(cls));
      }
      const nameMatch = /\[name=["']([^"']+)["']\]/.exec(selector);
      if (selector.startsWith('input') && nameMatch) {
        return all.filter((node) => node.tagName === 'INPUT' && node.name === nameMatch[1]);
      }
      if (selector.startsWith('input')) return all.filter((node) => node.tagName === 'INPUT');
      return [];
    },
    createElement(tag) { return new MiniNode(tag, {}, document); },
    createTextNode(text) {
      const node = new MiniNode('#text', {}, document);
      node.textContent = text;
      return node;
    },
  };
  for (const node of all) node.document = document;
  return document;
}

class MemoryStorage {
  constructor() { this.map = new Map(); }
  getItem(key) { return this.map.has(key) ? this.map.get(key) : null; }
  setItem(key, value) { this.map.set(key, String(value)); }
  removeItem(key) { this.map.delete(key); }
  clear() { this.map.clear(); }
}

/**
 * 在页面上下文里真正执行 apps/desktop-ui/native-boot.mjs。
 * 测试只摆好宿主原语（Tauri invoke、fetch、storage 等），装配由产品代码自己完成。
 */
async function runProductBoot(context) {
  const entry = path.resolve('apps/desktop-ui/native-boot.mjs');
  const source = await readFile(entry, 'utf8');
  const module = new vm.SourceTextModule(source, {context, identifier: pathToFileURL(entry).href});
  await module.link(async (specifier, referencing) => {
    const resolved = specifier.startsWith('.')
      ? pathToFileURL(path.resolve(path.dirname(fileURLToPath(referencing.identifier)), specifier)).href
      : specifier;
    const real = await import(resolved);
    const names = [...new Set([...Object.keys(real), 'default'])];
    return new vm.SyntheticModule(names, function bind() {
      for (const name of names) this.setExport(name, real[name]);
    }, {context});
  });
  await module.evaluate();
}

export async function createPageRuntime(label, options = {}) {
  const booting = Boolean(options.hostPrimitives);
  const compose = options.compose || (booting ? null : await createDesktopComposition(label, options));
  const ownsCompose = !options.compose && !booting;
  const host = compose ? createStewardHost(compose, {sessionToken: options.sessionToken || compose.sessionToken}) : null;
  const html = await readFile(path.resolve('apps/desktop-ui/index.html'), 'utf8');
  const document = parseDocument(html);
  const window = {
    document,
    localStorage: new MemoryStorage(),
    __STEWARD__: null,
    __STEWARD_HOST__: null,
  };
  const context = vm.createContext({
    window,
    document,
    localStorage: window.localStorage,
    globalThis: window,
    console,
    URL,
    Request,
    Response,
    Headers,
    TextEncoder,
    TextDecoder,
    AbortController,
    setTimeout,
    clearTimeout,
    setInterval,
    clearInterval,
    Date,
    Intl,
  });
  if (booting) {
    Object.assign(window, options.hostPrimitives);
    await runProductBoot(context);
    const bridgeSource = await readFile(path.resolve('apps/desktop-ui/bridge.js'), 'utf8');
    vm.runInContext(bridgeSource, context);
    try {
      await window.__STEWARD_BOOT__;
    } catch (error) {
      window.__STEWARD_BOOT_ERROR__ = error;
    }
  } else {
    host.attach(window);
  }
  const appSource = await readFile(path.resolve('apps/desktop-ui/app.bundle.js'), 'utf8');
  vm.runInContext(appSource, context);
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));
  return {
    compose,
    session: host?.session || null,
    window,
    document,
    async click(id) {
      const node = document.getElementById(id);
      if (!node) throw new Error(`missing button ${id}`);
      node.click();
      await Promise.resolve();
      await new Promise((resolve) => setImmediate(resolve));
      await new Promise((resolve) => setImmediate(resolve));
    },
    setValue(id, value) {
      const node = document.getElementById(id);
      if (!node) throw new Error(`missing input ${id}`);
      node.value = value;
    },
    text(id) {
      return document.getElementById(id)?.textContent || '';
    },
    snapshot() {
      return (host?.session || window.__STEWARD_SESSION__).snapshot();
    },
    close() {
      if (ownsCompose) compose.close();
    },
  };
}
