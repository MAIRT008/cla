import {createDesktopSession} from './session.mjs';

export function attachSteward(target, session) {
  async function dispatch(name, args = []) {
    const fn = session[name];
    if (typeof fn !== 'function') {
      throw Object.assign(new Error(`unknown ui action ${name}`), {code: 'UI_ACTION_UNKNOWN'});
    }
    return fn(...(Array.isArray(args) ? args : [args]));
  }
  target.__STEWARD_HOST__ = dispatch;
  const api = {};
  for (const name of Object.keys(session)) {
    if (typeof session[name] === 'function') api[name] = (...args) => dispatch(name, args);
  }
  target.__STEWARD__ = api;
  return api;
}

export function createStewardHost(compose, options = {}) {
  const session = createDesktopSession(compose, options);
  return {session, attach(target) { return attachSteward(target, session); }};
}
