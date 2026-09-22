import * as fixedYaml from '../../vendor/deps/js-yaml-4.3.0/dist/js-yaml.mjs';
import {installYamlLibrary} from '../../src/core/network/yaml.mjs';
import {bootNativeSteward} from './native.mjs';

/**
 * 正式页面的启动脚本：只要受限原生桥在位就装配 WebView 组合根。
 * 运行配置全部来自宿主的 DescribeCapabilities，页面不依赖任何预置的全局配置对象。
 */
// WebView 里没有 node:module，yaml.mjs 自己装不上固定的 js-yaml；受管配置编译之前在这里装上同一版本。
installYamlLibrary(fixedYaml);

const tauri = globalThis.__TAURI__?.core?.invoke || globalThis.__TAURI_INTERNALS__?.invoke || null;

if (typeof tauri === 'function') {
  globalThis.__STEWARD_BOOT__ = bootNativeSteward(globalThis, {
    invoke: (op, payload, authorizationRef) => tauri('steward_request', {op, payload, authorizationRef}),
    confirm: (request) => tauri('steward_user_confirm', {request}),
    fetchImpl: globalThis.fetch ? globalThis.fetch.bind(globalThis) : null,
    storage: globalThis.localStorage || null,
    navigator: globalThis.navigator || null,
    rtcPeerConnection: globalThis.RTCPeerConnection || null,
    intl: globalThis.Intl || null,
    webSocketImpl: globalThis.WebSocket ? (url) => new globalThis.WebSocket(url) : null,
  });
}
