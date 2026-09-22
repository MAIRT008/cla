import childProcess from 'node:child_process';
import dgram from 'node:dgram';
import http from 'node:http';
import https from 'node:https';
import {syncBuiltinESMExports} from 'node:module';
import net from 'node:net';

/**
 * 控制端离线用例的守卫：本进程里不许真的起进程、监听端口、连网或发 fetch。
 * 必须作为测试文件的第一条 import，保证之后加载的模块拿到的都是被替换后的函数。
 */
function blocked(name) {
  return () => {
    throw Object.assign(new Error(`offline guard: 控制端离线用例禁止调用 ${name}`), {code: 'OFFLINE_GUARD'});
  };
}

for (const name of ['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork']) {
  childProcess[name] = blocked(`child_process.${name}`);
}
net.Server.prototype.listen = blocked('net.Server.listen');
net.connect = blocked('net.connect');
net.createConnection = blocked('net.createConnection');
http.request = blocked('http.request');
http.get = blocked('http.get');
https.request = blocked('https.request');
https.get = blocked('https.get');
dgram.createSocket = blocked('dgram.createSocket');
globalThis.fetch = blocked('fetch');
syncBuiltinESMExports();
