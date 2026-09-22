import assert from 'node:assert/strict';
import test from 'node:test';
import {createDefaultBrowserDiagnostics} from '../../src/adapters/diagnostics/defaultBrowser.mjs';
import {createDiagnosticHarness} from '../../fixtures/diagnostics/harness.mjs';
import {createSyntheticBrowserHost, injectSession, runDiagPage} from './browserHost.mjs';

const ENV = 'synthetic-windows';
const WORLD = {echoIp: '203.0.113.10', expectedA: '203.0.113.10', expectedB: '203.0.113.20'};
const LEAKY_BROWSER = {
  timezone: 'Asia/Shanghai',
  utc_offset_minutes: 480,
  locale: 'zh-CN',
  languages: ['zh-CN', 'en'],
  candidates: [
    'candidate:1 1 udp 2122260223 192.168.1.5 50000 typ host generation 0',
    'candidate:2 1 udp 1686052607 198.51.100.77 50001 typ srflx raddr 192.168.1.5 rport 50000 generation 0',
  ],
};

async function setup(label, {browser = LEAKY_BROWSER, autoRun = true} = {}) {
  const harness = await createDiagnosticHarness(label, {world: WORLD});
  const host = createSyntheticBrowserHost({hostEnvironment: ENV, clock: harness.clock, browser, autoRun});
  const port = createDefaultBrowserDiagnostics({
    invoke: host.invoke,
    diagnostics: harness.controller,
    iceServers: [{urls: ['stun:stun.synthetic.invalid:3478']}],
  });
  const scan = await harness.controller.startScan({mode: 'special', scope: {categories: ['exit_ip']}, environmentRef: ENV});
  return {harness, host, port, scan};
}

test('诊断页：宿主注入的会话关不掉 script 标签；只带会话、样本与错误，不读 Cookie', async () => {
  const html = injectSession({session_ref: 's</script><script>alert(1)</script>', session_nonce: 'n', script_version: 'diag-sample-v1', task_ref: 't', environment_ref: ENV, report_path: '/diag/x/report', ice_servers: []});
  assert.equal(html.split('</script>').length, 3, '注入内容里的 </script> 被转义');
  assert.ok(!/document\.cookie/.test(html), '诊断页不读 Cookie');
  const posted = [];
  const run = await runDiagPage(html, {origin: 'http://127.0.0.1:1', browser: LEAKY_BROWSER, respond: ({url, init}) => {
    posted.push({url, body: JSON.parse(init.body)});
    return {ok: true, status: 204};
  }});
  assert.equal(posted.length, 1);
  assert.equal(posted[0].url, '/diag/x/report');
  assert.equal(posted[0].body.session_ref, 's</script><script>alert(1)</script>');
  assert.deepEqual(Object.keys(posted[0].body.sample).sort(), ['fingerprint', 'ice', 'platform']);
  assert.equal(posted[0].body.sample.platform.client_kind, 'default_browser');
  assert.equal(posted[0].body.sample.platform.timezone, 'Asia/Shanghai');
  assert.match(run.status, /已交回/);
});

test('默认浏览器回传进问题与评分：时区与 WebRTC 暴露按分配期望判定，来源标 default_browser', async () => {
  const {harness, host, port, scan} = await setup('default-browser-flow');
  assert.equal(scan.issues.length, 0, '扫描本身没有问题');
  const opened = await port.open({taskRef: scan.task_id, environmentRef: ENV});
  assert.equal(opened.status, 'WAITING');
  assert.equal(host.opened.length, 1, '宿主只打开本监听的页面');
  assert.match(host.opened[0], /^http:\/\/127\.0\.0\.1:\d+\/diag\/[0-9a-f]{32}$/);
  assert.deepEqual(host.active().session.ice_servers, [{urls: ['stun:stun.synthetic.invalid:3478']}]);

  const checked = await port.check();
  assert.equal(checked.view.status, 'RECEIVED', JSON.stringify(checked));
  assert.equal(checked.accepted.ok, true);
  assert.equal(host.active(), null, '收到后监听关闭');

  const result = harness.controller.result(scan.task_id);
  const sample = result.observations.find((item) => item.check_id === 'browser.session-sample');
  assert.equal(sample.client_kind, 'default_browser');
  const timezone = result.issues.find((item) => item.kind === 'BROWSER_TIMEZONE_MISMATCH');
  assert.equal(timezone.evidence_source, 'default_browser');
  assert.equal(timezone.root_cause_id, 'locale-mismatch');
  const webrtc = result.issues.find((item) => item.kind === 'WEBRTC_UNAPPROVED_ADDRESS');
  assert.deepEqual(webrtc.actual.addresses, ['198.51.100.77'], '私网 host 候选不算暴露');
  assert.equal(webrtc.severity, 'important');
  assert.ok(result.scoring.scoped_score <= 79, `回传后重新评分：${result.scoring.scoped_score}`);
  const session = harness.store.getRecord(sample.evidence_ref.replace('diag-receipt-', ''), 'browser_session');
  assert.equal(session.profile_binding, 'UNBOUND', 'Profile 不凭 UA 认定');
});

test('与分配一致的浏览器不产生问题；别的源、错的 nonce、过期都不被接受', async () => {
  const clean = await setup('default-browser-clean', {browser: {timezone: 'America/Los_Angeles', utc_offset_minutes: -420, candidates: ['candidate:2 1 udp 1 203.0.113.10 50001 typ srflx']}});
  await clean.port.open({taskRef: clean.scan.task_id, environmentRef: ENV});
  const checked = await clean.port.check();
  assert.equal(checked.view.status, 'RECEIVED');
  assert.equal(clean.harness.controller.result(clean.scan.task_id).issues.length, 0, '出口地址在分配里、时区一致');

  const forged = await setup('default-browser-forged', {autoRun: false});
  await forged.port.open({taskRef: forged.scan.task_id, environmentRef: ENV});
  await forged.host.runOpenedPage({origin: 'http://evil.invalid'});
  assert.equal((await forged.port.check()).view.status, 'WAITING', '别的源发来的回传宿主不收');

  await forged.port.open({taskRef: forged.scan.task_id, environmentRef: ENV});
  forged.host.active().session.session_nonce = 'tampered';
  await forged.host.runOpenedPage();
  const rejected = await forged.port.check();
  assert.equal(rejected.view.status, 'REJECTED');
  assert.equal(rejected.view.code, 'NONCE_INVALID', '核心按会话 nonce 复核');

  await forged.port.open({taskRef: forged.scan.task_id, environmentRef: ENV});
  forged.harness.clock.set('2026-09-14T18:00:00.000Z');
  assert.equal((await forged.port.check()).view.status, 'EXPIRED');
  assert.equal(forged.port.active(), null);
});

test('没有扫描任务、环境不是宿主本机时不开监听', async () => {
  const {port, host} = await setup('default-browser-guards');
  await assert.rejects(() => port.open({taskRef: null, environmentRef: ENV}), (error) => error.code === 'DIAG_TASK_REQUIRED');
  await assert.rejects(() => port.open({taskRef: 'diag-x', environmentRef: 'wsl-synthetic'}), (error) => error.code === 'BROWSER_DIAG_ENVIRONMENT_MISMATCH');
  assert.equal(host.opened.length, 0);
});
