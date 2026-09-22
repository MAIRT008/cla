import assert from 'node:assert/strict';
import test from 'node:test';
import {createCleanupScript} from '../../fixtures/delivery/aiScripts.mjs';
import {composition, confirmedLocalPlan, scanAndAnswer} from './harness.mjs';

test('FD-01/F05 F06 快扫复用上次结果，专项扫描只覆盖选定范围', async () => {
  const compose = await composition('gap-scan-modes');
  const deep = await compose.local.discover({mode: 'deep'});
  assert.equal(deep.coverage.complete, false, '声明环境里存在未安装客户端等缺口');
  assert.ok(deep.objects.length > 0);

  const quick = await compose.local.discover({mode: 'quick', priorScanId: deep.scan_id});
  assert.notEqual(quick.scan_id, deep.scan_id);
  const reused = quick.objects.filter((item) => item.read === false);
  assert.ok(reused.length > 0, '快扫必须复用上次未变对象而不是全部重读');
  const reusedPaths = new Set(reused.map((item) => item.relative_path));
  for (const item of deep.objects) {
    if (!reusedPaths.has(item.relative_path)) continue;
    const now = quick.objects.find((entry) => entry.relative_path === item.relative_path);
    assert.equal(now.sha256, item.sha256, '复用项的内容指纹必须与上次一致');
  }

  const focused = await compose.local.discover({mode: 'focused', kinds: ['cookie_sqlite']});
  assert.ok(focused.objects.length > 0);
  assert.ok(focused.objects.every((item) => item.kind === 'cookie_sqlite'), '专项扫描只收选定类型');
  assert.ok(
    (focused.coverage.gaps || []).some((item) => item.code === 'FOCUSED_SCOPE_ONLY'),
    '专项扫描必须声明评分只覆盖选定范围',
  );
  assert.equal(focused.coverage.complete, false);
  await assert.rejects(
    async () => compose.local.discover({mode: 'focused', kinds: ['not-a-supported-kind']}),
    (error) => error.code === 'INVALID_FOCUSED_TYPE',
  );
  compose.close();
});

test('FD-01/F25 F26 复查后重新评分，脱敏报告不含凭据值', async () => {
  const compose = await composition('gap-report');
  const scan = await scanAndAnswer(compose);
  const {plan, classification} = await confirmedLocalPlan(compose, scan.scan_id);
  const before = classification.score;
  assert.ok(before.deducted_points > 0, '处理前必须有扣分');

  const operation = await compose.local.executeConfirmedPlan({planId: plan.plan_id, version: plan.version, operationId: 'gap-report-op'});
  assert.equal(operation.status, 'completed');
  const recheck = await compose.local.recheckAction({planId: plan.plan_id, actionId: plan.actions[0].action_id});
  assert.equal(recheck.status, 'verified', '复查必须给出实际核验结果');

  const report = await compose.local.getReport({scanId: scan.scan_id, operationId: operation.operation_id});
  assert.ok(report.score, '报告带出重新计算的分数');
  assert.ok(report.findings.some((item) => item.current_state === 'resolved_by_recheck'), '复查通过的问题才标记解决');
  assert.ok(report.score.deducted_points < before.deducted_points, '只有复查确认后扣分才减少');

  const serialized = JSON.stringify(report);
  assert.ok(!serialized.includes('SYNTHETIC_CODE_AUTH_TOKEN'), '脱敏报告不得带出凭据值');
  assert.ok(!serialized.includes('restricted-session'), '脱敏报告不得带出 Cookie 值');
  compose.close();
});

test('FD-01/F15 站点数据命令按声明能力执行并留回执', async () => {
  const compose = await composition('gap-site-command');
  const scan = await compose.local.discover({mode: 'deep'});

  const request = compose.local.requestSiteCommand({
    scanId: scan.scan_id,
    profileRef: 'Default',
    site: 'claude.example',
    storageType: 'cache',
  });
  assert.equal(request.command, 'clear_supported_site_storage');
  assert.equal(request.protocol_version, 'synthetic-site-command-v1', '命令按声明能力固定协议版本');

  assert.throws(
    () => compose.local.requestSiteCommand({
      scanId: scan.scan_id,
      profileRef: 'Profile 1',
      site: 'claude.example',
      storageType: 'cache',
    }),
    (error) => error.code === 'SITE_COMMAND_UNSUPPORTED',
    '没有声明能力的 Profile 不得发命令',
  );

  const response = compose.local.recordSiteCommandResponse({
    requestId: request.request_id,
    response: {
      command: request.command,
      profile_ref: request.profile_ref,
      site: request.site,
      storage_type: request.storage_type,
      protocol_version: request.protocol_version,
      status: 'completed',
      changed_entries: 1,
    },
  });
  assert.equal(response.status, 'completed');
  assert.equal(response.changed_entries, 1, '回执记录实际变更条数');
  assert.throws(
    () => compose.local.recordSiteCommandResponse({
      requestId: request.request_id,
      response: {...request, status: 'completed', storage_type: 'local_storage'},
    }),
    (error) => error.code === 'SITE_COMMAND_RESPONSE_INVALID',
    '回执字段与固定请求不符必须拒绝',
  );
  compose.close();
});

test('FD-04/F40 A39 本地清理不覆盖监控证据与已交付日报', async () => {
  const compose = await composition('gap-audit-protection');
  const reportPath = compose.dailyPaths.json;
  const markdownPath = compose.dailyPaths.markdown;
  const jsonBefore = await compose.auditStore.readText(reportPath);
  const markdownBefore = await compose.auditStore.readText(markdownPath);
  const archiveBefore = (await compose.auditStore.listFiles('archive')).map((item) => item.path).sort();

  const scan = await scanAndAnswer(compose);
  assert.ok(scan.objects.length > 0);
  for (const object of scan.objects) {
    assert.ok(!object.relative_path.startsWith('audit/'), `扫描范围不得包含监控证据：${object.relative_path}`);
  }

  const {plan} = await confirmedLocalPlan(compose, scan.scan_id);
  for (const action of plan.actions) {
    assert.ok(!action.relative_path.startsWith('audit/'), `清理清单不得包含监控证据：${action.relative_path}`);
  }
  const operation = await compose.local.executeConfirmedPlan({planId: plan.plan_id, version: plan.version, operationId: 'gap-audit-op'});
  assert.equal(operation.status, 'completed');

  assert.equal(await compose.auditStore.readText(reportPath), jsonBefore, '已交付日报不得被本地清理改动');
  assert.equal(await compose.auditStore.readText(markdownPath), markdownBefore);
  assert.deepEqual((await compose.auditStore.listFiles('archive')).map((item) => item.path).sort(), archiveBefore, '归档不得被本地清理删改');
  compose.close();
});

test('FD-01/A21 标准与 AI 在同一案例上给出同一组目标', async () => {
  let scanId = null;
  const compose = await composition('gap-standard-vs-ai', {sdkFetch: createCleanupScript({scanId: () => scanId})});
  const scan = await scanAndAnswer(compose);
  scanId = scan.scan_id;

  const classification = compose.local.classify({scanId});
  const standardPlan = await compose.local.buildActionPlan({
    scanId,
    recommendationIds: (classification.recommendations || []).map((item) => item.recommendation_id),
  });
  const standardTargets = [...new Set(standardPlan.actions.map((item) => `${item.relative_path}|${item.kind}`))].sort();

  const ai = compose.createAi({sessionToken: 'token-max', userRef: 'user-max'});
  const task = await ai.startCleanup({scanId});
  assert.equal(task.status, 'AWAITING_CONFIRMATION');
  const aiPlan = compose.store.getRecord(task.planId, 'plan');
  const aiTargets = [...new Set(aiPlan.actions.map((item) => `${item.relative_path}|${item.kind}`))].sort();

  assert.deepEqual(aiTargets, standardTargets, 'AI 路径不得凭空增加或漏掉目标');
  assert.equal(aiPlan.scan_id, standardPlan.scan_id, '两条路径引用同一次扫描');
  assert.ok(
    aiPlan.actions.every((item) => item.expected_before_sha256),
    'AI 计划同样由程序冻结前置指纹',
  );
  compose.close();
});

test('FD-02/N03 FD-04/A05 主机与客体分别标注覆盖，未测环境不合成整机通过', async () => {
  const compose = await composition('gap-environments');

  const hostScan = await compose.diagnostics.startScan({mode: 'deep', environmentRef: 'synthetic-windows', profileRef: 'Default'});
  assert.equal(hostScan.environment_ref, 'synthetic-windows');
  assert.equal(hostScan.whole_machine_claim, false, '单环境扫描不得声称整机');
  const hostCoverage = Object.fromEntries(hostScan.environment_coverage.map((item) => [item.environment_ref, item]));
  assert.equal(hostCoverage['synthetic-windows'].status, 'MEASURED');
  assert.equal(hostCoverage['synthetic-windows'].kind, 'host');
  assert.equal(hostCoverage['wsl-synthetic'].status, 'NOT_MEASURED', '未测客体必须单独标注');
  assert.equal(hostCoverage['wsl-synthetic'].kind, 'wsl');
  assert.ok(hostCoverage['wsl-synthetic'].reason, '未测必须给出原因');
  assert.equal(hostCoverage['wsl-synthetic'].measured, false);

  const guestScan = await compose.diagnostics.startScan({mode: 'deep', environmentRef: 'wsl-synthetic', profileRef: 'Default'});
  const guestCoverage = Object.fromEntries(guestScan.environment_coverage.map((item) => [item.environment_ref, item]));
  assert.equal(guestCoverage['wsl-synthetic'].status, 'MEASURED', '换环境后被测对象随之变化');
  assert.equal(guestCoverage['synthetic-windows'].status, 'NOT_MEASURED');
  assert.notEqual(guestScan.task_id, hostScan.task_id);
  assert.ok(hostCoverage['synthetic-windows'].evidence_count > 0, '标 MEASURED 必须有本次真实采到的证据');
  assert.equal(hostCoverage['wsl-synthetic'].evidence_count, 0);
  assert.ok(guestCoverage['wsl-synthetic'].evidence_count > 0);
  assert.equal(guestCoverage['synthetic-windows'].evidence_count, 0);

  const bareEvidence = (result) => result.observations
    .filter((item) => !item.stale)
    .map(({task_id, environment_ref, evidence_ref, observed_at, ...rest}) => JSON.stringify(rest))
    .sort();
  assert.notDeepEqual(bareEvidence(guestScan), bareEvidence(hostScan), '去掉任务与环境标签后，两次扫描的观测证据本身也必须不同');

  const hostRequests = compose.environmentProbes.get('synthetic-windows').world.state.requests.map((item) => item.url);
  const guestRequests = compose.environmentProbes.get('wsl-synthetic').world.state.requests.map((item) => item.url);
  assert.ok(hostRequests.length > 0 && guestRequests.length > 0, '两个环境都真的发出了探测');
  assert.ok(
    guestRequests.some((url) => !hostRequests.includes(url)),
    '客体的探测目标必须与主机不同，不能共用同一套端口',
  );
  await assert.rejects(
    () => compose.diagnostics.startScan({mode: 'deep', environmentRef: 'undeclared-environment'}),
    (error) => error.code === 'ENVIRONMENT_PROBE_UNAVAILABLE',
    '没有探测端口的环境不得用主机证据冒充',
  );

  const report = compose.daily;
  const coverage = Object.fromEntries((report.collectionEvidence.environment_coverage || []).map((item) => [item.environment_ref, item]));
  assert.equal(coverage['synthetic-windows'].covered, true);
  assert.equal(coverage['wsl-synthetic'].covered, false, '日报必须分别标注主机与客体覆盖');
  assert.equal(report.collectionEvidence.whole_machine_claim, false, '客体未覆盖时不得声称整机');
  assert.ok(
    (report.coverageIssues || []).some((item) => item.code === 'COLLECTION_ENVIRONMENT_NOT_COVERED' && item.environment_ref === 'wsl-synthetic'),
    '未覆盖环境必须进入覆盖缺口',
  );
  assert.equal(report.coverageStatus, 'MONITORING_INCOMPLETE', '覆盖不全不得判完整');
  compose.close();
});
