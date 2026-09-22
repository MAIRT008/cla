import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {mkdir, readFile, symlink, writeFile} from 'node:fs/promises';
import path from 'node:path';
import {transientRun} from '../../fixtures/transientRoot.mjs';
import test from 'node:test';
import {DatabaseSync} from 'node:sqlite';
import {createSyntheticLocalService} from '../../src/adapters/local/index.mjs';
import {createWorkspaceAdapter} from '../../src/adapters/local/workspace.mjs';
import {createLocalService} from '../../src/core/local/index.mjs';
import {createSyntheticFixture, SYNTHETIC_ENVIRONMENT} from './demo.mjs';

async function preparedService(label, {confirm = true, mutateFixture = null, capabilities = {}} = {}) {
  const root = transientRun('local', label);
  await createSyntheticFixture(root);
  if (mutateFixture) await mutateFixture(root);
  const service = createSyntheticLocalService({workspaceRoot: root, environment: SYNTHETIC_ENVIRONMENT, capabilities});
  const scan = await service.discover({mode: 'deep'});
  for (const identity of scan.identities) {
    service.recordAccountAnswer({
      scanId: scan.scan_id,
      identityRef: identity.identity_ref,
      identityFingerprint: identity.identity_fingerprint,
      status: identity.identity_ref === 'restricted-account' ? 'restricted' : 'normal',
    });
  }
  const classification = service.classify({scanId: scan.scan_id});
  const plan = await service.buildActionPlan({scanId: scan.scan_id, recommendationIds: classification.recommendations.map((entry) => entry.recommendation_id)});
  if (confirm) await service.confirmActionPlan({planId: plan.plan_id, version: plan.version, actionIds: plan.actions.map((entry) => entry.action_id), source: 'local-user'});
  return {root, service, scan, classification, plan};
}

test('T3 scans actual synthetic files, protects projects, and requires local confirmation', async () => {
  const {service, scan, classification, plan} = await preparedService('local-scan', {confirm: false});
  assert.ok(scan.objects.some((entry) => entry.kind === 'cc_switch_sqlite'));
  assert.ok(scan.objects.some((entry) => entry.kind === 'cookie_sqlite'));
  assert.ok(scan.objects.find((entry) => entry.relative_path.endsWith('old-archive.json')).protected_paths.length > 0);
  assert.equal(classification.score.status, 'unknown', 'unknown JSON creates an explicit coverage gap');
  await assert.rejects(
    () => service.executeConfirmedPlan({planId: plan.plan_id, version: plan.version, operationId: 'no-confirmation'}),
    {code: 'NOT_CONFIRMED'},
  );
});

test('T3 core reads standard Uint8Array data without a Node Buffer dependency', async () => {
  const bytes = new TextEncoder().encode(JSON.stringify({legacyCredential: {identity_ref: 'restricted-account'}}));
  const records = new Map();
  const adapter = {
    clock: () => '2026-09-12T00:00:00.000Z',
    hashBytes: (value) => createHash('sha256').update(value).digest('hex'),
    async walk() { return [{relative_path: 'input/settings.json', status: 'found', size: bytes.byteLength}]; },
    async readBytes() { return bytes; },
    async fingerprint() { return this.hashBytes(bytes); },
    async inspectDatabase() { throw new Error('not used'); },
    async mutateDatabase() { throw new Error('not used'); },
    saveRecord(type, id, payload) { records.set(`${type}:${id}`, structuredClone(payload)); },
    getRecord(id, type) { return records.get(`${type}:${id}`) || null; },
    listRecords(type) { return [...records.entries()].filter(([key]) => key.startsWith(`${type}:`)).map(([, value]) => value); },
  };
  const service = createLocalService({adapter, environment: {scopes: ['input']}});
  const scan = await service.discover({mode: 'deep'});
  assert.equal(scan.objects[0].status, 'found');
  assert.deepEqual(scan.objects[0].identities, ['restricted-account']);
});

test('T3 confirmation freezes only selected same-file actions for execution and resume', async () => {
  const {service, plan} = await preparedService('local-selected-actions', {
    confirm: false,
    mutateFixture: async (root) => {
      const settingsPath = path.join(root, 'input/desktop/settings.json');
      const settings = JSON.parse(await readFile(settingsPath, 'utf8'));
      settings.legacyCredential = {identity_ref: 'restricted-account'};
      await writeFile(settingsPath, `${JSON.stringify(settings, null, 2)}\n`);
    },
  });
  const grouped = new Map();
  for (const action of plan.actions.filter((entry) => entry.kind === 'json_remove')) {
    const list = grouped.get(action.relative_path) || [];
    list.push(action);
    grouped.set(action.relative_path, list);
  }
  const pair = [...grouped.values()].find((actions) => actions.length >= 2);
  assert.ok(pair, 'fixture has two independently removable fields in one JSON object');
  const [unselected, selected] = pair;
  const confirmation = await service.confirmActionPlan({planId: plan.plan_id, version: plan.version, actionIds: [selected.action_id], source: 'local-user'});
  assert.equal(confirmation.actions.length, 1);
  assert.equal(confirmation.actions[0].action_id, selected.action_id);
  const cancelled = await service.executeConfirmedPlan({planId: plan.plan_id, version: plan.version, operationId: 'selected-only-resume', cancelAfter: 0});
  assert.equal(cancelled.status, 'cancelled');
  const resumed = await service.resumeOperation({operationId: 'selected-only-resume'});
  assert.ok(resumed.receipts.some((receipt) => receipt.action_id === selected.action_id && receipt.status === 'APPLIED'));
  assert.ok(!resumed.receipts.some((receipt) => receipt.action_id === unselected.action_id));
});

test('T3 preserves a JSON provider pointer when its provider action fails', async () => {
  const {root, service, plan} = await preparedService('local-provider-dependency', {capabilities: {blocked_paths: ['input/cc-switch.sqlite']}});
  const operation = await service.executeConfirmedPlan({planId: plan.plan_id, version: plan.version, operationId: 'provider-dependency'});
  const providerAction = plan.actions.find((action) => action.kind === 'cc_provider_delete' && action.selector.provider_id === 'restricted-provider');
  const pointerAction = plan.actions.find((action) => action.selector.linked_provider_ids?.includes('restricted-provider'));
  assert.equal(operation.receipts.find((receipt) => receipt.action_id === providerAction.action_id).code, 'ACCESS_DENIED');
  assert.equal(operation.receipts.find((receipt) => receipt.action_id === pointerAction.action_id).status, 'DEPENDENCY_BLOCKED');
  const settings = JSON.parse(await readFile(path.join(root, 'input/desktop/settings.json'), 'utf8'));
  assert.equal(settings.providerRef, 'restricted-provider');
});

test('T3 executes JSON and SQLite actions, resumes across a new service instance, and restores only selected JSON', async () => {
  const {root, service, scan, plan} = await preparedService('local-execute');
  const operation = await service.executeConfirmedPlan({planId: plan.plan_id, version: plan.version, operationId: 'cross-process-operation', cancelAfter: 2});
  assert.equal(operation.status, 'cancelled');
  const reopened = createSyntheticLocalService({workspaceRoot: root, environment: SYNTHETIC_ENVIRONMENT});
  const resumed = await reopened.resumeOperation({operationId: 'cross-process-operation'});
  assert.equal(resumed.status, 'completed');
  const cc = new DatabaseSync(path.join(root, 'input/cc-switch.sqlite'));
  try {
    assert.equal(cc.prepare("SELECT COUNT(*) AS count FROM providers WHERE id = 'restricted-provider' AND app_type = 'claude'").get().count, 0);
    assert.equal(cc.prepare("SELECT COUNT(*) AS count FROM providers WHERE id = 'normal-provider' AND app_type = 'claude'").get().count, 1);
    assert.equal(cc.prepare("SELECT COUNT(*) AS count FROM provider_endpoints WHERE provider_id = 'restricted-provider'").get().count, 0);
  } finally { cc.close(); }
  const settingsAction = plan.actions.find((action) => action.kind === 'json_remove' && action.relative_path === 'input/desktop/settings.json');
  const jsonReceipt = resumed.receipts.find((receipt) => receipt.action_id === settingsAction.action_id);
  const settingsPath = path.join(root, 'input/desktop/settings.json');
  const current = JSON.parse(await readFile(settingsPath, 'utf8'));
  assert.equal(current.providerRef, undefined);
  assert.equal(current.providerMode, 'managed');
  current.user_added_after_cleanup = true;
  await (await import('node:fs/promises')).writeFile(settingsPath, `${JSON.stringify(current, null, 2)}\n`);
  const preview = await reopened.previewRestore({backupRef: jsonReceipt.backup_ref});
  assert.equal(preview.recoverable, true, 'unrelated JSON edits do not conflict with field-level restore');
  reopened.confirmRestore({previewId: preview.preview_id, source: 'local-user'});
  await reopened.restoreChange({previewId: preview.preview_id});
  const restored = JSON.parse(await readFile(settingsPath, 'utf8'));
    assert.equal(restored.user_added_after_cleanup, true);
    assert.equal(restored.thirdParty.legacyProvider.identity_ref, 'restricted-account');
    const ccAction = plan.actions.find((action) => action.kind === 'cc_provider_delete');
    const ccReceipt = resumed.receipts.find((receipt) => receipt.action_id === ccAction.action_id);
    const ccPreview = await reopened.previewRestore({backupRef: ccReceipt.backup_ref});
    assert.equal(ccPreview.recoverable, true);
    reopened.confirmRestore({previewId: ccPreview.preview_id, source: 'local-user'});
    await reopened.restoreChange({previewId: ccPreview.preview_id});
    const restoredCc = new DatabaseSync(path.join(root, 'input/cc-switch.sqlite'));
    try {
      assert.equal(restoredCc.prepare("SELECT COUNT(*) AS count FROM providers WHERE id = 'restricted-provider' AND app_type = 'claude'").get().count, 1);
      assert.equal(restoredCc.prepare("SELECT COUNT(*) AS count FROM provider_endpoints WHERE provider_id = 'restricted-provider' AND app_type = 'claude'").get().count, 1);
    } finally { restoredCc.close(); }
    const cookieAction = plan.actions.find((action) => action.kind === 'cookie_delete');
    const cookieReceipt = resumed.receipts.find((receipt) => receipt.action_id === cookieAction.action_id);
    const cookiePreview = await reopened.previewRestore({backupRef: cookieReceipt.backup_ref});
    assert.equal(cookiePreview.recoverable, true);
    reopened.confirmRestore({previewId: cookiePreview.preview_id, source: 'local-user'});
    await reopened.restoreChange({previewId: cookiePreview.preview_id});
    const restoredCookies = new DatabaseSync(path.join(root, 'input/browser/Default/cookies.sqlite'));
    try {
      assert.equal(restoredCookies.prepare('SELECT COUNT(*) AS count FROM cookies WHERE name = ? AND host_key = ? AND top_frame_site_key = ? AND path = ? AND source_scheme = ? AND source_port = ? AND has_cross_site_ancestor = ?')
        .get(cookieAction.selector.name, cookieAction.selector.host_key, cookieAction.selector.top_frame_site_key, cookieAction.selector.path, cookieAction.selector.source_scheme, cookieAction.selector.source_port, cookieAction.selector.has_cross_site_ancestor).count, 1);
    } finally { restoredCookies.close(); }
    const report = await reopened.getReport({scanId: scan.scan_id, operationId: 'cross-process-operation'});
  const reportText = await readFile(path.join(root, report.json_path), 'utf8');
  assert.ok(!reportText.includes('SYNTHETIC_RESTRICTED_TOKEN'));
});

test('T3 consumes the declared environment snapshot, isolates a pure directory, and records a checked site command', async () => {
  const {root, service, scan, classification, plan} = await preparedService('local-environment-directory');
  assert.equal(scan.environment_snapshot.default_browser.profile_ref, 'Default');
  assert.ok(scan.objects.some((object) => object.profile_ref === 'Profile 1' && object.status === 'not_selected'));
  assert.equal(classification.result_groups.length, 5);
  assert.equal(scan.objects.find((object) => object.json_shape === 'desktop_profile').desktop_pointer_status, 'applied');
  assert.ok(plan.actions.some((action) => action.selector.field_path === 'env.ANTHROPIC_AUTH_TOKEN'));
  const request = service.requestSiteCommand({
    scanId: scan.scan_id,
    profileRef: 'Default',
    site: 'claude.example',
    storageType: 'cache',
  });
  const response = service.recordSiteCommandResponse({
    requestId: request.request_id,
    response: {...request, status: 'completed', changed_entries: 1, capability_ref: 'synthetic-cache-command'},
  });
  assert.equal(response.status, 'completed');
  const directoryAction = plan.actions.find((action) => action.kind === 'isolate_directory');
  assert.ok(directoryAction, 'explicit pure directory becomes one isolatable action');
  await service.confirmActionPlan({planId: plan.plan_id, version: plan.version, actionIds: [directoryAction.action_id], source: 'local-user'});
  const operation = await service.executeConfirmedPlan({planId: plan.plan_id, version: plan.version, operationId: 'directory-isolation'});
  const receipt = operation.receipts.find((entry) => entry.action_id === directoryAction.action_id);
  assert.equal(receipt.status, 'APPLIED');
  assert.equal(await (await import('node:fs/promises')).stat(path.join(root, directoryAction.relative_path)).catch(() => null), null);
  const preview = await service.previewRestore({backupRef: receipt.backup_ref});
  assert.equal(preview.recoverable, true);
  service.confirmRestore({previewId: preview.preview_id, source: 'local-user'});
  await service.restoreChange({previewId: preview.preview_id});
  assert.equal(JSON.parse(await readFile(path.join(root, directoryAction.relative_path, 'legacy.json'), 'utf8')).legacyProvider.identity_ref, 'restricted-account');
});

test('T3 rejects state initialization through a workspace state link before creating a database', async () => {
  const root = transientRun('local', 'state-root');
  const outside = transientRun('local', 'state-canary');
  await mkdir(root, {recursive: true});
  await mkdir(outside, {recursive: true});
  await symlink(outside, path.join(root, 'state'), 'junction');
  assert.throws(() => createWorkspaceAdapter({workspaceRoot: root}), /OUT_OF_SCOPE/);
  assert.equal(await (await import('node:fs/promises')).stat(path.join(outside, 'local.sqlite')).catch(() => null), null);
});

test('T3 records runtime cancellation before each not-yet-started action', async () => {
  const {service, plan} = await preparedService('local-runtime-cancel');
  const controller = new AbortController();
  controller.abort();
  const operation = await service.executeConfirmedPlan({planId: plan.plan_id, version: plan.version, operationId: 'runtime-cancel', signal: controller.signal});
  assert.equal(operation.status, 'cancelled');
  assert.equal(operation.receipts.length, plan.actions.length);
  assert.ok(operation.receipts.every((receipt) => receipt.status === 'NOT_STARTED' && receipt.code === 'CANCELLED_AT_BOUNDARY'));
});
