import assert from 'node:assert/strict';
import {copyFile, mkdir, writeFile} from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import {DatabaseSync} from 'node:sqlite';
import {transientRun} from '../../fixtures/transientRoot.mjs';
import {createSyntheticLocalService} from '../../src/adapters/local/index.mjs';
import {createWorkspaceAdapter} from '../../src/adapters/local/workspace.mjs';
import {createCcSwitchDatabase} from './demo.mjs';

const DB = 'roots/cc-switch/cc-switch.db';
const ENVIRONMENT = {
  environment_ref: 'windows-host',
  scopes: ['roots/cc-switch'],
  clients: [{client_ref: 'cc-switch', environment_ref: 'windows-host', installed: true, authorized: true, path_prefix: 'roots/cc-switch', category: 'third_party', label: 'CC Switch 配置'}],
  object_kinds: [{relative_path: DB, kind: 'cc_switch_sqlite'}],
  json_shapes: [],
  site_hosts: ['claude.ai', 'claude.com', 'anthropic.com'],
  gaps: [],
};

/**
 * CC Switch 库切到 WAL、关掉自动检查点，受限 Provider 只提交在 WAL 里；写连接一直开着，WAL 不会被并回主文件。
 * 这正是复核指出的形状：直接查询看得到这条记录，只复制主文件看不到。
 */
async function walWorkspace(label) {
  const root = transientRun('local', label);
  await mkdir(path.join(root, 'roots', 'cc-switch'), {recursive: true});
  const file = path.join(root, ...DB.split('/'));
  createCcSwitchDatabase(file);
  const writer = new DatabaseSync(file);
  writer.exec('PRAGMA journal_mode = WAL; PRAGMA wal_autocheckpoint = 0; PRAGMA foreign_keys = ON; DELETE FROM providers;');
  writer.exec('PRAGMA wal_checkpoint(TRUNCATE);');
  writer.prepare('INSERT INTO providers (id, app_type, name, settings_config, is_current) VALUES (?, ?, ?, ?, ?)')
    .run('wal-provider', 'claude', 'WAL-only provider', JSON.stringify({identity_ref: 'restricted-account'}), 0);
  writer.prepare('INSERT INTO provider_endpoints (provider_id, app_type, url, added_at) VALUES (?, ?, ?, ?)')
    .run('wal-provider', 'claude', 'https://relay.synthetic.invalid', 1);
  return {root, file, writer};
}

function providerIds(file) {
  const db = new DatabaseSync(file, {readOnly: true});
  try {
    return db.prepare('SELECT id FROM providers ORDER BY id').all().map((row) => row.id);
  } finally { db.close(); }
}

async function plannedDeletion(service) {
  const scan = await service.discover({mode: 'deep'});
  for (const identity of scan.identities) {
    service.recordAccountAnswer({scanId: scan.scan_id, identityRef: identity.identity_ref, identityFingerprint: identity.identity_fingerprint, status: 'restricted'});
  }
  const classification = service.classify({scanId: scan.scan_id});
  const plan = await service.buildActionPlan({scanId: scan.scan_id, recommendationIds: classification.recommendations.map((item) => item.recommendation_id)});
  await service.confirmActionPlan({planId: plan.plan_id, version: plan.version, actionIds: plan.actions.map((item) => item.action_id), source: 'local-user'});
  return {scan, plan};
}

test('BLOCK 记录只在 WAL 里时，扫描、模拟、备份、执行复读与恢复都按 SQLite 一致快照', async () => {
  const {root, file, writer} = await walWorkspace('sqlite-wal-chain');
  try {
    const mainOnly = path.join(root, 'main-file-copy.db');
    await copyFile(file, mainOnly);
    assert.deepEqual(providerIds(mainOnly), [], '前提：只复制主文件拿不到 WAL 里的记录');
    assert.deepEqual(providerIds(file), ['wal-provider']);

    const adapter = createWorkspaceAdapter({workspaceRoot: root});
    const beforeCheckpoint = await adapter.fingerprintDatabase(DB);
    const service = createSyntheticLocalService({workspaceRoot: root, environment: ENVIRONMENT, adapter});
    const {scan, plan} = await plannedDeletion(service);
    assert.equal(scan.objects.find((item) => item.relative_path === DB).sha256, beforeCheckpoint, '扫描指纹是逻辑状态');
    assert.deepEqual(plan.actions.map((item) => `${item.kind}:${item.selector.provider_id}`), ['cc_provider_delete:wal-provider']);

    const operation = await service.executeConfirmedPlan({planId: plan.plan_id, version: plan.version, operationId: 'wal-op'});
    assert.equal(operation.status, 'completed', JSON.stringify(operation.receipts));
    assert.deepEqual(providerIds(file), [], '真实删除');

    const backup = adapter.getBackup(operation.receipts[0].backup_ref);
    const backupFile = path.join(root, 'backup-copy.db');
    await writeFile(backupFile, await adapter.readBytes(backup.payload_path));
    assert.deepEqual(providerIds(backupFile), ['wal-provider'], '备份是一致快照，含 WAL 里的记录');

    const preview = await service.previewRestore({backupRef: backup.backup_ref});
    assert.equal(preview.recoverable, true, JSON.stringify(preview));
    service.confirmRestore({previewId: preview.preview_id, source: 'local-user'});
    await service.restoreChange({previewId: preview.preview_id});
    assert.deepEqual(providerIds(file), ['wal-provider'], '恢复写回被删记录');
  } finally {
    writer.close();
  }
});

test('BLOCK 逻辑指纹不随检查点变化，主文件字节会变', async () => {
  const {root, writer} = await walWorkspace('sqlite-wal-checkpoint');
  try {
    const adapter = createWorkspaceAdapter({workspaceRoot: root});
    const logical = await adapter.fingerprintDatabase(DB);
    const bytes = await adapter.fingerprint(DB);
    writer.exec('PRAGMA wal_checkpoint(TRUNCATE);');
    assert.equal(await adapter.fingerprintDatabase(DB), logical, '同一逻辑状态，指纹不变');
    assert.notEqual(await adapter.fingerprint(DB), bytes, 'WAL 并回主文件后主文件字节变了');
  } finally {
    writer.close();
  }
});

test('BLOCK 取不到一致快照时拒绝执行，库不动、不留备份', async () => {
  const {root, file, writer} = await walWorkspace('sqlite-wal-no-snapshot');
  try {
    const base = createWorkspaceAdapter({workspaceRoot: root});
    const adapter = {
      ...base,
      async snapshotDatabase() {
        throw Object.assign(new Error('DB_SNAPSHOT_UNAVAILABLE: synthetic lock'), {code: 'DB_SNAPSHOT_UNAVAILABLE'});
      },
    };
    const service = createSyntheticLocalService({workspaceRoot: root, environment: ENVIRONMENT, adapter});
    const {plan} = await plannedDeletion(service);
    const operation = await service.executeConfirmedPlan({planId: plan.plan_id, version: plan.version, operationId: 'wal-no-snapshot'});
    assert.notEqual(operation.status, 'completed');
    assert.equal(operation.receipts[0].status, 'FAILED');
    assert.equal(operation.receipts[0].code, 'DB_SNAPSHOT_UNAVAILABLE');
    assert.deepEqual(providerIds(file), ['wal-provider'], '没有快照就不改');
    assert.equal(base.getBackupByAction?.(plan.actions[0].action_id) ?? null, null, '不留备份');
  } finally {
    writer.close();
  }
});
