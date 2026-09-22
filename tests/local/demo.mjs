import {randomUUID} from 'node:crypto';
import {existsSync} from 'node:fs';
import {mkdir, writeFile} from 'node:fs/promises';
import path from 'node:path';
import {assertTransient} from '../../fixtures/transientRoot.mjs';
import {pathToFileURL} from 'node:url';
import {DatabaseSync} from 'node:sqlite';
import {createSyntheticLocalService} from '../../src/adapters/local/index.mjs';

export const SYNTHETIC_ENVIRONMENT = {
  scopes: ['input'],
  source_version: 'synthetic-v1',
  clients: [
    {client_ref: 'synthetic-chrome', environment_ref: 'windows-synthetic', installed: true, authorized: true, profile_refs: ['Default', 'Profile 1']},
    {client_ref: 'synthetic-wsl', environment_ref: 'wsl-synthetic', installed: false, authorized: false, profile_refs: []},
  ],
  default_browser: {client_ref: 'synthetic-chrome', profile_ref: 'Default'},
  cleanup_directories: ['input/third-party/isolated-residue'],
  object_relations: {
    'input/backup/old-archive.json': {purpose: 'project', lifecycle: 'archived', references: ['project:keep-me']},
    'input/audit/current.log': {purpose: 'audit', lifecycle: 'active', references: ['audit:current-window']},
    'input/project/references.jsonl': {purpose: 'project', lifecycle: 'active', references: ['provider:restricted-provider']},
  },
  json_shapes: [
    {
      relative_path: 'input/code/settings.json',
      role: 'claude_code_settings',
      actions: [
        {kind: 'json_set', field_path: 'env.ANTHROPIC_BASE_URL', expected_value: 'https://legacy.synthetic.invalid', value: 'https://managed.synthetic.invalid', issue_confirmed: true, identity_ref: 'restricted-account'},
        {kind: 'json_remove', field_path: 'env.ANTHROPIC_AUTH_TOKEN', issue_confirmed: true, identity_ref: 'restricted-account'},
      ],
    },
    {
      relative_path: 'input/code/settings-add.json',
      role: 'claude_code_settings',
      actions: [
        {kind: 'json_set', field_path: 'env.ANTHROPIC_BASE_URL', expected_missing: true, value: 'https://managed.synthetic.invalid', issue_confirmed: true, identity_ref: 'restricted-account'},
      ],
    },
    {
      relative_path: 'input/desktop/configLibrary/00000000-0000-4000-8000-000000157210.json',
      role: 'desktop_profile',
      profile_id: '00000000-0000-4000-8000-000000157210',
      meta_path: 'input/desktop/configLibrary/_meta.json',
      actions: [
        {kind: 'json_remove', field_path: 'inferenceGatewayApiKey', issue_confirmed: true, identity_ref: 'restricted-account', linked_provider_ids: ['restricted-provider']},
      ],
    },
    {relative_path: 'input/desktop/configLibrary/_meta.json', role: 'desktop_meta', actions: []},
  ],
  identity_associations: {
    'input/code/settings.json': {
      'env.ANTHROPIC_AUTH_TOKEN': {identity_ref: 'restricted-account', provider_id: 'restricted-provider'},
    },
  },
  site_command_capabilities: [
    {command: 'clear_supported_site_storage', profile_ref: 'Default', site: 'claude.example', storage_type: 'cache', protocol_version: 'synthetic-site-command-v1'},
  ],
};

function print(label, value) {
  process.stdout.write(`${label}: ${JSON.stringify(value)}\n`);
}

async function writeJson(root, relative, value) {
  const target = path.join(root, relative);
  await mkdir(path.dirname(target), {recursive: true});
  await writeFile(target, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

export function createCcSwitchDatabase(file) {
  const db = new DatabaseSync(file);
  try {
    db.exec(`
      PRAGMA foreign_keys = ON;
      PRAGMA user_version = 18;
      CREATE TABLE providers (
        id TEXT NOT NULL, app_type TEXT NOT NULL, name TEXT NOT NULL, settings_config TEXT NOT NULL,
        website_url TEXT, category TEXT, created_at INTEGER, sort_index INTEGER, notes TEXT,
        icon TEXT, icon_color TEXT, meta TEXT NOT NULL DEFAULT '{}', is_current BOOLEAN NOT NULL DEFAULT 0,
        in_failover_queue BOOLEAN NOT NULL DEFAULT 0, PRIMARY KEY (id, app_type)
      );
      CREATE TABLE provider_endpoints (
        id INTEGER PRIMARY KEY AUTOINCREMENT, provider_id TEXT NOT NULL, app_type TEXT NOT NULL,
        url TEXT NOT NULL, added_at INTEGER,
        FOREIGN KEY (provider_id, app_type) REFERENCES providers(id, app_type) ON DELETE CASCADE
      );
      CREATE TABLE mcp_servers (id TEXT PRIMARY KEY, name TEXT NOT NULL, server_config TEXT NOT NULL);
      CREATE TABLE skills (id TEXT PRIMARY KEY, name TEXT NOT NULL, skill_path TEXT NOT NULL);
    `);
    db.prepare('INSERT INTO providers (id, app_type, name, settings_config) VALUES (?, ?, ?, ?)')
      .run('restricted-provider', 'claude', 'Synthetic restricted provider', JSON.stringify({identity_ref: 'restricted-account', token: 'SYNTHETIC_PROVIDER_TOKEN'}));
    db.prepare('INSERT INTO providers (id, app_type, name, settings_config) VALUES (?, ?, ?, ?)')
      .run('normal-provider', 'claude', 'Synthetic normal provider', JSON.stringify({identity_ref: 'normal-account'}));
    db.prepare('INSERT INTO provider_endpoints (provider_id, app_type, url, added_at) VALUES (?, ?, ?, ?)')
      .run('restricted-provider', 'claude', 'https://synthetic.invalid/restricted', 1);
    db.prepare('INSERT INTO mcp_servers (id, name, server_config) VALUES (?, ?, ?)')
      .run('protected-mcp', 'Protected synthetic MCP', '{"project":true}');
    db.prepare('INSERT INTO skills (id, name, skill_path) VALUES (?, ?, ?)')
      .run('protected-skill', 'Protected synthetic skill', 'skills/protected');
  } finally { db.close(); }
}

export function createCookieDatabase(file) {
  const db = new DatabaseSync(file);
  try {
    db.exec(`
      CREATE TABLE meta (
        key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY,
        value LONGVARCHAR
      );
      INSERT INTO meta(key, value) VALUES ('version', '24'), ('last_compatible_version', '24');
      CREATE TABLE cookies (
        creation_utc INTEGER NOT NULL, host_key TEXT NOT NULL, top_frame_site_key TEXT NOT NULL,
        name TEXT NOT NULL, value TEXT NOT NULL, encrypted_value BLOB NOT NULL, path TEXT NOT NULL,
        expires_utc INTEGER NOT NULL, is_secure INTEGER NOT NULL, is_httponly INTEGER NOT NULL,
        last_access_utc INTEGER NOT NULL, has_expires INTEGER NOT NULL, is_persistent INTEGER NOT NULL,
        priority INTEGER NOT NULL, samesite INTEGER NOT NULL, source_scheme INTEGER NOT NULL,
        source_port INTEGER NOT NULL, last_update_utc INTEGER NOT NULL, source_type INTEGER NOT NULL,
        has_cross_site_ancestor INTEGER NOT NULL
      );
      CREATE UNIQUE INDEX cookies_unique_index ON cookies (
        host_key, top_frame_site_key, has_cross_site_ancestor, name, path, source_scheme, source_port
      );
    `);
    const insert = db.prepare(`INSERT INTO cookies VALUES (
      ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
    )`);
    const write = (name, encryptedByte) => insert.run(
      13438656000000001n, '.claude.example', 'https://claude.example', name, '', Buffer.from([encryptedByte]), '/',
      0, 1, 1, 13438656000000002n, 0, 0, 1, 0, 2, 443, 13438656000000003n, 0, 0,
    );
    write('restricted-session', 1);
    write('normal-session', 2);
    write('shared-session', 3);
  } finally { db.close(); }
}

export async function createSyntheticFixture(workspace) {
  const root = path.resolve(workspace);
  if (existsSync(root)) throw new Error(`fixture root already exists: ${root}`);
  await mkdir(root, {recursive: true});
  await writeJson(root, 'input/desktop/settings.json', {
    identity: {identity_ref: 'normal-account', cookie: 'SYNTHETIC_NORMAL_COOKIE'},
    thirdParty: {legacyProvider: {identity_ref: 'restricted-account', token: 'SYNTHETIC_RESTRICTED_TOKEN'}},
    providerRef: 'restricted-provider',
    providerMode: 'legacy',
    projectConfig: {project_name: 'keep-me', hook: 'protected'},
  });
  await writeJson(root, 'input/code/user-settings.json', {
    env: {legacyProxy: {identity_ref: 'restricted-account', password: 'SYNTHETIC_PROXY_SECRET'}},
    mcp: {project_tool: 'keep-me'},
  });
  await writeJson(root, 'input/code/settings.json', {
    env: {
      ANTHROPIC_BASE_URL: 'https://legacy.synthetic.invalid',
      ANTHROPIC_AUTH_TOKEN: 'SYNTHETIC_CODE_AUTH_TOKEN',
      ANTHROPIC_MODEL: 'synthetic-model',
    },
    mcpServers: {protected_mcp: {command: 'synthetic-mcp'}},
    projectSettings: {keep: true},
  });
  await writeJson(root, 'input/code/settings-add.json', {
    env: {ANTHROPIC_MODEL: 'synthetic-model'},
    hooks: {keep: true},
  });
  await writeJson(root, 'input/third-party/pure-legacy.json', {
    legacyProvider: {identity_ref: 'restricted-account', credential: 'SYNTHETIC_THIRD_PARTY_SECRET'},
  });
  await writeJson(root, 'input/third-party/isolated-residue/legacy.json', {
    legacyProvider: {identity_ref: 'restricted-account', credential: 'SYNTHETIC_ISOLATED_DIRECTORY_SECRET'},
  });
  await writeJson(root, 'input/desktop/configLibrary/00000000-0000-4000-8000-000000157210.json', {
    inferenceGatewayApiKey: 'SYNTHETIC_DESKTOP_API_KEY',
    inferenceGatewayAuthScheme: 'Bearer',
    inferenceGatewayBaseUrl: 'https://desktop.synthetic.invalid',
    inferenceProvider: 'synthetic-provider',
    disableDeploymentModeChooser: false,
    coworkEgressAllowedHosts: ['synthetic.invalid'],
    inferenceModels: [{name: 'synthetic-model', labelOverride: 'Synthetic'}],
  });
  await writeJson(root, 'input/desktop/configLibrary/_meta.json', {
    entries: [{id: '00000000-0000-4000-8000-000000157210', name: 'Synthetic managed profile'}],
    appliedId: '00000000-0000-4000-8000-000000157210',
  });
  await writeJson(root, 'input/browser/Default/site-storage.json', {
    entries: [
      {entry_id: 'restricted-local', profile_ref: 'Default', site: 'claude.example', storage_type: 'local_storage', identity_ref: 'restricted-account', value: 'SYNTHETIC_LOCAL'},
      {entry_id: 'normal-session', profile_ref: 'Default', site: 'claude.example', storage_type: 'session_storage', identity_ref: 'normal-account', value: 'SYNTHETIC_SESSION'},
      {entry_id: 'shared-indexeddb', profile_ref: 'Default', site: 'claude.example', storage_type: 'indexeddb', identity_ref: 'shared', value: 'SYNTHETIC_SHARED'},
      {entry_id: 'restricted-cache', profile_ref: 'Default', site: 'claude.example', storage_type: 'cache', identity_ref: 'restricted-account', value: 'SYNTHETIC_CACHE'},
      {entry_id: 'restricted-sw', profile_ref: 'Default', site: 'claude.example', storage_type: 'service_worker', identity_ref: 'restricted-account', value: 'SYNTHETIC_SW'},
    ],
  });
  await writeJson(root, 'input/browser/Profile 1/profile.json', {identity_ref: 'normal-account', profile_name: 'Secondary synthetic profile'});
  await writeJson(root, 'input/browser/Default/cookie-associations.json', {
    cookie_database_ref: 'input/browser/Default/cookies.sqlite',
    cookie_associations: [
      {profile_ref: 'Default', identity_ref: 'restricted-account', selector: {host_key: '.claude.example', top_frame_site_key: 'https://claude.example', has_cross_site_ancestor: 0, name: 'restricted-session', path: '/', source_scheme: 2, source_port: 443}},
      {profile_ref: 'Default', identity_ref: 'normal-account', selector: {host_key: '.claude.example', top_frame_site_key: 'https://claude.example', has_cross_site_ancestor: 0, name: 'normal-session', path: '/', source_scheme: 2, source_port: 443}},
    ],
  });
  await writeJson(root, 'input/wsl/config.json', {identity_ref: 'restricted-account', settings: {legacyCredential: {identity_ref: 'restricted-account'}}});
  await writeJson(root, 'input/backup/old-archive.json', {projectMemory: {keep: true}, legacyProvider: {identity_ref: 'restricted-account'}});
  await writeJson(root, 'input/unknown.json', {schema_version: 'unknown', payload: {do_not_write: true}});
  await mkdir(path.join(root, 'input/cache'), {recursive: true});
  await writeFile(path.join(root, 'input/cache/removable.log'), 'synthetic ordinary cache\n', 'utf8');
  await mkdir(path.join(root, 'input/audit'), {recursive: true});
  await writeFile(path.join(root, 'input/audit/current.log'), 'synthetic protected audit evidence\n', 'utf8');
  await mkdir(path.join(root, 'input/project'), {recursive: true});
  await writeFile(path.join(root, 'input/project/references.jsonl'), '{"project":"keep-me","providerRef":"restricted-provider"}\n', 'utf8');
  await mkdir(path.join(root, 'input'), {recursive: true});
  createCcSwitchDatabase(path.join(root, 'input/cc-switch.sqlite'));
  createCookieDatabase(path.join(root, 'input/browser/Default/cookies.sqlite'));
  return root;
}

async function prepare(root) {
  const service = createSyntheticLocalService({workspaceRoot: root, environment: SYNTHETIC_ENVIRONMENT});
  const scan = await service.discover({mode: 'deep'});
  for (const identity of scan.identities) {
    const status = identity.identity_ref === 'restricted-account' ? 'restricted' : 'normal';
    service.recordAccountAnswer({scanId: scan.scan_id, identityRef: identity.identity_ref, identityFingerprint: identity.identity_fingerprint, status});
  }
  const classification = service.classify({scanId: scan.scan_id});
  const plan = await service.buildActionPlan({scanId: scan.scan_id, recommendationIds: classification.recommendations.map((entry) => entry.recommendation_id)});
  const confirmation = await service.confirmActionPlan({planId: plan.plan_id, version: plan.version, actionIds: plan.actions.map((action) => action.action_id), source: 'local-user'});
  await writeJson(root, 'state/demo.json', {scan_id: scan.scan_id, plan_id: plan.plan_id, version: plan.version, confirmation_id: confirmation.confirmation_id, operation_id: `demo-${randomUUID()}`});
  return {scan, plan, confirmation};
}

async function demo(command, root) {
  if (command === 'init') return print('init', {origin: 'synthetic', workspace: await createSyntheticFixture(root), database_files: ['input/cc-switch.sqlite', 'input/browser/Default/cookies.sqlite']});
  if (!existsSync(root)) throw new Error(`workspace does not exist: ${root}`);
  if (command === 'prepare') {
    const result = await prepare(root);
    return print('prepare', {scan_id: result.scan.scan_id, plan_id: result.plan.plan_id, confirmed_actions: result.confirmation.action_ids.length, gaps: result.scan.coverage.gaps.length});
  }
  const context = JSON.parse(await (await import('node:fs/promises')).readFile(path.join(root, 'state/demo.json'), 'utf8'));
  const service = createSyntheticLocalService({workspaceRoot: root, environment: SYNTHETIC_ENVIRONMENT});
  if (command === 'execute-cancel') {
    const operation = await service.executeConfirmedPlan({planId: context.plan_id, version: context.version, operationId: context.operation_id, cancelAfter: 2});
    return print('execute-cancel', {task_id: operation.operation_id, status: operation.status, applied: operation.receipts.filter((item) => item.status === 'APPLIED').length, not_started: operation.receipts.filter((item) => item.status === 'NOT_STARTED').length});
  }
  if (command === 'status') {
    const operation = service.getTask(context.operation_id);
    return print('status', {task_id: operation.operation_id, status: operation.status, receipts: operation.receipts.length, backups: operation.receipts.filter((item) => item.backup_ref).map((item) => item.backup_ref)});
  }
  if (command === 'resume') {
    const before = service.getTask(context.operation_id);
    const completedBefore = new Set(before.receipts.filter((item) => ['APPLIED', 'RECOVERED_APPLIED', 'ALREADY_ABSENT'].includes(item.status)).map((item) => item.action_id));
    const operation = await service.resumeOperation({operationId: context.operation_id});
    return print('resume', {task_id: operation.operation_id, status: operation.status, skipped_completed: operation.receipts.filter((item) => item.status === 'RECOVERED_APPLIED').length, executed_on_resume: operation.receipts.filter((item) => item.status === 'APPLIED' && !completedBefore.has(item.action_id)).length});
  }
  const operation = service.getTask(context.operation_id);
  const jsonReceipt = operation.receipts.find((item) => item.backup_ref);
  if (!jsonReceipt) throw new Error('no restorable receipt exists');
  if (command === 'restore-preview') {
    const preview = await service.previewRestore({backupRef: jsonReceipt.backup_ref});
    await writeJson(root, 'state/restore.json', {preview_id: preview.preview_id});
    return print('restore-preview', {recoverable: preview.recoverable ? [preview.backup_ref] : [], conflicts: preview.conflicts});
  }
  if (command === 'restore') {
    const restore = JSON.parse(await (await import('node:fs/promises')).readFile(path.join(root, 'state/restore.json'), 'utf8'));
    service.confirmRestore({previewId: restore.preview_id, source: 'local-user'});
    const result = await service.restoreChange({previewId: restore.preview_id});
    return print('restore', {restored: [result.action_id], preserved: ['unrelated current JSON fields'], recheck: result.status});
  }
  if (command === 'report') {
    const report = await service.getReport({scanId: context.scan_id, operationId: context.operation_id});
    return print('report', {json: report.json_path, markdown: report.markdown_path, source_task: context.operation_id});
  }
  throw new Error(`unknown command: ${command}`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const command = process.argv[2];
  const workspaceIndex = process.argv.indexOf('--workspace');
  const workspace = workspaceIndex >= 0 ? process.argv[workspaceIndex + 1] : null;
  if (!command || !workspace) throw new Error('usage: demo.mjs <command> --workspace fixtures/_transient/local/runs/<name>');
  // 守卫要在这里，不能只放在外层运行器：这个文件可以被直接执行。
  await demo(command, assertTransient(workspace, {suite: 'local'}));
}
