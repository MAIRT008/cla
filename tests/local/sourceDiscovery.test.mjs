import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {test} from 'node:test';

import {createLocalService} from '../../src/core/local/index.mjs';

const hash = value => createHash('sha256').update(value).digest('hex');

function createPort() {
  const files = new Map([
    ['input/code/settings.json', new TextEncoder().encode(JSON.stringify({env: {
      ANTHROPIC_AUTH_TOKEN: 'SYNTHETIC_CODE_TOKEN',
      ANTHROPIC_BASE_URL: 'https://legacy.synthetic.invalid',
    }}))],
    ['input/cc-switch.sqlite', new Uint8Array([1, 2, 3])],
  ]);
  const records = new Map();
  const adapter = {
    clock: () => '2026-09-13T00:00:00.000Z',
    hashBytes: hash,
    async walk(scopes) {
      return [...files].filter(([relativePath]) => scopes.some(scope => relativePath === scope || relativePath.startsWith(`${scope}/`)))
        .map(([relative_path, bytes]) => ({relative_path, status: 'found', size: bytes.byteLength}));
    },
    async readBytes(relativePath) { return files.get(relativePath); },
    async fingerprint(relativePath) { return hash(files.get(relativePath)); },
    async fingerprintDatabase(relativePath) { return hash(files.get(relativePath)); },
    async inspectDatabase(relativePath, kind) {
      assert.equal(relativePath, 'input/cc-switch.sqlite');
      assert.equal(kind, 'cc_switch_sqlite');
      return {providers: [{provider_id: 'provider-a', app_type: 'claude', identity_ref: 'restricted-account', protected_usage: false}]};
    },
    async mutateDatabase() { throw new Error('read-only test adapter'); },
    saveRecord(type, id, payload) { records.set(id, {type, payload: structuredClone(payload)}); },
    getRecord(id, type) {
      const record = records.get(id);
      return record && (!type || record.type === type) ? structuredClone(record.payload) : null;
    },
    listRecords(type) { return [...records.values()].filter(record => !type || record.type === type).map(record => structuredClone(record.payload)); },
  };
  return createLocalService({
    adapter,
    environment: {
      scopes: ['input'],
      json_shapes: [{relative_path: 'input/code/settings.json', role: 'claude_code_settings'}],
      identity_associations: {
        'input/code/settings.json': {
          'env.ANTHROPIC_AUTH_TOKEN': {identity_ref: 'restricted-account', provider_id: 'provider-a'},
        },
      },
    },
  });
}

async function observe(accountStatus) {
  const service = createPort();
  const scan = await service.discover({mode: 'deep'});
  const identity = scan.identities.find(entry => entry.identity_ref === 'restricted-account');
  await service.recordAccountAnswer({
    scanId: scan.scan_id,
    identityRef: identity.identity_ref,
    identityFingerprint: identity.identity_fingerprint,
    status: accountStatus,
  });
  return service.classify({scanId: scan.scan_id});
}

test('standard discovery attributes an actual Code credential to an inspected restricted Provider', async () => {
  const restricted = await observe('restricted');
  const normal = await observe('normal');
  const selector = candidate => candidate.relative_path === 'input/code/settings.json'
    && candidate.selector?.field_path === 'env.ANTHROPIC_AUTH_TOKEN';

  assert.equal(restricted.recommendations.filter(selector).length, 1);
  assert.equal(normal.recommendations.filter(selector).length, 0);
});
