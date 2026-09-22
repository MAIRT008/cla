import {readFile} from 'node:fs/promises';
import path from 'node:path';
import {createDesktopComposition} from '../../apps/desktop-ui/compose.mjs';

export const PROTECTED_BYSTANDERS = [
  'input/project/references.jsonl',
  'input/audit/current.log',
  'input/backup/old-archive.json',
];

export async function readWorkspace(compose, relative) {
  return readFile(path.join(compose.root, relative), 'utf8');
}

export async function snapshotBystanders(compose) {
  const entries = {};
  for (const relative of PROTECTED_BYSTANDERS) entries[relative] = await readWorkspace(compose, relative);
  return entries;
}

export async function assertBystandersUnchanged(assert, compose, before) {
  for (const [relative, content] of Object.entries(before)) {
    assert.equal(await readWorkspace(compose, relative), content, `${relative} 不在本次范围内，不得改动`);
  }
}

export async function scanAndAnswer(compose, mode = 'deep') {
  const scan = await compose.local.discover({mode});
  for (const identity of scan.identities) {
    compose.local.recordAccountAnswer({
      scanId: scan.scan_id,
      identityRef: identity.identity_ref,
      identityFingerprint: identity.identity_fingerprint,
      status: identity.identity_ref === 'restricted-account' ? 'restricted' : 'normal',
    });
  }
  return scan;
}

export async function confirmedLocalPlan(compose, scanId) {
  const classification = compose.local.classify({scanId});
  const plan = await compose.local.buildActionPlan({
    scanId,
    recommendationIds: (classification.recommendations || []).map((item) => item.recommendation_id),
  });
  const actionIds = plan.actions.map((item) => item.action_id);
  const confirmation = await compose.local.confirmActionPlan({planId: plan.plan_id, version: plan.version, actionIds, source: 'local-user'});
  return {classification, plan, confirmation, actionIds};
}

export function aiTaskRecord(compose, taskId) {
  return compose.store.getRecord(taskId, 'ai_task_v1');
}

export async function composition(label, options = {}) {
  return createDesktopComposition(label, options);
}
