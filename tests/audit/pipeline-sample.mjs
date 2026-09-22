import fs from 'node:fs/promises';
import path from 'node:path';
import {runAuditPipeline} from '../../src/core/audit/index.mjs';
import {FixtureAuditStore} from '../../src/adapters/audit/fixtureStore.mjs';

const root = await fs.mkdtemp(path.join(path.resolve('fixtures/audit'), 't2-pipeline-run-'));
const store = new FixtureAuditStore(root);
const now = '2026-03-08T16:00:00Z';
await store.writeText('source/service_latest.log', [
  'time="2026-03-08T15:00:00Z" [TCP] (claude.exe) --> api.anthropic.com:443 using CLAUDE-FIXED[COX-Fixed-Chain]',
  'time="2026-03-08T15:01:00Z" [TCP] dial DIRECT (match DomainSuffix/anthropic.com) (claude.exe) --> api.anthropic.com:443 error: retry using CLAUDE-FIXED[COX-Fixed-Chain] timeout',
].join('\n'), {overwrite: false});

const result = await runAuditPipeline({
  now,
  sourceRoot: 'source',
  archiveRoot: 'archive',
  approvedSourceNames: ['service_latest.log'],
  mapping: {version: 'legacy-v2', fixedA: {route: 'CLAUDE-FIXED', member: 'COX-Fixed-Chain'}},
  trafficState: {
    totals: {uploadBytes: 0, downloadBytes: 0},
    observations: {'core:core-a': {uploadBytes: 100, downloadBytes: 200, resetId: 'boot-1', observedAt: '2026-03-08T14:59:00Z'}},
    coverageIssues: [],
  },
  trafficSamples: [{sourceKind: 'core', coreInstanceId: 'core-a', resetId: 'boot-1', uploadBytes: 140, downloadBytes: 260, observedAt: '2026-03-08T15:02:00Z'}],
  quota: {source: 'synthetic-server', status: 'ACTIVE', usedBytes: 100, limitBytes: 1000, observedAt: now},
  protection: {status: 'VERIFIED'},
  reportRoot: 'reports',
}, store);

console.log(JSON.stringify({
  artifactRoot: root,
  archiveEntries: result.evidence.archive.entries.map((entry) => entry.archivePath),
  reportPaths: result.delivery.paths,
  reportId: result.report.reportId,
  routeResult: result.report.routeResult,
  trafficTotals: result.report.traffic.totals,
}, null, 2));
