import assert from 'node:assert/strict';
import test from 'node:test';

const audit = await import('../../src/core/audit/index.mjs').catch(() => null);

test('FD-04/F09-F13 preserves legacy v2 categories and declares product scope', () => {
  assert.ok(audit, 'T2 audit consumer module must exist');

  const legacy = {
    version: 'legacy-v2',
    fixedA: {route: 'CLAUDE-FIXED', member: 'COX-Fixed-Chain'},
  };
  const product = {
    version: 'product-v1',
    fixedA: {route: 'SYNTHETIC-A'},
    managedBrowserProcesses: ['claude-browser.exe'],
  };

  assert.equal(audit.classifyRoute({process: 'claude.exe', destination: 'api.anthropic.com:443', chain: ['CLAUDE-FIXED', 'COX-Fixed-Chain'], outcome: 'connected'}, legacy).classification, 'PASS_ROUTE');
  assert.equal(audit.classifyRoute({process: 'claude.exe', destination: 'api.anthropic.com:443', chain: ['CLAUDE-FIXED', 'COX-Fixed-Chain'], outcome: 'timeout'}, legacy).classification, 'ROUTE_ERROR');
  assert.equal(audit.classifyRoute({process: 'claude.exe.old.1700000000', destination: 'claude.ai:443', chain: ['DIRECT'], outcome: 'connected'}, legacy).classification, 'WRONG_ROUTE');
  assert.equal(audit.classifyRoute({process: 'github-mcp-server.exe', destination: 'telemetry.vendor.example:443', chain: ['REJECT'], outcome: 'rejected'}, legacy).classification, 'SAFE_REJECT');

  const malicious = audit.classifyRoute({process: 'node.exe', destination: 'claude.ai.evil.example:443', chain: ['SYNTHETIC-A'], outcome: 'connected'}, product);
  assert.equal(malicious.classification, 'UNKNOWN');
  assert.equal(malicious.reason, 'OUT_OF_SCOPE');
  assert.equal(audit.classifyRoute({process: 'chrome.exe', destination: 'example.com:443', chain: ['SYNTHETIC-A'], outcome: 'connected'}, product).classification, 'UNKNOWN');
  assert.equal(audit.classifyRoute({process: 'claude-browser.exe', destination: 'example.com:443', chain: ['SYNTHETIC-A'], outcome: 'connected'}, product).classification, 'PASS_ROUTE');
  assert.equal(audit.classifyRoute({process: 'claude.exe', destination: 'api.anthropic.com:443', chain: ['DIRECT'], outcome: 'connected'}, product).classification, 'WRONG_ROUTE');
});

test('FD-04/F12 keeps missing route evidence unknown instead of passing it', () => {
  assert.ok(audit, 'T2 audit consumer module must exist');
  const result = audit.classifyRoute({process: 'claude.exe', destination: 'api.anthropic.com:443', chain: [], outcome: 'connected'}, {version: 'product-v1', fixedA: {route: 'SYNTHETIC-A'}});
  assert.equal(result.classification, 'UNKNOWN');
  assert.equal(result.reason, 'MISSING_ROUTE');
});
