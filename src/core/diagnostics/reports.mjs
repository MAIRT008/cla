import {RULESET_VERSION} from './constants.mjs';

const SECRET_KEY = /(?:token|cookie|password|secret|private.?key|credential|authorization)/i;

export function toDiagnosticView(result) {
  const issues = result.issues || [];
  return {
    task_id: result.task_id,
    mode: result.mode,
    status: result.status,
    score: result.scoring?.score ?? null,
    score_status: result.scoring?.status,
    environment_ref: result.environment_ref,
    profile_ref: result.profile_ref,
    categories: result.categories_completed,
    issue_count: issues.length,
    critical: issues.filter((item) => item.severity === 'critical').length,
    important: issues.filter((item) => item.severity === 'important').length,
    mild: issues.filter((item) => item.severity === 'mild').length,
    gaps: (result.observations || []).filter((item) => item.limitation || ['SERVICE_NOT_CONFIGURED', 'UNAVAILABLE', 'NOT_CAPTURED', 'NO_RESULT', 'REQUEST_FAILED'].includes(item.status)).map((item) => ({check_id: item.check_id, status: item.status, limitation: item.limitation})),
  };
}

function redactValue(value, depth = 0) {
  if (value == null) return value;
  if (depth > 8) return {redacted: 'DEPTH_LIMIT'};
  if (Array.isArray(value)) return value.map((item) => redactValue(item, depth + 1));
  if (typeof value !== 'object') return value;
  const out = {};
  for (const [key, item] of Object.entries(value)) {
    if (SECRET_KEY.test(key)) continue;
    out[key] = redactValue(item, depth + 1);
  }
  return out;
}

export function redactDiagnostic(result) {
  if (!result || typeof result !== 'object') return result;
  return redactValue(structuredClone(result));
}

export function renderDiagnosticMarkdown(result) {
  const view = toDiagnosticView(result);
  const lines = [
    `# 诊断报告 ${result.task_id}`,
    '',
    `- 模式: ${result.mode}`,
    `- 规则: ${RULESET_VERSION}`,
    `- 状态: ${view.status}`,
    `- 分数: ${view.score == null ? '未完成' : view.score}`,
    `- 环境: ${result.environment_ref}`,
    `- Profile: ${result.profile_ref || '未绑定'}`,
    '',
    '## 问题',
  ];
  for (const issue of result.issues || []) {
    lines.push(`- ${issue.severity || 'info'} ${issue.kind} (${issue.root_cause_id})`);
  }
  lines.push('', '## 缺口');
  for (const gap of view.gaps) lines.push(`- ${gap.check_id}: ${gap.status} ${gap.limitation || ''}`);
  return `${lines.join('\n')}\n`;
}

export function diagnosticSummaryForAudit(result) {
  const view = toDiagnosticView(result);
  return {
    diagnostic_task_id: result.task_id,
    mode: result.mode,
    score_status: view.score_status,
    issue_count: view.issue_count,
    evidence_refs: (result.observations || []).map((item) => item.evidence_ref),
    does_not_override_daily_fail: true,
  };
}

export function persistDiagnosticReport(store, result) {
  const redacted = redactDiagnostic(result);
  const report = {
    task_id: result.task_id,
    markdown: renderDiagnosticMarkdown(redacted),
    json: redacted,
    audit_summary: diagnosticSummaryForAudit(redacted),
    restore_refs: (store.listRecords?.('diagnostic_restore') || []).filter((item) => item.plan_id?.includes(result.task_id)).map((item) => item.plan_id),
  };
  store.saveRecord('diagnostic_report', `diag-report-${result.task_id}`, report);
  return report;
}
