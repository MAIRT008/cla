export const LOCAL_RULESET_VERSION = 'fd01-local-v1';

const SECRET_KEY = /(?:token|cookie|password|secret|private.?key|proxy.*(?:pass|auth)|credential)/i;
const SECRET_VALUE = /(?:\b(?:token|cookie|password|secret|credential|authorization)\b\s*[:=]\s*\S+|\bbearer\s+\S+|\bsk-[A-Za-z0-9_-]+|\bSYNTHETIC_[A-Z0-9_]*(?:TOKEN|COOKIE|SECRET|PASSWORD)[A-Z0-9_]*)/i;

export function scoreProblems(problems, coverage = {}) {
  const active = problems.filter((problem) => !problem.false_positive && !problem.closed);
  const unique = new Map();
  for (const problem of active) {
    const key = problem.root_cause_ref || problem.problem_id;
    if (!unique.has(key)) unique.set(key, problem);
  }

  const deduplicated = [...unique.values()];
  const counts = {critical: 0, important: 0, minor: 0};
  for (const problem of deduplicated) {
    if (Object.hasOwn(counts, problem.severity)) counts[problem.severity] += 1;
  }

  const points = counts.critical * 40 + counts.important * 15 + Math.min(10, counts.minor * 2);
  let score = Math.max(0, 100 - points);
  if (counts.critical) score = Math.min(score, 59);
  if (counts.important) score = Math.min(score, 84);
  const complete = coverage.complete === true && !coverage.critical_gap;

  return {
    ruleset_version: LOCAL_RULESET_VERSION,
    status: complete ? 'final' : 'unknown',
    score: complete ? score : null,
    counts,
    deducted_points: points,
    coverage_gaps: coverage.gaps || [],
    deduplicated_problem_refs: deduplicated.map((item) => item.problem_id),
  };
}

export function redactForExport(value) {
  if (Array.isArray(value)) return value.map(redactForExport);
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value).map(([key, child]) => [key, SECRET_KEY.test(key) ? '[redacted]' : redactForExport(child)]),
    );
  }
  if (typeof value === 'string' && SECRET_VALUE.test(value)) return '[redacted]';
  if (typeof value === 'string' && value.length > 240) return `${value.slice(0, 240)}...[truncated]`;
  return value;
}

export function makeMarkdownReport(report) {
  const lines = [
    '# Local environment report',
    '',
    `- Report: ${report.report_id}`,
    `- Scan: ${report.scan_id}`,
    `- Mode: ${report.mode}`,
    `- Scope: ${(report.scan_scope || []).join(', ') || 'not recorded'}`,
    `- Rules: ${report.ruleset_version}`,
    `- Score: ${report.score.status === 'final' ? report.score.score : 'unknown'}`,
    `- Coverage: ${report.coverage.status}`,
    '',
    '## Findings',
  ];
  for (const finding of report.findings) {
    lines.push(`- [${finding.severity}] ${finding.summary} (${finding.problem_id})`);
  }
  if (!report.findings.length) lines.push('- No actionable findings in the selected scope.');
  lines.push('', '## Result groups');
  for (const group of report.result_groups || []) lines.push(`- ${group.category}: ${group.object_refs.length} object(s), ${group.recommendation_ids.length} recommendation(s)`);
  if (!(report.result_groups || []).length) lines.push('- No standard result groups recorded.');
  lines.push('', '## Account decisions');
  for (const answer of report.account_answers || []) lines.push(`- ${answer.identity_ref}: ${answer.status}`);
  if (!(report.account_answers || []).length) lines.push('- No current account decision recorded.');
  lines.push('', '## Actions');
  for (const receipt of report.receipts) {
    lines.push(`- ${receipt.action_id}: ${receipt.status}${receipt.code ? ` (${receipt.code})` : ''}`);
  }
  if (!report.receipts.length) lines.push('- No execution receipt recorded.');
  lines.push('', '## Rechecks');
  for (const recheck of report.rechecks || []) lines.push(`- ${recheck.action_id}: ${recheck.status}`);
  if (!(report.rechecks || []).length) lines.push('- No action recheck recorded.');
  lines.push('', '## Retained and restored');
  lines.push(`- Retained recommendations: ${(report.retained_recommendation_ids || []).join(', ') || 'none'}`);
  for (const decision of report.problem_decisions || []) lines.push(`- Decision: ${decision.problem_id} ${decision.decision} (${decision.reason})`);
  for (const restore of report.restore_sources || []) lines.push(`- Restore: ${restore.action_id} from ${restore.backup_ref}`);
  lines.push('', '## Coverage gaps');
  for (const gap of report.coverage.gaps) lines.push(`- ${gap.code}: ${gap.message}`);
  if (!report.coverage.gaps.length) lines.push('- None recorded.');
  return `${lines.join('\n')}\n`;
}
