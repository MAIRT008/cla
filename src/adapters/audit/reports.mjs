const REPORT_ROOT = 'reports';
const decoder = new TextDecoder();

/** 读回已交付的日报产物；只消费 T2 写下的文件，不重新生成报告。 */
export async function loadAuditReports(auditStore, reportRoot = REPORT_ROOT) {
  const files = await auditStore.listFiles(reportRoot);
  const reports = [];
  for (const file of files) {
    if (!file.path.endsWith('daily-audit.json')) continue;
    try { reports.push({path: file.path, report: JSON.parse(decoder.decode(file.bytes))}); } catch { /* corrupt artifacts stay out of the listing */ }
  }
  return reports.sort((left, right) => String(left.report.reportDate).localeCompare(String(right.report.reportDate)));
}

/** 读回 AI 附注产物；附注与标准日报分开存放。 */
export async function loadAiNotes(auditStore, reportRoot = REPORT_ROOT) {
  const files = await auditStore.listFiles(`${reportRoot}/ai-notes`);
  const notes = [];
  for (const file of files) {
    try { notes.push({path: file.path, note: JSON.parse(decoder.decode(file.bytes))}); } catch { /* ignore unreadable note */ }
  }
  return notes;
}
