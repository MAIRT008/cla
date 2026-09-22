export function expectedFromAssignment(assignment) {
  if (!assignment || typeof assignment !== 'object') {
    return {A: null, B: null, timezone: null, utc_offset_minutes: null, source: 'MISSING'};
  }
  const exitA = assignment.resources?.[assignment.roles?.A] || assignment.resources?.[assignment.resource_refs?.exit_a];
  const exitB = assignment.resources?.[assignment.roles?.B] || assignment.resources?.[assignment.resource_refs?.exit_b];
  return {
    A: assignment.expected_exits?.A || exitA?.public_ip || exitA?.exit_ip || null,
    B: assignment.expected_exits?.B || exitB?.public_ip || exitB?.exit_ip || null,
    timezone: assignment.expected_timezone || assignment.template?.timezone || null,
    utc_offset_minutes: assignment.expected_utc_offset_minutes ?? null,
    dns_resolvers: assignment.expected_dns_resolvers || assignment.template?.dns_resolvers || [],
    source: 'assignment',
  };
}
