export const SCRIPT_VERSION = 'diag-sample-v1';
export const RULESET_VERSION = 'NET_SCORE_0.1';
export const PROOF_SIMULATION = 'simulation';
export const MODES = Object.freeze(['deep', 'quick', 'special']);
export const CATEGORIES = Object.freeze(['exit_ip', 'multipath', 'browser', 'fingerprint', 'claude_tls', 'kernel']);

export const CHECKS = Object.freeze({
  deep: CATEGORIES.slice(),
  quick: ['exit_ip', 'kernel', 'multipath'],
  special: null,
});

export const SUGGESTION = Object.freeze({
  DIRECT: 'DIRECT_FIX',
  CONDITIONAL: 'NEEDS_CONDITIONS',
  REFERENCE: 'REFERENCE_ONLY',
});
