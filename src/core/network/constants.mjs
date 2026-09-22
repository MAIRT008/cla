export const MODES = Object.freeze(['daily_single_ip', 'claude_single_ip', 'claude_dual_ip']);

export const MODE_LABELS = Object.freeze({
  daily_single_ip: '日常单 IP',
  claude_single_ip: 'Claude 专用单 IP',
  claude_dual_ip: 'Claude 专用双 IP',
});

export const RECOMMENDED_FOR = Object.freeze({
  free: 'daily_single_ip',
  pro: 'claude_single_ip',
  max_5x: 'claude_single_ip',
  max_20x: 'claude_dual_ip',
});

export const CLAUDE_DOMAINS = Object.freeze([
  'claude.ai',
  'claude.com',
  'anthropic.com',
  'clau.de',
  'claudeusercontent.com',
  'claudemcpclient.com',
  'claudemcpcontent.com',
]);

export const DEFAULT_CLAUDE_PROCESSES = Object.freeze(['claude.exe']);
export const DEFAULT_MANAGED_BROWSER_PROCESSES = Object.freeze(['claude-browser.exe']);

export const GROUP = Object.freeze({
  FRONT: 'FRONT',
  EXIT_A: 'EXIT-A',
  EXIT_B: 'EXIT-B',
  PROXY_A: 'PROXY-A',
  PROXY_B: 'PROXY-B',
  CLAUDE: 'CLAUDE-FIXED',
  GENERAL: 'GENERAL-EGRESS',
  DIRECT: 'DIRECT',
  REJECT: 'REJECT',
  EMERGENCY: 'EMERGENCY-EGRESS',
});

export const AUTH_KIND = Object.freeze({
  ONCE: 'ONCE_CONFIRMED',
  MAINTENANCE: 'MAINTENANCE_SCOPE',
  PROTECTION: 'PREAUTHORIZED_PROTECTION',
  EMERGENCY: 'EMERGENCY_CONFIRMED',
});

export const RECORD = Object.freeze({
  STATE: 'network_state_v1',
  OPERATION: 'network_operation_v1',
  WHITELIST: 'network_whitelist_v1',
  RESTORE: 'network_restore_v1',
  INCIDENT: 'network_incident_v1',
  EMERGENCY: 'network_emergency_v1',
  EVENT: 'network_event_v1',
});

export const BROAD_LABELS = Object.freeze(new Set([
  'com', 'net', 'org', 'edu', 'gov', 'info', 'io', 'co', 'cn', 'local', 'localhost', 'invalid', '*',
]));

export const PRODUCT_CLASSIFICATION_VERSION = 'product-v1';
export const PROOF_SIMULATION = 'simulation';
