/**
 * 受限原生桥契约：页面侧与 Rust 宿主侧的唯一事实源。
 *
 * Rust 宿主按 `OPS` 实现；页面侧只经这些操作取得本地能力，不另建通道。
 * `tests/delivery/native-chain.test.mjs` 会断言 `commands.rs` 处理的操作与本表完全一致。
 */

export const CONTRACT_VERSION = 'steward-bridge-1';

export const CAPABILITY_GROUPS = Object.freeze({
  network: '经产品网络服务读取实际运行记录、下发受管配置、确认系统保护与生命周期动作；页面看不到服务命令、内核地址或 secret',
  files: '工作区与已授权根（roots/<root_ref>/…）内的文件读写、删除、复制、遍历与目录隔离；真实根只读，改写须单次确认绑定精确目标',
  records: '本地记录库与备份索引',
  databases: 'Chromium Cookie v24 与 CC Switch v18 的读取、改写与恢复',
  emergency: '手动应急上网的第二浏览器会话：枚举可区分候选、按确认开启与关闭',
  control: '本产品控制端的就绪状态，以及首启管理员提交（一次性首启凭据由宿主附加，不交给页面）',
  session: '本应用登录会话材料在宿主保险库里的保存、读取与清除；不进 localStorage、导出或普通日志',
  browser_diag: '默认浏览器诊断：宿主在 127.0.0.1 开一次性监听、用默认浏览器打开带一次性令牌的诊断页、取回唯一一份同源回传；页面给不了别的 URL',
  discovery: '只读发现当前用户的 Claude 相关位置、浏览器 Profile、默认浏览器与 WSL 发行版；授权或撤销扫描范围（授权由宿主弹本地确认，路径由宿主自己测得）',
  logs: '本地日志：宿主、控制端与产品网络服务日志的只读列举与读取（内核日志单独标为含访问明细）；本进程应用日志追加；诊断包写进日志目录下新建的导出目录；打开日志或导出目录。页面给不了路径，只能给白名单里的来源编号',
  notify: '危急系统通知：页面只给固定事件与提示编号，标题与正文由宿主按事件取固定文案；主窗口可见时不另弹，弹不出来如实回失败',
});

/** 每个操作：所属能力组、必需载荷字段、是否需要授权引用。 */
export const OPS = Object.freeze({
  DescribeCapabilities: {group: 'meta', payload: [], authorization: false},

  ReadNetworkState: {group: 'network', payload: ['environment_ref'], authorization: false},
  ApplyNetworkPlan: {
    group: 'network',
    payload: ['operation_id', 'environment_ref', 'plan_ref', 'plan_version', 'assignment_version', 'expected_config_sha256', 'yaml'],
    authorization: true,
  },
  ProtectEnvironment: {group: 'network', payload: ['operation_id', 'environment_ref', 'action', 'processes', 'loopback_policy', 'reason_code'], authorization: true},
  NetworkLifecycle: {group: 'network', payload: ['operation_id', 'environment_ref', 'event'], authorization: true},

  FileRead: {group: 'files', payload: ['path'], authorization: false},
  FileWrite: {group: 'files', payload: ['path', 'bytes'], authorization: true},
  FileRemove: {group: 'files', payload: ['path'], authorization: true},
  FileCopy: {group: 'files', payload: ['from', 'to'], authorization: true},
  FileExists: {group: 'files', payload: ['path'], authorization: false},
  FileWalk: {group: 'files', payload: ['prefixes'], authorization: false},
  DirIsolate: {group: 'files', payload: ['from', 'to'], authorization: true},
  DirPreviewRestore: {group: 'files', payload: ['isolation_path', 'target_path'], authorization: false},
  DirRestore: {group: 'files', payload: ['isolation_path', 'target_path'], authorization: true},

  RecordsLoad: {group: 'records', payload: [], authorization: false},
  RecordSave: {group: 'records', payload: ['type', 'id', 'payload', 'now'], authorization: true},
  BackupSave: {group: 'records', payload: ['backup_ref', 'action_id', 'payload_path', 'metadata', 'now'], authorization: true},

  DbInspect: {group: 'databases', payload: ['path', 'kind'], authorization: false},
  DbMutate: {group: 'databases', payload: ['path', 'kind', 'selector'], authorization: true},
  // 可选 prior_mutations：[{kind, selector}]，先在副本上依次应用，再模拟本条；同一个库上的多条改写靠它串起预期指纹。
  DbSimulate: {group: 'databases', payload: ['path', 'kind', 'selector'], authorization: false},
  // 数据库对象的逻辑指纹与一致快照：经 SQLite 读取（含 WAL 里已提交的内容），不按主文件字节。取不到一致快照就失败。
  DbFingerprint: {group: 'databases', payload: ['path'], authorization: false},
  DbSnapshot: {group: 'databases', payload: ['path'], authorization: false},
  DbPreviewRestore: {group: 'databases', payload: ['path', 'kind', 'selector', 'backup_bytes'], authorization: false},
  DbRestore: {group: 'databases', payload: ['path', 'kind', 'selector', 'backup_bytes'], authorization: true},

  EmergencyHosts: {group: 'emergency', payload: [], authorization: false},
  EmergencyOpen: {group: 'emergency', payload: ['session_id', 'host_id', 'expires_at', 'environment_ref'], authorization: true},
  EmergencyClose: {group: 'emergency', payload: ['session_id', 'environment_ref'], authorization: true},

  ControlStatus: {group: 'control', payload: [], authorization: false},
  ControlSetupAdmin: {group: 'control', payload: ['username', 'password'], authorization: false},

  SessionLoad: {group: 'session', payload: [], authorization: false},
  SessionSave: {group: 'session', payload: ['access_token', 'expires_at', 'user_ref'], authorization: false},
  SessionClear: {group: 'session', payload: [], authorization: false},

  DiscoverEnvironment: {group: 'discovery', payload: [], authorization: false},
  AuthorizeRoots: {group: 'discovery', payload: ['root_refs'], authorization: false},
  RevokeRoots: {group: 'discovery', payload: ['root_refs'], authorization: false},
  BrowserDiagListen: {group: 'browser_diag', payload: ['task_ref', 'environment_ref'], authorization: false},
  BrowserDiagLaunch: {group: 'browser_diag', payload: ['listener_ref', 'session'], authorization: false},
  BrowserDiagReceive: {group: 'browser_diag', payload: ['listener_ref'], authorization: false},
  BrowserDiagClose: {group: 'browser_diag', payload: ['listener_ref'], authorization: false},

  // source_ref 形如 <类别>/<文件名>：host、control、network_service、network_core；只认各类别白名单里的文件名。
  LogSources: {group: 'logs', payload: [], authorization: false},
  LogRead: {group: 'logs', payload: ['source_ref'], authorization: false},
  // 页面流程失败的本地记录：event 为小写短名，fields 只收标量；宿主遮盖秘密字段名。每个失败的原生操作宿主另记一行（操作名与错误码）。
  AppLogAppend: {group: 'logs', payload: ['event'], authorization: false},
  // 诊断包文件：export_ref 形如 diag-YYYYMMDD-HHMMSS-<hex>，新建不覆盖；写失败删掉半截。清单由页面最后写。
  LogExportWrite: {group: 'logs', payload: ['export_ref', 'name', 'bytes'], authorization: false},
  LogOpenFolder: {group: 'logs', payload: ['target'], authorization: false},

  // event 只有 WRONG_ROUTE、PROTECTION_NOT_CONFIRMED、PROTECTION_FAILED；ref 是提示编号。多给任何字段宿主都拒绝。
  NotifyCritical: {group: 'notify', payload: ['event', 'ref'], authorization: false},
});

/** 控制端协议版本：宿主握手与页面都按它核对。 */
export const CONTROL_PROTOCOL = 'steward-control-1';

/**
 * DescribeCapabilities 除能力分组外还回报产品运行配置：
 * 页面自己没有安装信息，控制端地址、受管内核地址、声明环境与 Windows 用户都由宿主给出。
 * control_base_url 只在控制端握手通过后才有值；control 是控制端状态（starting/ready/failed 及日志位置）。
 * network_service 只含产品服务身份、pipe 名与协议版本和链接是否就绪，不含内核地址或任何 secret。
 */
export const PRODUCT_CONFIG_FIELDS = Object.freeze([
  'control_base_url',
  'control',
  'network_service',
  'windows_user',
  'environment_ref',
  'environments',
  'environment',
  'log_root',
]);

/**
 * 授权只有一个来源：原生的 `steward_user_confirm`。
 * 它绑定本地用户交互，自己测量目标指纹，签发并持久化一条记录，返回不可预测的引用。
 * 写命令只收这个引用；原生侧按**记录里的**范围、动作、对象、版本、指纹与期限复核。
 * 页面传来的授权内容从不作数，`confirmed: true` 也不作数。
 *
 * 授权范围：四种授权互不替代，原生侧按范围复核。
 * single_confirmation 覆盖一次用户确认里点名的那一个对象，必须带计划、动作、目标与目标指纹；
 * workspace_owned 只覆盖应用自己的产物目录，不能拿来改用户对象；
 * preauthorized_protection 只覆盖预授权的环境保护、受管配置下发与恢复/维护类生命周期动作；
 * stop_management 是撤本产品保护的显式停止管理，单独确认、只用一次，预授权保护不能代替它。
 */
export const AUTHORIZATION_SCOPES = Object.freeze({
  single_confirmation: {
    ops: ['FileWrite', 'FileRemove', 'FileCopy', 'DirIsolate', 'DirRestore', 'DbMutate', 'DbRestore'],
    requires: ['plan_ref', 'plan_version', 'action_id', 'action', 'native_op', 'target', 'expected_sha256', 'expires_at'],
    single_use: true,
    target_must_match_payload: true,
    fingerprint_must_match_object: true,
  },
  workspace_owned: {
    ops: ['FileWrite', 'FileRemove', 'FileCopy', 'RecordSave', 'BackupSave'],
    requires: ['expires_at'],
    path_prefixes: ['records/', 'backups/', 'exports/', 'audit/', 'reports/', 'state/'],
    target_must_match_payload: false,
    fingerprint_must_match_object: false,
  },
  emergency_session: {
    ops: ['EmergencyOpen', 'EmergencyClose'],
    requires: ['session_ref', 'native_op', 'expires_at'],
    single_use: true,
    target_must_match_payload: false,
    fingerprint_must_match_object: false,
  },
  preauthorized_protection: {
    ops: ['ApplyNetworkPlan', 'ProtectEnvironment', 'NetworkLifecycle'],
    requires: ['environment_ref', 'expires_at'],
    target_must_match_payload: false,
    fingerprint_must_match_object: false,
  },
  stop_management: {
    ops: ['NetworkLifecycle'],
    requires: ['environment_ref', 'native_op', 'expires_at'],
    single_use: true,
    target_must_match_payload: false,
    fingerprint_must_match_object: false,
  },
});

/** 生命周期事件：页面能请求的全部动作。窗口关闭、界面退出不在其中，它们不影响产品服务。 */
export const NETWORK_LIFECYCLE_EVENTS = Object.freeze(['restore_last_valid', 'maintenance_start', 'maintenance_end', 'stop_management']);

/** 载荷里指向被改对象的字段，按操作取第一个存在的。 */
export const TARGET_FIELDS = Object.freeze({
  FileWrite: ['path'],
  FileRemove: ['path'],
  FileCopy: ['from'],
  DirIsolate: ['from'],
  DirRestore: ['target_path'],
  DbMutate: ['path'],
  DbRestore: ['path'],
  RecordSave: [],
  BackupSave: ['payload_path'],
  EmergencyOpen: [],
  EmergencyClose: [],
  ApplyNetworkPlan: [],
  ProtectEnvironment: [],
  NetworkLifecycle: [],
});

/** 已授权根下的真实路径前缀：页面只能这样指代用户自己电脑上的对象。 */
export const REAL_ROOT_PREFIX = 'roots/';

export function isRealPath(value) {
  const text = typeof value === 'string' ? value.replaceAll('\\', '/') : '';
  return text === 'roots' || text.startsWith(REAL_ROOT_PREFIX);
}

/** 载荷里任何路径字段是否指向真实根。 */
export function touchesRealPath(payload = {}) {
  return ['path', 'from', 'to', 'isolation_path', 'target_path', 'payload_path'].some((field) => isRealPath(payload[field]))
    || (Array.isArray(payload.prefixes) && payload.prefixes.some(isRealPath));
}

/** 除确认目标外的路径字段：复制与隔离的去向、恢复的来源、备份载荷，都不许是真实路径。 */
export const SECONDARY_PATH_FIELDS = Object.freeze({
  FileCopy: 'to',
  DirIsolate: 'to',
  DirRestore: 'isolation_path',
  BackupSave: 'payload_path',
});

/** 记录级数据库改写：确认与复核都按数据库的逻辑状态取指纹，不按主文件字节。 */
export const DATABASE_ACTION_KINDS = Object.freeze(['cc_provider_delete', 'cookie_delete']);

export function targetPathFor(op, payload = {}) {
  for (const field of TARGET_FIELDS[op] || []) {
    if (typeof payload[field] === 'string' && payload[field]) return payload[field];
  }
  return null;
}

export const ERROR_CODES = Object.freeze({
  OP_UNKNOWN: 'NATIVE_OP_UNKNOWN',
  PAYLOAD_INVALID: 'NATIVE_PAYLOAD_INVALID',
  AUTHORIZATION_REQUIRED: 'NATIVE_AUTHORIZATION_REQUIRED',
  AUTHORIZATION_SCOPE_INVALID: 'NATIVE_AUTHORIZATION_SCOPE_INVALID',
  AUTHORIZATION_UNKNOWN: 'NATIVE_AUTHORIZATION_UNKNOWN',
  AUTHORIZATION_OP_MISMATCH: 'NATIVE_AUTHORIZATION_OP_MISMATCH',
  AUTHORIZATION_CONSUMED: 'NATIVE_AUTHORIZATION_CONSUMED',
  AUTHORIZATION_STORE_TAMPERED: 'NATIVE_AUTHORIZATION_STORE_TAMPERED',
  CONFIRMATION_DECLINED: 'NATIVE_CONFIRMATION_DECLINED',
  AUTHORIZATION_EXPIRED: 'NATIVE_AUTHORIZATION_EXPIRED',
  AUTHORIZATION_TARGET_MISMATCH: 'NATIVE_AUTHORIZATION_TARGET_MISMATCH',
  OBJECT_DRIFTED: 'NATIVE_OBJECT_DRIFTED',
  OUT_OF_SCOPE: 'NATIVE_PATH_OUT_OF_SCOPE',
  CAPABILITY_UNIMPLEMENTED: 'NATIVE_CAPABILITY_UNIMPLEMENTED',
  IO_FAILED: 'NATIVE_IO_FAILED',
});

export function opNames() {
  return Object.keys(OPS);
}

export function opsForGroup(group) {
  return opNames().filter((name) => OPS[name].group === group);
}

/** `steward_user_confirm` 的请求形状：页面在发起确认前先按这张表自检。 */
export const CONFIRMATION_REQUEST_FIELDS = Object.freeze({
  single_confirmation: ['plan_ref', 'plan_version', 'action_id', 'action', 'native_op', 'target'],
  workspace_owned: [],
  emergency_session: ['session_ref', 'native_op'],
  preauthorized_protection: ['environment_ref'],
  stop_management: ['environment_ref', 'native_op'],
});

/**
 * 一次确认覆盖的那一个原生写操作。
 * 页面按动作种类点名；原生签发时核对它属于该范围，执行时核对它就是当前操作。
 */
export const NATIVE_OP_FOR_ACTION = Object.freeze({
  json_set: 'FileWrite',
  json_remove: 'FileWrite',
  legacy_json_cleanup: 'FileWrite',
  site_storage_remove: 'FileWrite',
  delete_file: 'FileRemove',
  isolate_directory: 'DirIsolate',
  cookie_delete: 'DbMutate',
  cc_provider_delete: 'DbMutate',
});

/** 恢复走的是另一组原生操作。 */
export const NATIVE_OP_FOR_RESTORE = Object.freeze({
  isolate_directory: 'DirRestore',
  cookie_delete: 'DbRestore',
  cc_provider_delete: 'DbRestore',
});

export function nativeOpForAction(kind, {restore = false} = {}) {
  if (restore) return NATIVE_OP_FOR_RESTORE[kind] || 'FileWrite';
  return NATIVE_OP_FOR_ACTION[kind] || null;
}

/** 页面发起确认前的自检；返回 null 表示可以发出。 */
export function checkConfirmationRequest(request = {}) {
  const scope = AUTHORIZATION_SCOPES[request?.scope];
  if (!scope) {
    return {code: ERROR_CODES.AUTHORIZATION_SCOPE_INVALID, reason: `unknown authorization scope ${request?.scope}`};
  }
  for (const field of CONFIRMATION_REQUEST_FIELDS[request.scope] || []) {
    if (request[field] === undefined || request[field] === null || request[field] === '') {
      return {code: ERROR_CODES.AUTHORIZATION_SCOPE_INVALID, reason: `a ${request.scope} confirmation requires ${field}`};
    }
  }
  if (request.scope === 'single_confirmation' && !request.target?.path) {
    return {code: ERROR_CODES.AUTHORIZATION_SCOPE_INVALID, reason: 'a single confirmation requires target.path'};
  }
  if (scope.single_use && !scope.ops.includes(request.native_op)) {
    return {code: ERROR_CODES.AUTHORIZATION_SCOPE_INVALID, reason: `scope ${request.scope} does not cover ${request.native_op}`};
  }
  return null;
}

/**
 * 复核一条**已签发记录**是否覆盖这次调用。只有握着记录的一侧（Rust 宿主，或站在它位置上的替身）
 * 能调用它：页面拿不到记录，也就伪造不出通过这一关的授权。
 * 指纹比对不在这里做，那一步要读磁盘。
 */
export function checkIssuedAuthorization(op, payload = {}, record = null, now = null, reference = null) {
  const spec = OPS[op];
  if (!spec) return {code: ERROR_CODES.OP_UNKNOWN, reason: `unknown native op ${op}`};
  if (!spec.authorization) return null;
  if (typeof reference !== "string" || !reference) {
    return {code: ERROR_CODES.AUTHORIZATION_REQUIRED, reason: `${op} requires a reference issued by steward_user_confirm`};
  }
  if (!record) {
    return {code: ERROR_CODES.AUTHORIZATION_UNKNOWN, reason: `${reference} was never issued by this host`};
  }
  if (record.confirmed !== true) {
    return {code: ERROR_CODES.AUTHORIZATION_UNKNOWN, reason: `${record.authorization_ref} carries no local confirmation`};
  }
  const scope = AUTHORIZATION_SCOPES[record.scope];
  if (!scope) return {code: ERROR_CODES.AUTHORIZATION_SCOPE_INVALID, reason: `unknown authorization scope ${record.scope}`};
  if (!scope.ops.includes(op)) {
    return {code: ERROR_CODES.AUTHORIZATION_SCOPE_INVALID, reason: `scope ${record.scope} does not cover ${op}`};
  }
  for (const field of scope.requires) {
    // expected_sha256 允许显式为 null：那表示授权要求目标此刻不存在（目录已被隔离走）。
    const missing = field === 'expected_sha256'
      ? !(field in record)
      : record[field] === undefined || record[field] === null || record[field] === '';
    if (missing) {
      return {code: ERROR_CODES.AUTHORIZATION_SCOPE_INVALID, reason: `scope ${record.scope} requires ${field}`};
    }
  }
  if (record.expires_at && now && Date.parse(now) >= Date.parse(record.expires_at)) {
    return {code: ERROR_CODES.AUTHORIZATION_EXPIRED, reason: `authorization ${record.authorization_ref} expired at ${record.expires_at}`};
  }
  if (scope.single_use) {
    // 一次确认绑定一个精确原生操作，且只用一次：跨动作与重放都在这里被挡下。
    if (record.native_op !== op) {
      return {code: ERROR_CODES.AUTHORIZATION_OP_MISMATCH, reason: `authorization covers ${record.native_op} but ${op} was requested`};
    }
    if (record.consumed_at) {
      return {code: ERROR_CODES.AUTHORIZATION_CONSUMED, reason: `${record.authorization_ref} was already used once`};
    }
  }
  const target = targetPathFor(op, payload);
  if (scope.path_prefixes && target && !scope.path_prefixes.some((prefix) => target.startsWith(prefix))) {
    return {code: ERROR_CODES.AUTHORIZATION_TARGET_MISMATCH, reason: `scope ${record.scope} may not touch ${target}`};
  }
  // 真实根只能作为单次确认绑定的那一个目标出现；工作区自有授权完全碰不到真实根。
  if (isRealPath(payload[SECONDARY_PATH_FIELDS[op]])) {
    return {code: ERROR_CODES.AUTHORIZATION_TARGET_MISMATCH, reason: `${op} may only touch a real path as its confirmed target`};
  }
  if (scope.path_prefixes && touchesRealPath(payload)) {
    return {code: ERROR_CODES.AUTHORIZATION_TARGET_MISMATCH, reason: `scope ${record.scope} may not touch an authorized real root`};
  }
  if (scope.target_must_match_payload) {
    const granted = record.target?.path || null;
    if (!granted || !target || granted !== target) {
      return {code: ERROR_CODES.AUTHORIZATION_TARGET_MISMATCH, reason: `authorization covers ${granted} but the payload targets ${target}`};
    }
  }
  if (record.scope === 'emergency_session' && record.session_ref !== payload.session_id) {
    return {code: ERROR_CODES.AUTHORIZATION_TARGET_MISMATCH, reason: `authorization covers session ${record.session_ref} but the payload targets ${payload.session_id}`};
  }
  if (['preauthorized_protection', 'stop_management'].includes(record.scope) && record.environment_ref !== payload.environment_ref) {
    return {code: ERROR_CODES.AUTHORIZATION_TARGET_MISMATCH, reason: `authorization covers ${record.environment_ref} but the payload targets ${payload.environment_ref}`};
  }
  if (op === 'NetworkLifecycle' && (payload.event === 'stop_management') !== (record.scope === 'stop_management')) {
    return {code: ERROR_CODES.AUTHORIZATION_SCOPE_INVALID, reason: `scope ${record.scope} does not cover network lifecycle event ${payload.event}`};
  }
  return null;
}

/** 页面侧在发出请求前先按契约自检，错误载荷不进原生层。 */
export function assertPayload(op, payload = {}) {
  const spec = OPS[op];
  if (!spec) throw Object.assign(new Error(`unknown native op ${op}`), {code: ERROR_CODES.OP_UNKNOWN});
  for (const field of spec.payload) {
    if (payload[field] === undefined || payload[field] === null) {
      throw Object.assign(new Error(`native op ${op} requires ${field}`), {code: ERROR_CODES.PAYLOAD_INVALID});
    }
  }
  return spec;
}
