import {PROOF_SIMULATION, RECORD} from './constants.mjs';
import {nowIso} from './time.mjs';
import {stateId} from './apply.mjs';
import {resolveApprovedProcessPaths, resolveApprovedProtection} from './protectedProcesses.mjs';

const LIMITED_RETRY = 3;

function save(store, request, state) {
  if (store?.saveRecord) store.saveRecord(RECORD.STATE, stateId(request), state);
  return state;
}

export function advanceLifecycle(state, event, ports = {}) {
  const now = nowIso(ports.clock);
  const current = {
    proof_scope: PROOF_SIMULATION,
    lifecycle: 'installed',
    network_enabled: false,
    ui_visible: true,
    service_running: false,
    protection: {status: 'INACTIVE'},
    retry_count: 0,
    last_valid_plan: null,
    disk_full: false,
    conflict: null,
    ...state,
    observed_at: now,
  };
  const type = event?.type;
  const request = {user_ref: current.user_ref, environment_ref: current.environment_ref};

  if (type === 'first_open') {
    current.lifecycle = 'first_open_readonly';
    current.network_enabled = false;
    current.actions = [{action: 'observe', proxy_takeover: false}];
    current.effects = {proxy_changed: false, protection: 'INACTIVE'};
    return save(ports.store, request, current);
  }
  if (type === 'confirm_enable') {
    current.lifecycle = 'enabled';
    current.network_enabled = true;
    current.service_running = true;
    current.boot_authorized = event.boot_authorized === true;
    current.actions = [{action: 'protection_first'}, {action: 'apply_assigned_plan'}];
    current.effects = {protection_ready_required: true, applied: 'PENDING'};
    return save(ports.store, request, current);
  }
  if (type === 'close_window') {
    current.ui_visible = false;
    current.lifecycle = 'window_closed';
    current.service_running = current.network_enabled;
    current.actions = [{action: 'keep_service'}];
    current.effects = {service_running: current.service_running, protection_retained: true, core_stopped: false};
    if (ports.protection?.markUiExit) current.effects.protection = ports.protection.markUiExit();
    return save(ports.store, request, current);
  }
  if (type === 'boot') {
    current.lifecycle = current.boot_authorized ? 'boot_authorized' : 'boot_unauthorized';
    current.actions = current.boot_authorized ? [{action: 'protection_first'}, {action: 'load_last_valid'}] : [{action: 'no_auto_protect'}];
    current.effects = {auto_protected: current.boot_authorized === true};
    return save(ports.store, request, current);
  }
  if (type === 'restart' || type === 'wake') {
    current.lifecycle = type;
    current.actions = type === 'wake'
      ? [{action: 'read_back'}, {action: 'protection_first'}, {action: 'load_last_valid_unrevoked'}]
      : [{action: 'protection_first'}, {action: 'load_last_valid_unrevoked'}];
    current.effects = {unknown_proxy_released: false, coverage_gap: type === 'wake'};
    current.retry_count = 0;
    return save(ports.store, request, current);
  }
  if (type === 'core_crash') {
    current.lifecycle = 'core_crash';
    current.retry_count = (current.retry_count || 0) + 1;
    current.actions = [{action: 'keep_os_protection'}, {action: current.retry_count <= LIMITED_RETRY ? 'limited_restart' : 'stop_retry'}];
    current.effects = {direct_released: false, retry: current.retry_count <= LIMITED_RETRY, retry_count: current.retry_count};
    if (ports.core?.crash) ports.core.crash();
    return save(ports.store, request, current);
  }
  if (type === 'exit_ui') {
    current.ui_visible = false;
    current.lifecycle = 'ui_exited';
    current.service_running = true;
    current.actions = [{action: 'keep_network_service'}];
    current.effects = {service_running: true, management_stopped: false};
    return save(ports.store, request, current);
  }
  if (type === 'stop_management') {
    current.lifecycle = 'management_stopped';
    current.network_enabled = false;
    current.service_running = false;
    current.actions = [{action: 'stop_management_restore_original'}];
    current.effects = {management_stopped: true, claude_unprotected: true, requires_explicit_confirm: true};
    return save(ports.store, request, current);
  }
  if (type === 'maintenance_start') {
    current.lifecycle = 'maintenance';
    current.actions = [{action: 'keep_os_protection'}, {action: 'stop_core_for_maintenance'}];
    current.effects = {protection_retained: true, direct_released: false, core_stopped: 'PENDING'};
    return save(ports.store, request, current);
  }
  if (type === 'maintenance_end') {
    current.lifecycle = 'maintenance_ended';
    current.actions = [{action: 'protection_first'}, {action: 'start_core_last_valid'}];
    current.effects = {requires_recheck: true, unknown_proxy_released: false};
    return save(ports.store, request, current);
  }
  if (type === 'upgrade_failed') {
    current.lifecycle = 'upgrade_failed';
    current.actions = [{action: 'revert_last_valid'}];
    current.effects = {reverted: Boolean(current.last_valid_plan || current.expected), quota_reset: false};
    return save(ports.store, request, current);
  }
  if (type === 'uninstall') {
    const owned = (event.settings || []).filter((item) => item.owned_by === 'this_app' && item.externally_modified !== true);
    const skipped = (event.settings || []).filter((item) => item.owned_by !== 'this_app' || item.externally_modified === true);
    current.lifecycle = 'uninstalled';
    current.actions = [{action: 'revoke_owned_unmodified'}];
    current.effects = {revoked: owned.map((item) => item.id), skipped: skipped.map((item) => ({id: item.id, reason: item.externally_modified ? 'EXTERNAL_MODIFICATION' : 'NOT_OWNED'}))};
    return save(ports.store, request, current);
  }
  if (type === 'external_proxy_conflict') {
    current.conflict = {detected: true, forced_stop: false, names: event.names || []};
    current.actions = [{action: 'report_conflict'}];
    current.effects = {external_stopped: false, imported_secrets: false};
    return save(ports.store, request, current);
  }
  if (type === 'disk_full') {
    current.disk_full = true;
    current.actions = [{action: 'keep_protection_stop_new_archive'}];
    current.effects = {protection_retained: true, archive_writes: 'STOPPED', evidence_deleted: false};
    return save(ports.store, request, current);
  }
  current.lifecycle = 'unknown_event';
  current.actions = [];
  current.effects = {ignored: true};
  return save(ports.store, request, current);
}

export async function executeLifecycle(state, event, ports = {}) {
  const next = advanceLifecycle(state, event, ports);
  const executed = [];
  let protectionConfirmed = false;
  for (const item of next.actions || []) {
    if (item.action === 'protection_first' || item.action === 'keep_os_protection') {
      if (ports.protection?.requestProtection) {
        const scope = await resolveApprovedProtection({state: next, event, control: ports.control, userRef: next.user_ref || event?.user_ref});
        const result = await ports.protection.requestProtection({
          action: 'block_new',
          environment_ref: next.environment_ref,
          authorization_kind: 'PREAUTHORIZED_PROTECTION',
          processes: scope.processes,
          loopback_policy: scope.loopback_policy,
        });
        protectionConfirmed = result.new_connections_restricted === true;
        executed.push({action: item.action, status: result.status, new_connections_restricted: protectionConfirmed});
        next.protection = {status: result.status, new_connections_restricted: protectionConfirmed};
      }
    }
    // 维护停内核的客户端门槛：本次保护请求没有确认新连接受限，就不发停内核命令（服务端另有同样的门槛）。
    if (item.action === 'stop_core_for_maintenance' && ports.core?.lifecycle && !protectionConfirmed) {
      executed.push({action: item.action, ok: false, code: 'PROTECTION_NOT_CONFIRMED', skipped: true, core_stopped: false, protection_retained: false});
      next.effects = {...next.effects, core_stopped: false, protection_retained: false};
      continue;
    }
    if (item.action === 'read_back' && ports.core?.readRuntime) {
      const runtime = await ports.core.readRuntime();
      next.runtime = runtime;
      executed.push({action: 'read_back', service: runtime.service.status, protection: runtime.protection.status, readback: runtime.readback.status});
    }
    if (item.action === 'limited_restart' && ports.core?.restart) {
      ports.core.restart();
      executed.push({action: 'limited_restart', restart_count: ports.core.snapshot?.().restart_count || null});
    } else if (item.action === 'limited_restart' && ports.core?.lifecycle) {
      // 产品服务的看门狗负责有限重启，客户端不另外拉起内核。
      executed.push({action: 'limited_restart', owner: 'network_service'});
    }
    if ((item.action === 'stop_core_for_maintenance' || item.action === 'start_core_last_valid') && ports.core?.lifecycle) {
      const stopping = item.action === 'stop_core_for_maintenance';
      const result = await ports.core.lifecycle({event: stopping ? 'maintenance_start' : 'maintenance_end'});
      if (stopping) {
        const outcome = {core_stopped: result.receipt?.core_stopped === true, protection_retained: result.receipt?.protection_retained === true};
        executed.push({action: item.action, ok: result.ok, code: result.code, ...outcome});
        next.effects = {...next.effects, ...outcome};
      } else {
        executed.push({action: item.action, ok: result.ok, code: result.code});
      }
    }
    if (item.action === 'stop_management_restore_original' && ports.core?.lifecycle) {
      const processes = await resolveApprovedProcessPaths({state: next, event, control: ports.control, userRef: next.user_ref || event?.user_ref});
      const result = await ports.core.lifecycle({event: 'stop_management', processes});
      executed.push({action: item.action, ok: result.ok, code: result.code});
      next.effects = {...next.effects, protection_released: result.ok === true};
    }
    if ((item.action === 'load_last_valid' || item.action === 'load_last_valid_unrevoked' || item.action === 'revert_last_valid') && typeof ports.restore === 'function') {
      const result = await ports.restore(next);
      executed.push({action: item.action, overall: result?.overall || null, code: result?.code || null});
    }
    if (item.action === 'revoke_owned_unmodified' && ports.sysopt?.revokeOwned) {
      const result = await ports.sysopt.revokeOwned(next.effects?.revoked || []);
      executed.push({action: item.action, revoked: result?.revoked || next.effects?.revoked || []});
    }
  }
  next.executed = executed;
  return save(ports.store, {user_ref: next.user_ref, environment_ref: next.environment_ref}, next);
}
