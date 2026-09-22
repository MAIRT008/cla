function cloneState(value) {
  return structuredClone(value || {});
}

function initialState(value) {
  const state = cloneState(value);
  state.totals ||= {uploadBytes: 0, downloadBytes: 0};
  state.observations ||= {};
  state.connectionBreakdown ||= {};
  state.coverageIssues ||= [];
  state.coverageStatus ||= state.coverageIssues.length ? 'MONITORING_INCOMPLETE' : 'COMPLETE';
  return state;
}

function issue(state, code, sample, detail = null) {
  state.coverageIssues.push({code, observedAt: sample.observedAt || null, sourceKind: sample.sourceKind || 'unknown', detail});
  state.coverageStatus = 'MONITORING_INCOMPLETE';
}

function sourceKey(sample, sourceKind) {
  if (sourceKind === 'core') return sample.coreInstanceId ? `core:${sample.coreInstanceId}` : null;
  if (sourceKind === 'connection') {
    if (!sample.connectionId) return null;
    return `connection:${sample.coreInstanceId || sample.instanceId || 'unknown'}:${sample.connectionId}`;
  }
  return sample.sourceId ? `${sourceKind}:${sample.sourceId}` : null;
}

function observation(sample) {
  return {
    uploadBytes: sample.uploadBytes,
    downloadBytes: sample.downloadBytes,
    resetId: sample.resetId || null,
    observedAt: sample.observedAt || null,
  };
}

export function accumulateTraffic(previousState, sample = {}) {
  const state = initialState(previousState);
  if (sample.serverQuota) {
    state.serverQuota = structuredClone(sample.serverQuota);
  }
  const sourceKind = sample.sourceKind || 'unknown';
  const delta = {uploadBytes: 0, downloadBytes: 0};
  const key = sourceKey(sample, sourceKind);
  if (!key) {
    issue(state, 'UNKNOWN_SOURCE', sample);
    return {state, delta, status: 'INCOMPLETE'};
  }
  if (!Number.isFinite(sample.uploadBytes) || !Number.isFinite(sample.downloadBytes)) {
    issue(state, 'MISSING_COUNTER', sample);
    return {state, delta, status: 'INCOMPLETE'};
  }
  if (sample.attribution === 'unknown') {
    issue(state, 'UNKNOWN_ATTRIBUTION', sample);
  }

  const current = observation(sample);
  const previous = state.observations[key];
  const contributesToTotals = sourceKind !== 'connection' || sample.coveredByCore !== true;

  if (!previous) {
    state.observations[key] = current;
    if (sample.baselineKnown !== true) issue(state, 'INITIAL_BASELINE', sample);
    return {state, delta, status: 'BASELINE'};
  }
  const currentMillis = new Date(current.observedAt).getTime();
  const previousMillis = new Date(previous.observedAt).getTime();
  if (!Number.isFinite(currentMillis)) {
    issue(state, 'MISSING_OBSERVATION_TIME', sample);
    return {state, delta, status: 'INCOMPLETE'};
  }
  if (Number.isFinite(previousMillis) && currentMillis < previousMillis) {
    issue(state, 'OUT_OF_ORDER_OBSERVATION', sample, {previousObservedAt: previous.observedAt});
    return {state, delta, status: 'OUT_OF_ORDER'};
  }
  if (Number.isFinite(previousMillis) && currentMillis === previousMillis) {
    if (previous.resetId === current.resetId && previous.uploadBytes === current.uploadBytes && previous.downloadBytes === current.downloadBytes) {
      return {state, delta, status: 'DUPLICATE'};
    }
    issue(state, 'CONFLICTING_OBSERVATION', sample, {previousObservedAt: previous.observedAt});
    return {state, delta, status: 'CONFLICTING_OBSERVATION'};
  }
  state.observations[key] = current;
  if (previous.resetId !== current.resetId || current.uploadBytes < previous.uploadBytes || current.downloadBytes < previous.downloadBytes) {
    issue(state, 'COUNTER_RESET', sample, {previousResetId: previous.resetId, currentResetId: current.resetId});
    return {state, delta, status: 'COUNTER_RESET'};
  }

  delta.uploadBytes = current.uploadBytes - previous.uploadBytes;
  delta.downloadBytes = current.downloadBytes - previous.downloadBytes;
  if (!contributesToTotals) {
    state.connectionBreakdown[key] = (state.connectionBreakdown[key] || {uploadBytes: 0, downloadBytes: 0});
    state.connectionBreakdown[key].uploadBytes += delta.uploadBytes;
    state.connectionBreakdown[key].downloadBytes += delta.downloadBytes;
    return {state, delta: {uploadBytes: 0, downloadBytes: 0}, status: 'COVERED_BY_CORE'};
  }
  state.totals.uploadBytes += delta.uploadBytes;
  state.totals.downloadBytes += delta.downloadBytes;
  return {state, delta, status: delta.uploadBytes || delta.downloadBytes ? 'ACCUMULATED' : 'DUPLICATE'};
}
