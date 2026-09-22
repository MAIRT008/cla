import {classifyIceCandidate} from './parse.mjs';

export async function collectIce({peerConnection, iceServers, timeoutMs = 800, clock = () => Date.now()} = {}) {
  if (!peerConnection) {
    return {status: 'UNSUPPORTED', candidates: [], limitation: 'NO_PEER_CONNECTION', public_candidates: false};
  }
  const candidates = [];
  let done = false;
  const started = Date.now();
  await new Promise((resolve) => {
    const timer = setTimeout(() => resolve(), timeoutMs);
    peerConnection.onicecandidate = (event) => {
      if (!event?.candidate) {
        done = true;
        clearTimeout(timer);
        resolve();
        return;
      }
      candidates.push(classifyIceCandidate(event.candidate));
    };
    peerConnection.onicegatheringstatechange = () => {
      if (peerConnection.iceGatheringState === 'complete') {
        done = true;
        clearTimeout(timer);
        resolve();
      }
    };
    try {
      peerConnection.setConfiguration?.({iceServers: iceServers || []});
      peerConnection.createDataChannel?.('diag');
      const offer = peerConnection.createOffer?.();
      if (offer && typeof offer.then === 'function') offer.then((desc) => peerConnection.setLocalDescription?.(desc)).catch(() => {});
    } catch {
      clearTimeout(timer);
      resolve();
    }
  });
  try { peerConnection.close?.(); } catch {}
  const publicCandidates = candidates.some((item) => item.srflx || item.relay);
  return {
    status: candidates.length || done ? 'OBSERVED' : 'NO_CANDIDATES',
    candidates,
    public_candidates: publicCandidates,
    host_only: candidates.length > 0 && !publicCandidates,
    limitation: publicCandidates ? null : 'NO_PUBLIC_STUN_CANDIDATE',
    duration_ms: Date.now() - started,
    leak: false,
  };
}
