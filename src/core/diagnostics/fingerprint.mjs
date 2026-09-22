import {sha256Hex} from '../../adapters/platform/index.mjs';

function digest(value) {
  return sha256Hex(String(value));
}

async function capture(label, work) {
  try {
    const value = await work();
    return {status: 'OBSERVED', label, value};
  } catch (error) {
    return {status: error?.code === 'UNSUPPORTED' ? 'UNSUPPORTED' : 'DENIED', label, error: error?.message || String(error), value: null};
  }
}

export async function collectFingerprint({canvas, webgl, audio, fonts, screen, cryptoImpl, clock = () => Date.now()} = {}) {
  const canvasResult = await capture('canvas', async () => {
    if (!canvas?.fillText) throw Object.assign(new Error('canvas unavailable'), {code: 'UNSUPPORTED'});
    canvas.fillText('AI Steward fingerprint', 2, 12);
    const data = canvas.toDataURL ? canvas.toDataURL() : canvas.data || '';
    if (!data) throw Object.assign(new Error('canvas empty'), {code: 'DENIED'});
    return {hash: digest(data), length: data.length};
  });
  const webglResult = await capture('webgl', async () => {
    if (!webgl?.getParameter) throw Object.assign(new Error('webgl unavailable'), {code: 'UNSUPPORTED'});
    return {
      vendor: webgl.getParameter(webgl.VENDOR) || webgl.getParameter(0x9245) || null,
      renderer: webgl.getParameter(webgl.RENDERER) || webgl.getParameter(0x9246) || null,
    };
  });
  const audioResult = await capture('audio', async () => {
    if (!audio?.getChannelData) throw Object.assign(new Error('audio unavailable'), {code: 'UNSUPPORTED'});
    const samples = audio.getChannelData(0);
    const sum = Array.from(samples || []).slice(0, 32).reduce((total, item) => total + Number(item || 0), 0);
    return {hash: digest(sum.toFixed(8)), played: false};
  });
  const fontResult = await capture('fonts', async () => {
    const sample = fonts || ['Arial', 'Times New Roman', 'Noto Sans SC'];
    return {sample, scanned_directory: false};
  });
  const screenResult = await capture('screen', async () => ({
    width: screen?.width ?? null,
    height: screen?.height ?? null,
    color_depth: screen?.colorDepth ?? null,
    device_pixel_ratio: screen?.devicePixelRatio ?? null,
  }));
  const nonce = cryptoImpl?.randomUUID?.() || digest(String(clock()));
  return {
    observed_at: typeof clock() === 'string' ? clock() : new Date(clock()).toISOString(),
    canvas: canvasResult,
    webgl: webglResult,
    audio: audioResult,
    fonts: fontResult,
    screen: screenResult,
    sample_nonce: nonce,
    uniqueness: 'UNKNOWN',
    account_risk: 'NOT_INFERRED',
  };
}
