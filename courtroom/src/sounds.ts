// Courtroom sounds, synthesized in code (no recorded audio).
//
// PLAN:
// 1. The gavel is a short decaying tone with a click on the front, about 0.4 s. That is under the 1.5 s limit.
// 2. Samples are peak-normalized to 0.5.
// 3. Mute is saved in localStorage. Storage errors are ignored.
// 4. Any audio error is swallowed. A sound must never break the page.

const MUTE_KEY = "courtroom.muted";

export function isMuted(): boolean {
  try {
    return localStorage.getItem(MUTE_KEY) === "1";
  } catch {
    return false;
  }
}

export function setMuted(muted: boolean): void {
  try {
    localStorage.setItem(MUTE_KEY, muted ? "1" : "0");
  } catch {
    // Storage blocked: the mute lasts for this page only.
  }
}

/** The gavel samples, peak-normalized to 0.5. Pure, so it can be checked without a browser. */
export function gavelSamples(sampleRate: number): Float32Array<ArrayBuffer> {
  const length = Math.floor(sampleRate * 0.4);
  const out = new Float32Array(new ArrayBuffer(length * 4));
  for (let i = 0; i < length; i++) {
    const t = i / sampleRate;
    const thump = Math.sin(2 * Math.PI * 180 * t) * Math.exp(-t * 14);
    // Fixed pseudo-noise, so the same rate always gives the same clip.
    const click = (i < sampleRate * 0.01 ? 1 : 0) * (((i * 9301 + 49297) % 233280) / 233280 * 2 - 1) * 0.6;
    out[i] = thump + click;
  }
  let peak = 0;
  for (const v of out) peak = Math.max(peak, Math.abs(v));
  if (peak > 0) for (let i = 0; i < length; i++) out[i] = (out[i] / peak) * 0.5;
  return out;
}

export function playGavel(): void {
  if (isMuted()) return;
  try {
    const Ctx = window.AudioContext;
    const ctx = new Ctx();
    const samples = gavelSamples(ctx.sampleRate);
    const buffer = ctx.createBuffer(1, samples.length, ctx.sampleRate);
    buffer.copyToChannel(samples, 0);
    const source = ctx.createBufferSource();
    source.buffer = buffer;
    source.connect(ctx.destination);
    source.start();
    source.onended = () => void ctx.close();
  } catch {
    // No audio device or blocked context: stay silent.
  }
}
