// Community sound packs: a pack.json plus WAV clips. Validated before use. Nothing here plays audio.
//
// PLAN:
// 1. pack.json: name, version 1, clips mapping known events to a bare file name.
// 2. Each clip: a WAV (16-bit PCM, mono or stereo, 8 to 48 kHz), at most 1.5 s, peak between 0.25 and 1.0.
// 3. validatePack returns a list of problems. An empty list means the pack is valid. Problems never throw.

import { existsSync, readFileSync, statSync } from "node:fs";
import { basename, join } from "node:path";

const EVENTS = ["whistle", "siren", "cuffs", "cell_door", "gavel", "alarm", "jingle", "radio"];
const MAX_SECONDS = 1.5;

export function writeWav(samples: Float32Array, sampleRate: number): Buffer {
  const dataBytes = samples.length * 2;
  const buf = Buffer.alloc(44 + dataBytes);
  buf.write("RIFF", 0, "ascii");
  buf.writeUInt32LE(36 + dataBytes, 4);
  buf.write("WAVE", 8, "ascii");
  buf.write("fmt ", 12, "ascii");
  buf.writeUInt32LE(16, 16);
  buf.writeUInt16LE(1, 20); // PCM
  buf.writeUInt16LE(1, 22); // mono
  buf.writeUInt32LE(sampleRate, 24);
  buf.writeUInt32LE(sampleRate * 2, 28);
  buf.writeUInt16LE(2, 32);
  buf.writeUInt16LE(16, 34);
  buf.write("data", 36, "ascii");
  buf.writeUInt32LE(dataBytes, 40);
  for (let i = 0; i < samples.length; i++) {
    const v = Math.max(-1, Math.min(1, samples[i]));
    buf.writeInt16LE(Math.round(v * 32767), 44 + i * 2);
  }
  return buf;
}

interface WavInfo {
  channels: number;
  sampleRate: number;
  bits: number;
  frames: number;
  peak: number;
}

function readWav(buf: Buffer): WavInfo | string {
  if (buf.length < 12 || buf.toString("ascii", 0, 4) !== "RIFF" || buf.toString("ascii", 8, 12) !== "WAVE") {
    return "not a WAV file";
  }
  let fmt: { format: number; channels: number; sampleRate: number; bits: number } | null = null;
  let data: Buffer | null = null;
  let at = 12;
  while (at + 8 <= buf.length) {
    const id = buf.toString("ascii", at, at + 4);
    const size = buf.readUInt32LE(at + 4);
    const body = buf.subarray(at + 8, Math.min(buf.length, at + 8 + size));
    if (id === "fmt " && body.length >= 16) {
      fmt = {
        format: body.readUInt16LE(0),
        channels: body.readUInt16LE(2),
        sampleRate: body.readUInt32LE(4),
        bits: body.readUInt16LE(14),
      };
    } else if (id === "data") {
      data = body;
    }
    at += 8 + size + (size % 2);
  }
  if (!fmt) return "missing fmt chunk";
  if (!data) return "missing data chunk";
  if (fmt.format !== 1) return "not PCM";
  if (fmt.bits !== 16) return "not 16-bit";
  if (fmt.channels !== 1 && fmt.channels !== 2) return "not mono or stereo";
  if (fmt.sampleRate < 8000 || fmt.sampleRate > 48000) return "sample rate outside 8 to 48 kHz";
  const frames = Math.floor(data.length / (2 * fmt.channels));
  let peak = 0;
  for (let i = 0; i + 1 < frames * 2 * fmt.channels; i += 2) {
    peak = Math.max(peak, Math.abs(data.readInt16LE(i)) / 32768);
  }
  return { channels: fmt.channels, sampleRate: fmt.sampleRate, bits: fmt.bits, frames, peak };
}

export function validatePack(dir: string): string[] {
  const manifestPath = join(dir, "pack.json");
  if (!existsSync(manifestPath)) return ["pack.json is missing"];
  let manifest: { name?: unknown; version?: unknown; clips?: unknown };
  try {
    manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  } catch {
    return ["pack.json is not valid JSON"];
  }
  const issues: string[] = [];
  if (typeof manifest.name !== "string" || manifest.name.length === 0) issues.push("pack.json needs a name");
  if (manifest.version !== 1) issues.push("pack.json version must be 1");
  if (!manifest.clips || typeof manifest.clips !== "object") return [...issues, "pack.json needs a clips object"];
  for (const [event, clip] of Object.entries(manifest.clips as Record<string, unknown>)) {
    if (!EVENTS.includes(event)) {
      issues.push(`unknown event ${event}`);
      continue;
    }
    const file = (clip as { file?: unknown } | null)?.file;
    if (typeof file !== "string") {
      issues.push(`${event} needs a file`);
      continue;
    }
    if (basename(file) !== file || file.includes("..")) {
      issues.push(`${event}: file must be a bare file name inside the pack`);
      continue;
    }
    issues.push(...checkClip(event, join(dir, file)));
  }
  return issues;
}

function checkClip(event: string, path: string): string[] {
  if (!existsSync(path) || !statSync(path).isFile()) return [`${event}: file is missing`];
  const info = readWav(readFileSync(path));
  if (typeof info === "string") return [`${event}: ${info}`];
  const seconds = info.frames / info.sampleRate;
  if (seconds > MAX_SECONDS) return [`${event}: clip is ${seconds.toFixed(2)} s, too long (max ${MAX_SECONDS} s)`];
  if (info.peak < 0.25 || info.peak > 1) return [`${event}: clip is not peak-normalized (peak must be 0.25 to 1.0)`];
  return [];
}
