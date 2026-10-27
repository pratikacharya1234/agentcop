// Mugshot card as a PNG. Every line is redacted here too, so the pixels depend only on redacted text.
//
// PLAN:
// 1. Build the text lines from the case fields, each passed through redact().
// 2. Wrap to 49 characters per line and cap at 12 lines. Cut lines end with "...".
// 3. Draw on a fixed 640x360 white card with the built-in font at scale 2, with a frame coloured by verdict.
// 4. Encode as PNG. Same input gives the same bytes.

import { glyph } from "./font.ts";
import { encodePng } from "./png.ts";
import { redact } from "./redact.ts";

export interface MugshotCase {
  case_id: string;
  verdict: string;
  tool_name: string;
  command: string;
  reason: string;
}

const W = 640;
const H = 360;
const SCALE = 2;
const PAD = 24;
const ADVANCE = 6 * SCALE; // 5 columns plus one gap
const LINE_HEIGHT = 20;
const CHARS_PER_LINE = Math.floor((W - 2 * PAD) / ADVANCE);
const MAX_LINES = 12;

const FRAME: Record<string, [number, number, number]> = {
  deny: [180, 35, 24],
  ask: [181, 71, 8],
  allow: [6, 118, 71],
};

export function cardLines(c: MugshotCase): string[] {
  const fields = [
    "AGENTCOP MUGSHOT",
    `CASE ${redact(c.case_id)}`,
    `VERDICT ${redact(c.verdict)}`,
    `TOOL ${redact(c.tool_name)}`,
    ...wrap(`REASON ${redact(c.reason)}`),
    ...wrap(`COMMAND ${redact(c.command)}`),
  ];
  if (fields.length <= MAX_LINES) return fields;
  return [...fields.slice(0, MAX_LINES - 1), "..."];
}

export function renderMugshot(c: MugshotCase): Buffer {
  const rgba = new Uint8Array(W * H * 4).fill(255);
  const frame = FRAME[c.verdict] ?? FRAME.ask;
  drawFrame(rgba, frame);
  cardLines(c).forEach((line, row) => drawText(rgba, line, PAD, PAD + row * LINE_HEIGHT));
  return encodePng(W, H, rgba);
}

function wrap(text: string): string[] {
  const out: string[] = [];
  for (let i = 0; i < text.length; i += CHARS_PER_LINE) out.push(text.slice(i, i + CHARS_PER_LINE));
  return out.length ? out : [""];
}

function drawFrame(rgba: Uint8Array, [r, g, b]: [number, number, number]) {
  for (let y = 0; y < H; y++) {
    for (let x = 0; x < W; x++) {
      if (x < 6 || y < 6 || x >= W - 6 || y >= H - 6) setPixel(rgba, x, y, r, g, b);
    }
  }
}

function drawText(rgba: Uint8Array, text: string, x0: number, y0: number) {
  [...text].forEach((ch, i) => {
    const rows = glyph(ch);
    rows.forEach((row, gy) => {
      [...row].forEach((cell, gx) => {
        if (cell !== "#") return;
        for (let dy = 0; dy < SCALE; dy++) {
          for (let dx = 0; dx < SCALE; dx++) {
            setPixel(rgba, x0 + i * ADVANCE + gx * SCALE + dx, y0 + gy * SCALE + dy, 0, 0, 0);
          }
        }
      });
    });
  });
}

function setPixel(rgba: Uint8Array, x: number, y: number, r: number, g: number, b: number) {
  const at = (y * W + x) * 4;
  rgba[at] = r;
  rgba[at + 1] = g;
  rgba[at + 2] = b;
  rgba[at + 3] = 255;
}
