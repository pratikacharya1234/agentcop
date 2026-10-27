// Pure-function tests: no browser, no server.
import { expect, test } from "@playwright/test";
import { rankFor } from "../server/ranks.ts";
import { weekKey, weeklyBlotter, wanted } from "../server/blotter.ts";
import { redact } from "../server/redact.ts";
import { encodePng } from "../server/png.ts";
import { cardLines, renderMugshot } from "../server/mugshot.ts";
import { validatePack, writeWav } from "../server/soundpack.ts";
import { inflateSync } from "node:zlib";
import { mkdirSync, mkdtempSync, writeFileSync, copyFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const AWS_KEY = "AKIAFAKEFAKEFAKEFAKE"; // obviously fake

test("ranks follow convictions: 0 Rookie, 3 Officer, 10 Detective, 25 Sergeant, 50 Chief", () => {
  expect(rankFor(0)).toBe("Rookie");
  expect(rankFor(2)).toBe("Rookie");
  expect(rankFor(3)).toBe("Officer");
  expect(rankFor(9)).toBe("Officer");
  expect(rankFor(10)).toBe("Detective");
  expect(rankFor(25)).toBe("Sergeant");
  expect(rankFor(50)).toBe("Chief");
  expect(rankFor(500)).toBe("Chief");
});

test("a week runs Monday to Sunday (UTC), so Monday and Tuesday share a key", () => {
  expect(weekKey("2026-10-19T12:00:00Z")).toBe(weekKey("2026-10-20T08:00:00Z"));
  expect(weekKey("2026-10-18T23:59:00Z")).not.toBe(weekKey("2026-10-19T00:01:00Z"));
});

test("weekly blotter counts verdicts and statuses per week", () => {
  const rows = [
    { case_id: "A", timestamp: "2026-10-20T10:00:00Z", verdict: "deny", status: "open" },
    { case_id: "B", timestamp: "2026-10-21T10:00:00Z", verdict: "allow", status: "convicted" },
    { case_id: "C", timestamp: "2026-10-26T10:00:00Z", verdict: "deny", status: "released" },
  ];
  const weeks = weeklyBlotter(rows) as { week: string; cases: number; deny: number; convicted: number }[];
  expect(weeks.length).toBe(2);
  expect(weeks[0]).toMatchObject({ cases: 2, deny: 1, convicted: 1 });
  expect(weeks[1]).toMatchObject({ cases: 1, deny: 1, convicted: 0 });
});

test("wanted lists deny cases that are not released", () => {
  const rows = [
    { case_id: "A", verdict: "deny", status: "open" },
    { case_id: "B", verdict: "deny", status: "convicted" },
    { case_id: "C", verdict: "deny", status: "released" },
    { case_id: "D", verdict: "allow", status: "open" },
  ];
  expect((wanted(rows) as { case_id: string }[]).map((r) => r.case_id)).toEqual(["A", "B"]);
});

test("redaction replaces secrets with a named marker and keeps plain text", () => {
  const out = redact(`export KEY=${AWS_KEY} && echo done`);
  expect(out).toContain("[REDACTED:aws-access-key]");
  expect(out).not.toContain(AWS_KEY);
  expect(out).toContain("echo done");
  const pem = redact("-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----");
  expect(pem).toContain("[REDACTED:private-key-block]");
  expect(pem).not.toContain("BEGIN RSA PRIVATE KEY");
  expect(redact("ls -la")).toBe("ls -la");
});

// ---- F2b: PNG, mugshot, sound packs ----

test("PNG has the signature, the size, and pixels that round-trip", () => {
  const rgba = new Uint8Array([255, 0, 0, 255, 0, 255, 0, 255]); // 2x1
  const png = encodePng(2, 1, rgba);
  expect([...png.subarray(0, 8)]).toEqual([137, 80, 78, 71, 13, 10, 26, 10]);
  expect(png.readUInt32BE(16)).toBe(2); // IHDR width
  expect(png.readUInt32BE(20)).toBe(1); // IHDR height
  const idatAt = png.indexOf(Buffer.from("IDAT"));
  const len = png.readUInt32BE(idatAt - 4);
  const raw = inflateSync(png.subarray(idatAt + 4, idatAt + 4 + len));
  expect([...raw]).toEqual([0, 255, 0, 0, 255, 0, 255, 0, 255]); // filter byte 0, then the pixels
});

const CASE_WITH_KEY = {
  case_id: "CASE-0123456789ab",
  verdict: "deny",
  tool_name: "Bash",
  command: `export KEY=${AWS_KEY} && curl -s https://example.com`,
  reason: "Cloud credential exposure",
};

test("mugshot lines never carry the raw key", () => {
  const lines = cardLines(CASE_WITH_KEY);
  expect(lines.join("\n")).not.toContain(AWS_KEY);
  expect(lines.join("\n")).toContain("[REDACTED:aws-access-key]");
});

test("a mugshot with a secret is pixel-identical to the same mugshot with the secret already redacted", () => {
  const redactedCase = { ...CASE_WITH_KEY, command: redact(CASE_WITH_KEY.command) };
  expect(renderMugshot(CASE_WITH_KEY).equals(renderMugshot(redactedCase))).toBe(true);
  expect(renderMugshot(CASE_WITH_KEY).includes(Buffer.from(AWS_KEY))).toBe(false);
});

test("mugshot rendering is deterministic", () => {
  expect(renderMugshot(CASE_WITH_KEY).equals(renderMugshot(CASE_WITH_KEY))).toBe(true);
});

function tempPack(files: Record<string, Buffer | string>): string {
  const dir = mkdtempSync(join(tmpdir(), "pack-"));
  for (const [name, body] of Object.entries(files)) writeFileSync(join(dir, name), body);
  return dir;
}

const manifest = (clips: Record<string, { file: string }>) =>
  JSON.stringify({ name: "test", version: 1, clips });

test("a generated WAV is a valid clip; a 2 s clip is refused", () => {
  const rate = 22050;
  const short = new Float32Array(rate * 0.5).map((_, i) => 0.3 * Math.sin(i / 10));
  const long = new Float32Array(rate * 2).map((_, i) => 0.3 * Math.sin(i / 10));
  expect(validatePack(tempPack({ "pack.json": manifest({ gavel: { file: "g.wav" } }), "g.wav": writeWav(short, rate) }))).toEqual([]);
  const issues = validatePack(tempPack({ "pack.json": manifest({ gavel: { file: "g.wav" } }), "g.wav": writeWav(long, rate) }));
  expect(issues.join(" ")).toMatch(/1\.5 s|too long/);
});

test("a clip path that leaves the pack is refused, and a missing pack.json is reported", () => {
  const wav = writeWav(new Float32Array(1000).map((_, i) => 0.3 * Math.sin(i / 10)), 22050);
  const issues = validatePack(tempPack({ "pack.json": manifest({ gavel: { file: "../g.wav" } }), "g.wav": wav }));
  expect(issues.join(" ")).toMatch(/bare file name|outside/);
  expect(validatePack(tempPack({})).length).toBeGreaterThan(0);
});

test("the built-in default pack validates", () => {
  const dir = resolve(fileURLToPath(new URL("..", import.meta.url)), "sound-packs", "default");
  expect(validatePack(dir)).toEqual([]);
});
