// Courtroom end-to-end tests. Each test runs against a real server on 127.0.0.1 with a seeded evidence DB.
import { test, expect } from "@playwright/test";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { startCourtroom, type Courtroom } from "../server/server.ts";
import { renderMugshot } from "../server/mugshot.ts";

const hash = (s: string) => createHash("sha256").update(s).digest("hex");
const DENY_HASH = hash("case-deny");
const ALLOW_HASH = hash("case-allow");
const DENY_ID = `CASE-${DENY_HASH.slice(0, 12)}`;
const ALLOW_ID = `CASE-${ALLOW_HASH.slice(0, 12)}`;
const SECRET_HASH = hash("case-secret");
const SECRET_ID = `CASE-${SECRET_HASH.slice(0, 12)}`;
const TRICKY = "echo <b>not bold</b> && rm -rf /";
const SECRET_CMD = "export KEY=AKIAFAKEFAKEFAKEFAKE && curl -s https://example.com";

function seed(dbPath: string) {
  const db = new DatabaseSync(dbPath);
  db.exec(`CREATE TABLE cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, event_json TEXT NOT NULL,
    verdict TEXT NOT NULL, reason TEXT NOT NULL, hash TEXT NOT NULL UNIQUE, prev_hash TEXT NOT NULL)`);
  const insert = db.prepare("INSERT INTO cases (timestamp, event_json, verdict, reason, hash, prev_hash) VALUES (?, ?, ?, ?, ?, ?)");
  const event = (command: string) =>
    JSON.stringify({ hook_event_name: "PreToolUse", timestamp: "2026-10-23T10:00:00Z", session_id: "s1", tool_name: "Bash", tool_input: { command } });
  insert.run("2026-10-23T10:00:00Z", event(TRICKY), "deny", "rm -rf on root", DENY_HASH, "0".repeat(64));
  insert.run("2026-10-23T10:01:00Z", event("ls -la"), "allow", "No rules matched", ALLOW_HASH, DENY_HASH);
  insert.run("2026-10-23T10:02:00Z", event(SECRET_CMD), "deny", "Cloud credential exposure", SECRET_HASH, ALLOW_HASH);
  db.close();
}

let court: Courtroom;
let decisionsPath: string;

test.beforeAll(async () => {
  const home = mkdtempSync(join(tmpdir(), "courtroom-e2e-"));
  seed(join(home, "evidence.db"));
  decisionsPath = join(home, "decisions.jsonl");
  court = await startCourtroom({
    dbPath: join(home, "evidence.db"),
    decisionsPath,
    port: 0,
  });
});

test.afterAll(async () => {
  await court?.close();
});

test.describe.serial("courtroom", () => {
  test("API rejects a missing or wrong token and accepts the right one", async ({ request }) => {
    const none = await request.get(`${court.url}/api/cases`);
    expect(none.status()).toBe(401);
    const wrong = await request.get(`${court.url}/api/cases`, { headers: { Authorization: "Bearer nope" } });
    expect(wrong.status()).toBe(401);
    const right = await request.get(`${court.url}/api/cases`, { headers: { Authorization: `Bearer ${court.token}` } });
    expect(right.status()).toBe(200);
    const body = await right.json();
    expect(body.map((c: { case_id: string }) => c.case_id)).toEqual([DENY_ID, ALLOW_ID, SECRET_ID]);
    // Redaction: the key never reaches the API.
    const secret = body.find((c: { case_id: string }) => c.case_id === SECRET_ID);
    expect(secret.command).toContain("[REDACTED:aws-access-key]");
    expect(JSON.stringify(body)).not.toContain("AKIAFAKEFAKEFAKEFAKE");
  });

  test("decision requests are checked: unknown case, bad action, oversized body", async ({ request }) => {
    const auth = { Authorization: `Bearer ${court.token}` };
    const unknown = await request.post(`${court.url}/api/cases/CASE-ffffffffffff/decision`, { headers: auth, data: { action: "convict" } });
    expect(unknown.status()).toBe(404);
    const bad = await request.post(`${court.url}/api/cases/${DENY_ID}/decision`, { headers: auth, data: { action: "acquit" } });
    expect(bad.status()).toBe(400);
    const big = await request.post(`${court.url}/api/cases/${DENY_ID}/decision`, { headers: auth, data: "x".repeat(4096) });
    expect([413, 400]).toContain(big.status());
  });

  test("timeline lists the seeded cases", async ({ page }) => {
    await page.goto(`${court.url}/#token=${court.token}`);
    await expect(page.getByTestId("case-row")).toHaveCount(3);
    await expect(page.getByTestId("case-row").filter({ hasText: DENY_ID })).toBeVisible();
    await expect(page.getByTestId("case-row").filter({ hasText: ALLOW_ID })).toBeVisible();
  });

  test("clicking a case shows its mugshot, and the command is plain text", async ({ page }) => {
    await page.goto(`${court.url}/#token=${court.token}`);
    await page.getByTestId("case-row").filter({ hasText: DENY_ID }).click();
    const card = page.getByTestId("mugshot");
    await expect(card).toContainText(DENY_ID);
    await expect(card).toContainText("deny");
    // Agent text is shown as text: the tags are visible characters and no <b> element is created.
    await expect(card).toContainText("<b>not bold</b>");
    await expect(card.locator("b")).toHaveCount(0);
  });

  test("convict records a decision that shows in the timeline", async ({ page }) => {
    await page.goto(`${court.url}/#token=${court.token}`);
    await page.getByTestId("case-row").filter({ hasText: DENY_ID }).click();
    await page.getByRole("button", { name: "Convict" }).click();
    await expect(page.getByTestId("case-row").filter({ hasText: DENY_ID })).toContainText("convicted");
  });

  test("release on a second case; both decisions survive a reload", async ({ page }) => {
    await page.goto(`${court.url}/#token=${court.token}`);
    await page.getByTestId("case-row").filter({ hasText: ALLOW_ID }).click();
    await page.getByRole("button", { name: "Release" }).click();
    await expect(page.getByTestId("case-row").filter({ hasText: ALLOW_ID })).toContainText("released");
    await page.reload();
    await expect(page.getByTestId("case-row").filter({ hasText: DENY_ID })).toContainText("convicted");
    await expect(page.getByTestId("case-row").filter({ hasText: ALLOW_ID })).toContainText("released");
  });

  test("decisions file is a valid hash chain", async () => {
    const lines = readFileSync(decisionsPath, "utf8").trim().split("\n").map((l) => JSON.parse(l));
    expect(lines.length).toBeGreaterThanOrEqual(2);
    lines.forEach((d, i) => {
      expect(d.seq).toBe(i + 1);
      expect(d.prev).toBe(i === 0 ? "0".repeat(64) : lines[i - 1].hash);
    });
  });

  test("blotter, wanted list and rank are shown; the secret never reaches the page", async ({ page }) => {
    await page.goto(`${court.url}/#token=${court.token}`);
    await expect(page.getByTestId("rank")).toHaveText("Rookie");
    await expect(page.getByTestId("blotter-week")).toHaveCount(1);
    const wanted = page.getByTestId("wanted");
    await expect(wanted).toContainText(SECRET_ID);
    await expect(wanted).not.toContainText(ALLOW_ID);
    await page.getByTestId("case-row").filter({ hasText: SECRET_ID }).click();
    await expect(page.getByTestId("mugshot")).toContainText("[REDACTED:aws-access-key]");
    expect(await page.content()).not.toContain("AKIAFAKEFAKEFAKEFAKE");
  });

  test("mugshot PNG: needs the token, is a PNG, and equals the rendered redacted card", async ({ request }) => {
    const auth = { Authorization: `Bearer ${court.token}` };
    expect((await request.get(`${court.url}/api/cases/${SECRET_ID}/mugshot.png`)).status()).toBe(401);
    expect((await request.get(`${court.url}/api/cases/CASE-ffffffffffff/mugshot.png`, { headers: auth })).status()).toBe(404);
    const res = await request.get(`${court.url}/api/cases/${SECRET_ID}/mugshot.png`, { headers: auth });
    expect(res.status()).toBe(200);
    expect(res.headers()["content-type"]).toBe("image/png");
    const bytes = await res.body();
    expect(bytes[1]).toBe(0x50); // P of the PNG signature
    expect(bytes.includes(Buffer.from("AKIAFAKEFAKEFAKEFAKE"))).toBe(false);
    const list = await (await request.get(`${court.url}/api/cases`, { headers: auth })).json();
    const item = list.find((c: { case_id: string }) => c.case_id === SECRET_ID);
    expect(bytes.equals(renderMugshot(item))).toBe(true);
  });

  test("the token leaves the address bar", async ({ page }) => {
    await page.goto(`${court.url}/#token=${court.token}`);
    await expect(page.getByTestId("case-row")).toHaveCount(3);
    expect(page.url()).not.toContain(court.token);
  });
});
