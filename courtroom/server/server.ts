// Courtroom server: local only (127.0.0.1), random token, read-only evidence, decisions appended.
//
// PLAN:
// 1. Bind 127.0.0.1. Generate a 24-byte random token unless one is given.
// 2. Every /api route needs "Authorization: Bearer <token>". Compare in constant time. Anything else is 401.
// 3. GET /api/cases lists cases with their latest decision. POST /api/cases/:id/decision records release or convict (1 KB body cap).
// 4. Other GET paths serve the built frontend from dist/. Paths are checked so nothing outside dist/ can be read.
// 5. Any unexpected error returns 500 with no details (fail closed).

import { randomBytes, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { readFileSync, existsSync, statSync } from "node:fs";
import { extname, join, normalize, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { readCases } from "./data.ts";
import { appendDecision, latestByCase, readDecisions, type Action } from "./decisions.ts";
import { rankFor } from "./ranks.ts";
import { wanted, weeklyBlotter } from "./blotter.ts";
import { redact } from "./redact.ts";
import { renderMugshot } from "./mugshot.ts";

export interface CourtroomOptions {
  dbPath: string;
  statePath: string;
  port: number;
  token?: string;
  staticDir?: string;
}

export interface Courtroom {
  url: string;
  token: string;
  close(): Promise<void>;
}

const HERE = fileURLToPath(new URL(".", import.meta.url));
const DEFAULT_STATIC = resolve(HERE, "..", "dist");
const MAX_BODY = 1024;
const TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml",
  ".json": "application/json",
};

export async function startCourtroom(opts: CourtroomOptions): Promise<Courtroom> {
  const token = opts.token ?? randomBytes(24).toString("base64url");
  const staticDir = resolve(opts.staticDir ?? DEFAULT_STATIC);
  const server = createServer((req, res) => {
    handle(req, res, opts, token, staticDir).catch(() => {
      if (!res.headersSent) sendJson(res, 500, { error: "internal error" });
      else res.end();
    });
  });
  await new Promise<void>((ok, fail) => {
    server.once("error", fail);
    server.listen(opts.port, "127.0.0.1", () => ok());
  });
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : opts.port;
  return {
    url: `http://127.0.0.1:${port}`,
    token,
    close: () => new Promise<void>((ok) => server.close(() => ok())),
  };
}

async function handle(
  req: IncomingMessage,
  res: ServerResponse,
  opts: CourtroomOptions,
  token: string,
  staticDir: string,
): Promise<void> {
  const url = new URL(req.url ?? "/", "http://127.0.0.1");
  if (url.pathname.startsWith("/api/")) {
    if (!authorized(req, token)) return sendJson(res, 401, { error: "unauthorized" });
    return api(req, res, url.pathname, opts);
  }
  if (req.method !== "GET") return sendJson(res, 405, { error: "method not allowed" });
  return serveStatic(res, url.pathname, staticDir);
}

function authorized(req: IncomingMessage, token: string): boolean {
  const header = req.headers.authorization ?? "";
  const expected = Buffer.from(`Bearer ${token}`);
  const given = Buffer.from(header);
  return given.length === expected.length && timingSafeEqual(given, expected);
}

function api(req: IncomingMessage, res: ServerResponse, path: string, opts: CourtroomOptions): Promise<void> | void {
  if (req.method === "GET" && path === "/api/cases") {
    return sendJson(res, 200, withStatus(opts));
  }
  const mugshot = /^\/api\/cases\/(CASE-[0-9a-f]{12})\/mugshot\.png$/.exec(path);
  if (req.method === "GET" && mugshot) {
    const item = withStatus(opts).find((c) => c.case_id === mugshot[1]);
    if (!item) return sendJson(res, 404, { error: "no such case" });
    res.writeHead(200, {
      "Content-Type": "image/png",
      "Content-Disposition": `attachment; filename="${item.case_id}.png"`,
      "Cache-Control": "no-store",
    });
    res.end(renderMugshot(item));
    return;
  }
  if (req.method === "GET" && path === "/api/blotter") {
    const cases = withStatus(opts);
    const convictions = cases.filter((c) => c.status === "convicted").length;
    return sendJson(res, 200, {
      rank: { name: rankFor(convictions), convictions },
      weeks: weeklyBlotter(cases),
      wanted: wanted(cases),
    });
  }
  const match = /^\/api\/cases\/(CASE-[0-9a-f]{12})\/decision$/.exec(path);
  if (match && req.method === "POST") {
    return recordDecision(req, res, match[1], opts);
  }
  return sendJson(res, 404, { error: "not found" });
}

async function recordDecision(req: IncomingMessage, res: ServerResponse, caseId: string, opts: CourtroomOptions) {
  const body = await readBody(req);
  if (body === null) return sendJson(res, 413, { error: "body too large" });
  let action: unknown;
  try {
    action = (JSON.parse(body) as { action?: unknown }).action;
  } catch {
    return sendJson(res, 400, { error: "bad json" });
  }
  if (action !== "release" && action !== "convict") return sendJson(res, 400, { error: "action must be release or convict" });
  if (!readCases(opts.dbPath).some((c) => c.case_id === caseId)) return sendJson(res, 404, { error: "no such case" });
  const decision = appendDecision(opts.statePath, caseId, action as Action);
  return sendJson(res, 201, decision);
}

// Read the body up to MAX_BODY. Past the cap, keep reading and discard, so the 413 can still be sent.
// Destroying the socket here would reset the connection before the client sees the reply.
function readBody(req: IncomingMessage): Promise<string | null> {
  return new Promise((ok, fail) => {
    let size = 0;
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size <= MAX_BODY) chunks.push(chunk);
    });
    req.on("end", () => ok(size > MAX_BODY ? null : Buffer.concat(chunks).toString("utf8")));
    req.on("error", fail);
  });
}

function serveStatic(res: ServerResponse, pathname: string, staticDir: string) {
  const requested = pathname === "/" ? "/index.html" : decodeURIComponent(pathname);
  const file = resolve(join(staticDir, normalize(requested)));
  const inside = file === staticDir || file.startsWith(staticDir + sep);
  const target = inside && existsSync(file) && statSync(file).isFile() ? file : join(staticDir, "index.html");
  if (!existsSync(target)) return sendJson(res, 404, { error: "not built; run npm run build" });
  res.writeHead(200, { "Content-Type": TYPES[extname(target)] ?? "application/octet-stream", "Cache-Control": "no-store" });
  res.end(readFileSync(target));
}

/** Cases with the latest decision applied. Secrets are redacted here, so nothing downstream sees them raw. */
function withStatus(opts: CourtroomOptions) {
  const decided = latestByCase(readDecisions(opts.statePath));
  return readCases(opts.dbPath).map((c) => ({
    ...c,
    command: redact(c.command),
    reason: redact(c.reason),
    status: statusOf(decided.get(c.case_id)),
  }));
}

function statusOf(action: Action | undefined): "open" | "convicted" | "released" {
  if (action === "convict") return "convicted";
  if (action === "release") return "released";
  return "open";
}

function sendJson(res: ServerResponse, code: number, body: unknown) {
  res.writeHead(code, { "Content-Type": "application/json", "Cache-Control": "no-store" });
  res.end(JSON.stringify(body));
}
