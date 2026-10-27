// Human decisions (release / convict), one hash-chained row each, in the `decisions` table of state.db.
// Append-only (2026-10-27: moved from decisions.jsonl; install imports the old file).
//
// PLAN:
// 1. Each row: seq, case_id, action, at, prev (hash of the row before), hash (sha256 of prev + the fields).
// 2. The first row's prev is 64 zeros.
// 3. Each read and each append opens the state file, sets a busy timeout, and closes it. A missing file means none.

import { createHash } from "node:crypto";
import { existsSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";

export type Action = "release" | "convict";

export interface Decision {
  seq: number;
  case_id: string;
  action: Action;
  at: string;
  prev: string;
  hash: string;
}

const GENESIS = "0".repeat(64);

function open(path: string): DatabaseSync {
  mkdirSync(dirname(path), { recursive: true });
  const db = new DatabaseSync(path);
  db.exec("PRAGMA busy_timeout = 5000");
  db.exec(
    "CREATE TABLE IF NOT EXISTS decisions (seq INTEGER PRIMARY KEY, case_id TEXT NOT NULL, action TEXT NOT NULL, at TEXT NOT NULL, prev TEXT NOT NULL, hash TEXT NOT NULL)",
  );
  return db;
}

export function readDecisions(path: string): Decision[] {
  if (!existsSync(path)) return [];
  const db = open(path);
  try {
    return db
      .prepare("SELECT seq, case_id, action, at, prev, hash FROM decisions ORDER BY seq")
      .all() as unknown as Decision[];
  } finally {
    db.close();
  }
}

export function appendDecision(path: string, case_id: string, action: Action): Decision {
  const db = open(path);
  try {
    db.exec("BEGIN IMMEDIATE");
    const last = db.prepare("SELECT seq, hash FROM decisions ORDER BY seq DESC LIMIT 1").get() as
      | { seq: number; hash: string }
      | undefined;
    const seq = (last?.seq ?? 0) + 1;
    const prev = last?.hash ?? GENESIS;
    const at = new Date().toISOString();
    const hash = createHash("sha256").update(`${prev}|${seq}|${case_id}|${action}|${at}`).digest("hex");
    db.prepare("INSERT INTO decisions (seq, case_id, action, at, prev, hash) VALUES (?, ?, ?, ?, ?, ?)").run(
      seq,
      case_id,
      action,
      at,
      prev,
      hash,
    );
    db.exec("COMMIT");
    return { seq, case_id, action, at, prev, hash };
  } catch (e) {
    db.exec("ROLLBACK");
    throw e;
  } finally {
    db.close();
  }
}

/** Latest action per case, or undefined when the case is still open. */
export function latestByCase(decisions: Decision[]): Map<string, Action> {
  const map = new Map<string, Action>();
  for (const d of decisions) map.set(d.case_id, d.action);
  return map;
}
