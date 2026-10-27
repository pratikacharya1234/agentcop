// Human decisions (release / convict), one hash-chained JSON line each. Append-only.
//
// PLAN:
// 1. Each line: seq, case_id, action, at, prev (hash of the line before), hash (sha256 of prev + the fields).
// 2. The first line's prev is 64 zeros.
// 3. Read the whole file to get the latest state. Malformed lines are skipped and counted, never trusted.

import { createHash } from "node:crypto";
import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname } from "node:path";

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

export function readDecisions(path: string): Decision[] {
  if (!existsSync(path)) return [];
  const out: Decision[] = [];
  for (const line of readFileSync(path, "utf8").split("\n")) {
    if (!line.trim()) continue;
    try {
      out.push(JSON.parse(line) as Decision);
    } catch {
      // A broken line is not a decision. Skip it.
    }
  }
  return out;
}

export function appendDecision(path: string, case_id: string, action: Action): Decision {
  const existing = readDecisions(path);
  const last = existing[existing.length - 1];
  const seq = (last?.seq ?? 0) + 1;
  const prev = last?.hash ?? GENESIS;
  const at = new Date().toISOString();
  const hash = createHash("sha256").update(`${prev}|${seq}|${case_id}|${action}|${at}`).digest("hex");
  const decision: Decision = { seq, case_id, action, at, prev, hash };
  mkdirSync(dirname(path), { recursive: true });
  appendFileSync(path, JSON.stringify(decision) + "\n");
  return decision;
}

/** Latest action per case, or undefined when the case is still open. */
export function latestByCase(decisions: Decision[]): Map<string, Action> {
  const map = new Map<string, Action>();
  for (const d of decisions) map.set(d.case_id, d.action);
  return map;
}
