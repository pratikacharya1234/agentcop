// Read-only access to the evidence DB. The courtroom never writes it.
//
// PLAN:
// 1. Open the DB read-only. A missing DB means no cases yet, not an error.
// 2. Case ID = CASE- plus the first 12 hex of the hash (the same ID the CLI prints).
// 3. Parse event_json safely. Any text from the agent is kept as data and capped in length.

import { existsSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";

export interface CaseRow {
  case_id: string;
  timestamp: string;
  verdict: string;
  tool_name: string;
  command: string;
  reason: string;
}

const MAX_TEXT = 2000;

export function readCases(dbPath: string): CaseRow[] {
  if (!existsSync(dbPath)) return [];
  const db = new DatabaseSync(dbPath, { readOnly: true });
  try {
    const rows = db
      .prepare("SELECT timestamp, event_json, verdict, reason, hash FROM cases ORDER BY id")
      .all() as { timestamp: string; event_json: string; verdict: string; reason: string; hash: string }[];
    return rows.map((r) => {
      const event = parseEvent(r.event_json);
      return {
        case_id: `CASE-${r.hash.slice(0, 12)}`,
        timestamp: cap(r.timestamp, 64),
        verdict: cap(r.verdict, 16),
        tool_name: cap(event.tool_name, 64),
        command: cap(event.command, MAX_TEXT),
        reason: cap(r.reason, 512),
      };
    });
  } finally {
    db.close();
  }
}

function parseEvent(json: string): { tool_name: string; command: string } {
  try {
    const e = JSON.parse(json) as { tool_name?: unknown; tool_input?: unknown };
    const tool_name = typeof e.tool_name === "string" ? e.tool_name : "?";
    const input = e.tool_input;
    const command =
      input && typeof input === "object" && typeof (input as { command?: unknown }).command === "string"
        ? (input as { command: string }).command
        : JSON.stringify(input ?? null);
    return { tool_name, command };
  } catch {
    return { tool_name: "?", command: "(unreadable event)" };
  }
}

function cap(text: string, max: number): string {
  return text.length <= max ? text : text.slice(0, max) + "…";
}
