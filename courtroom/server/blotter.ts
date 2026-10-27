// Weekly Police Blotter and Wanted list. Pure functions over case summaries.
//
// PLAN:
// 1. A week runs Monday to Sunday in UTC. Its key is the Monday's date (YYYY-MM-DD).
// 2. The blotter counts each verdict and status per week, oldest week first.
// 3. Wanted = deny cases that were not released. Convicted cases stay on the list.

export interface CaseSummary {
  case_id: string;
  timestamp: string;
  verdict: string;
  status: string;
}

export interface WeekRow {
  week: string;
  cases: number;
  deny: number;
  ask: number;
  allow: number;
  convicted: number;
  released: number;
}

export function weekKey(timestamp: string): string {
  const d = new Date(timestamp);
  const daysSinceMonday = (d.getUTCDay() + 6) % 7;
  const monday = Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate() - daysSinceMonday);
  return new Date(monday).toISOString().slice(0, 10);
}

export function weeklyBlotter(cases: CaseSummary[]): WeekRow[] {
  const weeks = new Map<string, WeekRow>();
  for (const c of cases) {
    const key = weekKey(c.timestamp);
    const row = weeks.get(key) ?? { week: key, cases: 0, deny: 0, ask: 0, allow: 0, convicted: 0, released: 0 };
    row.cases += 1;
    if (c.verdict === "deny" || c.verdict === "ask" || c.verdict === "allow") row[c.verdict] += 1;
    if (c.status === "convicted") row.convicted += 1;
    if (c.status === "released") row.released += 1;
    weeks.set(key, row);
  }
  return [...weeks.values()].sort((a, b) => a.week.localeCompare(b.week));
}

export function wanted<T extends { verdict: string; status: string }>(cases: T[]): T[] {
  return cases.filter((c) => c.verdict === "deny" && c.status !== "released");
}
