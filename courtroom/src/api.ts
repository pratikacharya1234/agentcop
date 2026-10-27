// Calls to the courtroom server. The token is kept in memory only.

export type Status = "open" | "convicted" | "released";

export interface CaseItem {
  case_id: string;
  timestamp: string;
  verdict: string;
  tool_name: string;
  command: string;
  reason: string;
  status: Status;
}

export interface Blotter {
  rank: { name: string; convictions: number };
  weeks: { week: string; cases: number; deny: number; ask: number; allow: number; convicted: number; released: number }[];
  wanted: CaseItem[];
}

export class Api {
  constructor(private readonly token: string) {}

  private headers(): HeadersInit {
    return { Authorization: `Bearer ${this.token}`, "Content-Type": "application/json" };
  }

  async listCases(): Promise<CaseItem[]> {
    const res = await fetch("/api/cases", { headers: this.headers() });
    if (!res.ok) throw new Error(`list failed: ${res.status}`);
    return (await res.json()) as CaseItem[];
  }

  async blotter(): Promise<Blotter> {
    const res = await fetch("/api/blotter", { headers: this.headers() });
    if (!res.ok) throw new Error(`blotter failed: ${res.status}`);
    return (await res.json()) as Blotter;
  }

  async decide(caseId: string, action: "release" | "convict"): Promise<void> {
    const res = await fetch(`/api/cases/${caseId}/decision`, {
      method: "POST",
      headers: this.headers(),
      body: JSON.stringify({ action }),
    });
    if (!res.ok) throw new Error(`decision failed: ${res.status}`);
  }
}

const TOKEN_KEY = "courtroom.token";

/**
 * Read the token from the URL fragment, then remove it from the address bar.
 * It is kept in sessionStorage so a reload in the same tab still works. The tab closing clears it.
 */
export function takeTokenFromUrl(): string | null {
  const match = /^#token=([A-Za-z0-9_-]+)$/.exec(window.location.hash);
  if (match) {
    window.history.replaceState(null, "", window.location.pathname + window.location.search);
    try {
      sessionStorage.setItem(TOKEN_KEY, match[1]);
    } catch {
      // Storage blocked: the token lasts until this page is reloaded.
    }
    return match[1];
  }
  try {
    return sessionStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}
