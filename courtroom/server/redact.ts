// Secrets never leave the server in case text. Each match becomes [REDACTED:<name>].
//
// PLAN:
// 1. The built-in patterns of policy/redact.toml (2026-10-27): the same names, in the same order.
// 2. A PEM header with no footer redacts to the end of the text (fail closed).
// Limit: this list is a copy of policy/redact.toml. A unit test checks that every name there is here.

const PATTERNS: [string, RegExp][] = [
  ["aws-access-key", /AKIA[0-9A-Z]{16}/g],
  ["github-token", /gh[pousr]_[A-Za-z0-9]{20,}/g],
  ["github-fine-grained-token", /github_pat_[A-Za-z0-9_]{20,}/g],
  ["api-key-sk", /sk-[A-Za-z0-9_-]{16,}/g],
  ["slack-token", /xox[abposr]-[A-Za-z0-9-]{10,}/g],
  ["jwt", /eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}/g],
  ["private-key-block", /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g],
  ["authorization-header", /authorization:[^\n"'\\]*/gi],
  ["bearer-token", /bearer\s+[A-Za-z0-9._~+/=-]{8,}/gi],
  ["password-or-token-value", /\b(?:password|passwd|pwd|token|secret|api[_-]?key)=[^\s"'&;]+/gi],
  ["url-userinfo", /[A-Za-z][A-Za-z0-9+.-]*:\/\/[^\s/:@"']+:[^\s/@"']+@/g],
];

export function redact(text: string): string {
  let out = text;
  for (const [name, pattern] of PATTERNS) {
    out = out.replace(pattern, `[REDACTED:${name}]`);
  }
  return out;
}
