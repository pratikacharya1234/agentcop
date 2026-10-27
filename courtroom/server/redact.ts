// Secrets never leave the server in case text. Each match becomes [REDACTED:<name>].
//
// PLAN:
// 1. Known shapes only: AWS access key ids, PEM private key blocks, GitHub tokens.
// 2. A PEM header with no footer redacts to the end of the text (fail closed).
// Limit: this list is a copy of the egress patterns in policy/egress.toml. It is not read from that file yet.

const PATTERNS: [string, RegExp][] = [
  ["aws-access-key", /AKIA[0-9A-Z]{16}/g],
  ["private-key-block", /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g],
  ["github-token", /gh[pousr]_[A-Za-z0-9]{36}/g],
];

export function redact(text: string): string {
  let out = text;
  for (const [name, pattern] of PATTERNS) {
    out = out.replace(pattern, `[REDACTED:${name}]`);
  }
  return out;
}
