// Ranks come from convictions. Thresholds are constants, not policy: they are presentation, not enforcement.
//
// PLAN:
// 1. Walk the ladder from the top. The first threshold the count meets is the rank.

const LADDER: readonly [number, string][] = [
  [50, "Chief"],
  [25, "Sergeant"],
  [10, "Detective"],
  [3, "Officer"],
  [0, "Rookie"],
];

export function rankFor(convictions: number): string {
  for (const [min, name] of LADDER) {
    if (convictions >= min) return name;
  }
  return "Rookie";
}
