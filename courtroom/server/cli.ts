// Start the courtroom for the local user: reads ~/.agentcop, prints the URL with the token in the fragment.
import { homedir } from "node:os";
import { join } from "node:path";
import { startCourtroom } from "./server.ts";

const home = join(homedir(), ".agentcop");
const port = Number(process.env.COURTROOM_PORT ?? 8787);
const court = await startCourtroom({
  dbPath: join(home, "evidence.db"),
  decisionsPath: join(home, "decisions.jsonl"),
  port,
});
console.log(`Courtroom open at ${court.url}/#token=${court.token}`);
console.log("Local only. Ctrl+C to stop.");
