// Writes the built-in sound pack's gavel clip. Run: npx tsx scripts/make-default-pack.ts
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { gavelSamples } from "../src/sounds.ts";
import { writeWav } from "../server/soundpack.ts";

const RATE = 22050;
const out = join(fileURLToPath(new URL("..", import.meta.url)), "sound-packs", "default");
writeFileSync(join(out, "gavel.wav"), writeWav(gavelSamples(RATE), RATE));
console.log("wrote", join(out, "gavel.wav"));
