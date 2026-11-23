// Copies the website's detection code into the crypto-detect skill as plain JavaScript: npm run skill:build
// One source of truth: edit src/lib/classify.ts or src/lib/seed.ts, then run this. The generated files must not be edited.
// Plain .mjs (not .ts) so the skill runs on any Node 18+ and keeps working when the folder is copied to ~/.claude/skills/.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const out = path.join(root, ".claude/skills/crypto-detect/scripts/lib");
fs.mkdirSync(out, { recursive: true });

for (const name of ["classify", "seed"]) {
  const src = fs.readFileSync(path.join(root, `src/lib/${name}.ts`), "utf8");
  const js = ts.transpileModule(src, { compilerOptions: { target: ts.ScriptTarget.ES2020, module: ts.ModuleKind.ESNext } }).outputText;
  const header = `// GENERATED from src/lib/${name}.ts by scripts/build-skill.mjs (npm run skill:build). Do not edit: edit the .ts and rebuild.\n`;
  fs.writeFileSync(path.join(out, `${name}.mjs`), header + js);
  console.log(`wrote .claude/skills/crypto-detect/scripts/lib/${name}.mjs`);
}
