// Copies the website's detection code into the encrypt-detector and encrypt-ai-detector skills as plain JavaScript: npm run skill:build
// One source of truth: edit src/lib/classify.ts, seed.ts or detect.ts, then run this. The generated files must not be edited.
// Plain .mjs (not .ts) so the skills run on any Node 18+ and keep working when the folder is copied to ~/.claude/skills/.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
// encrypt-detector: rules + SEED (for --key). encrypt-ai-detector: rules + the Ask Claude prompt and answer schema.
const targets = { "encrypt-detector": ["classify", "seed"], "encrypt-ai-detector": ["classify", "detect"] };

for (const [skill, names] of Object.entries(targets)) {
  const out = path.join(root, `.claude/skills/${skill}/scripts/lib`);
  fs.mkdirSync(out, { recursive: true });
  for (const name of names) {
    const src = fs.readFileSync(path.join(root, `src/lib/${name}.ts`), "utf8");
    const js = ts.transpileModule(src, { compilerOptions: { target: ts.ScriptTarget.ES2020, module: ts.ModuleKind.ESNext } }).outputText;
    const header = `// GENERATED from src/lib/${name}.ts by scripts/build-skill.mjs (npm run skill:build). Do not edit: edit the .ts and rebuild.\n`;
    fs.writeFileSync(path.join(out, `${name}.mjs`), header + js);
    console.log(`wrote .claude/skills/${skill}/scripts/lib/${name}.mjs`);
  }
}
