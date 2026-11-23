// Sends a stratified subset of data/test.json to the running site's /api/detect (the Claude engine).
// node eval/run-ai.mjs <out.json> [baseUrl]   (start the site first: npm start)
// 3 samples per algorithm: plaintext 0 as hex, 2 as Base64, 4 as hex. Mapping: top candidate's family -> category.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
const here = path.dirname(fileURLToPath(import.meta.url));
const [out = "data/ai.json", base = "http://localhost:3100"] = process.argv.slice(2);
const { samples } = JSON.parse(fs.readFileSync(path.join(here, "data/test.json"), "utf8"));

const pts = [...new Set(samples.map((s) => s.plaintext))];
const pick = [[0, "hex"], [2, "base64"], [4, "hex"]];
const subset = samples.filter((s) => pick.some(([i, e]) => s.plaintext === pts[i] && s.encoding === e));
const FAMILY = { hash: "hashing", symmetric: "symmetric", asymmetric: "asymmetric" };

const results = [];
let next = 0;
async function worker() {
  while (next < subset.length) {
    const s = subset[next++];
    let r;
    try {
      const res = await fetch(base + "/api/detect", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ text: s.value }) });
      const j = await res.json();
      const top = j.candidates?.[0];
      r = res.ok && top
        ? { category: FAMILY[top.family] ?? "UNKNOWN", confidence: top.confidence, algorithm: top.type }
        : { category: "UNKNOWN", confidence: "error", algorithm: j.error ?? "no answer" };
    } catch (e) { r = { category: "UNKNOWN", confidence: "error", algorithm: e.message }; }
    results.push({ id: s.id, ...r });
    console.log(`${results.length}/${subset.length} ${s.algorithm} (${s.encoding}) -> ${r.category} / ${r.confidence} / ${r.algorithm}`);
  }
}
await Promise.all([worker(), worker(), worker()]);
fs.writeFileSync(path.join(here, out), JSON.stringify(results, null, 1));
