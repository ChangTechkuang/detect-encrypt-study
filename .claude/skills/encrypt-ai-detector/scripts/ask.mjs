#!/usr/bin/env node
// encrypt-ai-detector: calculate (rule engine) -> analyse + research (claude.exe headless) -> print the result only.
//
//   printf '%s' '<value>' | node ask.mjs          plain-text result
//   printf '%s' '<value>' | node ask.mjs --json   the raw JSON result
//
// claude.exe is found at CLAUDE_BIN, ~/.local/bin, PATH, then the newest VS Code Claude Code extension.
// It runs with the user's own Claude login, WebSearch as its only tool, no settings/MCP/project files.
import { execFileSync, spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { classify } from "./lib/classify.mjs";
import { MAX_INPUT, RESULT_SCHEMA, SYSTEM_PROMPT } from "./lib/detect.mjs";

const TIMEOUT_MS = 180_000; // research (web search) takes longer than the website's 90 s
const EXE = process.platform === "win32" ? "claude.exe" : "claude";

const RESEARCH = `

You may use WebSearch to RESEARCH facts about algorithms and formats (output sizes, prefixes, headers, which systems use them)
when the rule check and your own knowledge are not enough. NEVER put the DATA, or any part of it, in a search query: search for
algorithm names and sizes only. Do the arithmetic yourself from the rule check (bytes, blocks, IV + tag layouts) and show it in
the reasons, e.g. "24 bytes = 8-byte IV + 2 x 8-byte DES blocks".`;

export function findClaude() {
  const isFile = (p) => { try { return fs.statSync(p).isFile(); } catch { return false; } };
  for (const p of [process.env.CLAUDE_BIN, path.join(os.homedir(), ".local", "bin", EXE)]) if (p && isFile(p)) return p;
  try {
    const hit = execFileSync(process.platform === "win32" ? "where" : "which", ["claude"], { encoding: "utf8", windowsHide: true, stdio: ["ignore", "pipe", "ignore"] })
      .split(/\r?\n/).map((l) => l.trim()).find(isFile);
    if (hit) return hit;
  } catch { /* not on PATH */ }
  const ext = path.join(os.homedir(), ".vscode", "extensions");
  try {
    const dirs = fs.readdirSync(ext).filter((d) => d.startsWith("anthropic.claude-code-"))
      .sort((a, b) => a.localeCompare(b, undefined, { numeric: true })).reverse();
    for (const d of dirs) { const p = path.join(ext, d, "resources", "native-binary", EXE); if (isFile(p)) return p; }
  } catch { /* no VS Code */ }
  return null;
}

/** Same facts line the website's /api/detect sends: computed by code, so Claude explains instead of recounting. */
export function facts(text) {
  const r = classify(text);
  return `RULE CHECK (computed by code): category=${r.category} (${Math.round(r.categoryConfidence * 100)}%), algorithm=${r.algorithm}, ` +
    `representation=${r.representation}, bytes=${r.bytes}. Evidence: ${r.evidence.join(" ")} Could also be: ${r.candidates.join("; ") || "-"}`;
}

function runClaude(bin, input) {
  const args = ["-p", "--output-format", "json", "--tools", "WebSearch", "--allowedTools", "WebSearch",
    "--strict-mcp-config", "--setting-sources", "", "--no-session-persistence",
    "--system-prompt", SYSTEM_PROMPT + RESEARCH, "--json-schema", JSON.stringify(RESULT_SCHEMA)];
  return new Promise((resolve, reject) => {
    // cwd = temp dir so no CLAUDE.md or project context is picked up; the value goes in on stdin, never the command line
    const p = spawn(bin, args, { cwd: os.tmpdir(), windowsHide: true });
    let out = "", err = "";
    const timer = setTimeout(() => { p.kill(); reject(new Error("claude.exe took too long (180 s).")); }, TIMEOUT_MS);
    p.stdout.on("data", (d) => (out += d));
    p.stderr.on("data", (d) => (err += d));
    p.on("error", (e) => { clearTimeout(timer); reject(new Error(`Cannot start claude.exe: ${e.message}`)); });
    p.on("close", (code) => {
      clearTimeout(timer);
      if (code === 0 || out.trim().startsWith("{")) resolve(out);
      else reject(new Error(`claude.exe exited with code ${code}: ${err.slice(0, 300) || "no output"}. Is Claude Code logged in?`));
    });
    p.stdin.end(input);
  });
}

export function format(r, text) {
  const c = classify(text);
  return [
    `Result: ${r.summary}`,
    "",
    "Candidates:",
    ...r.candidates.map((x, i) => `  ${i + 1}. ${x.type} (${x.family}, ${x.confidence}): ${x.reason}`),
    "",
    // odd hex / plain text never decodes, so bytes is 0: show the character count instead
    `Calculated: ${c.bytes ? `${c.bytes} bytes` : `${text.replace(/\s+/g, "").length} characters (not decodable)`}, ${c.representation}, rule category ${c.category} (${Math.round(c.categoryConfidence * 100)}%)`,
    `Next step: ${r.nextStep}`,
  ].join("\n");
}

// ---- command line
if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname.replace(/^\/(\w:)/, "$1"))) {
  const json = process.argv.includes("--json");
  let text = process.argv.slice(2).filter((a) => a !== "--json").join(" ");
  if (!text && !process.stdin.isTTY) text = await new Promise((res) => { let s = ""; process.stdin.on("data", (d) => (s += d)); process.stdin.on("end", () => res(s)); });
  const fail = (msg) => { console.error(msg); process.exit(1); };
  if (!text.trim()) fail("No value given. usage: printf '%s' '<value>' | node ask.mjs [--json]");
  if (text.length > MAX_INPUT) fail(`Too long: max ${MAX_INPUT} characters.`);
  const bin = findClaude();
  if (!bin) fail("claude.exe not found. Install Claude Code, or set CLAUDE_BIN to the full path of claude.exe.");
  try {
    const res = JSON.parse(await runClaude(bin, `${facts(text)}\n\nDATA:\n${text.trim()}`));
    const r = res.structured_output;
    if (res.is_error || !r?.candidates) fail(`Claude error: ${res.result ?? res.subtype ?? "unexpected answer"}`);
    console.log(json ? JSON.stringify(r, null, 2) : format(r, text));
  } catch (e) { fail(e.message); }
}
