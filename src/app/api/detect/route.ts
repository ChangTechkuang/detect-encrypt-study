import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { MAX_INPUT, RESULT_SCHEMA, SYSTEM_PROMPT, isDetectResult } from "@/lib/detect";
import { classify } from "@/lib/classify";

// Runs Claude Code's claude.exe in headless mode (-p) with the user's own Claude login: no API key.
// shortcut: only works on a machine where claude.exe is installed and logged in (local use), not on a public server.
const TIMEOUT_MS = 90_000;

/** CLAUDE_BIN if set, else the newest claude.exe in this user's VS Code extensions, else `claude` on PATH.
 *  Looked up per request so an extension update (which deletes the old folder) needs no restart. */
function findClaude(): string {
  if (process.env.CLAUDE_BIN) return process.env.CLAUDE_BIN;
  const ext = path.join(os.homedir(), ".vscode", "extensions");
  try {
    const dirs = fs.readdirSync(ext).filter((d) => d.startsWith("anthropic.claude-code-"))
      .sort((a, b) => b.localeCompare(a, undefined, { numeric: true })); // 2.1.330 before 2.1.99
    for (const d of dirs) {
      const exe = path.join(ext, d, "resources", "native-binary", process.platform === "win32" ? "claude.exe" : "claude");
      if (fs.existsSync(exe)) return exe;
    }
  } catch { /* no VS Code extensions folder */ }
  return "claude";
}

export async function POST(req: Request) {
  let text: unknown, claudePath: unknown;
  try { ({ text, claudePath } = await req.json()); } catch { return Response.json({ error: "Send JSON: { \"text\": \"...\" }" }, { status: 400 }); }
  if (typeof text !== "string" || !text.trim()) return Response.json({ error: "Paste something to detect." }, { status: 400 });
  if (text.length > MAX_INPUT) return Response.json({ error: `Too long: max ${MAX_INPUT} characters.` }, { status: 400 });
  // The path comes from the browser and gets executed: only accept an existing file actually named claude(.exe)
  if (claudePath !== undefined && !isClaudePath(claudePath))
    return Response.json({ error: "That is not a path to claude.exe. Enter the full path, e.g. C:\\...\\claude.exe.", needPath: true }, { status: 400 });
  const bin = (claudePath as string | undefined) || findClaude();

  try {
    // The rule check is computed by code from the exact bytes, so Claude explains it instead of recounting
    const r = classify(text);
    const facts = `RULE CHECK (computed by code): category=${r.category} (${Math.round(r.categoryConfidence * 100)}%), algorithm=${r.algorithm}, ` +
      `representation=${r.representation}, bytes=${r.bytes}. Evidence: ${r.evidence.join(" ")} Could also be: ${r.candidates.join("; ") || "-"}`;
    const out = await runClaude(bin, `${facts}

DATA:
${text.trim()}`);
    const json = JSON.parse(out);
    if (json.is_error) return Response.json({ error: `Claude error: ${json.result ?? json.subtype}` }, { status: 502 });
    if (!isDetectResult(json.structured_output)) return Response.json({ error: "Claude returned an unexpected answer. Try again." }, { status: 502 });
    return Response.json(json.structured_output);
  } catch (e) {
    return Response.json({ error: (e as Error).message, needPath: e instanceof NotFound || undefined }, { status: 502 });
  }
}

class NotFound extends Error {}

function isClaudePath(p: unknown): p is string {
  if (typeof p !== "string" || !path.isAbsolute(p) || !/^claude(\.exe)?$/i.test(path.basename(p))) return false;
  try { return fs.statSync(p).isFile(); } catch { return false; }
}

/** Input goes in through stdin (never the command line), and Claude gets no tools, settings, MCP servers or project files. */
function runClaude(bin: string, input: string): Promise<string> {
  const args = [
    "-p", "--output-format", "json",
    "--tools", "",                // no tools: the input can't make it run commands or read files
    "--strict-mcp-config", "--setting-sources", "",
    "--no-session-persistence",
    "--system-prompt", SYSTEM_PROMPT,
    "--json-schema", JSON.stringify(RESULT_SCHEMA),
  ];
  return new Promise((resolve, reject) => {
    // cwd = temp dir so no CLAUDE.md or project context is picked up
    // turbopackIgnore: claude.exe is an external program, not a project file the bundler should trace
    const p = spawn(/*turbopackIgnore: true*/ bin, args, { cwd: os.tmpdir(), windowsHide: true });
    let stdout = "", stderr = "";
    const timer = setTimeout(() => { p.kill(); reject(new Error("Claude took too long (90 s). Try again.")); }, TIMEOUT_MS);
    p.stdout.on("data", (d) => (stdout += d));
    p.stderr.on("data", (d) => (stderr += d));
    p.on("error", (e) => { clearTimeout(timer); reject(new NotFound(`Cannot start claude.exe (${e.message}). Enter where claude.exe is stored.`)); });
    p.on("close", (code) => {
      clearTimeout(timer);
      if (code === 0 || stdout.trim().startsWith("{")) resolve(stdout);
      else reject(new Error(`claude.exe exited with code ${code}: ${stderr.slice(0, 300) || "no output"}. Is Claude Code logged in?`));
    });
    p.stdin.end(input);
  });
}
