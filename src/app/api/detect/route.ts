import { spawn } from "node:child_process";
import os from "node:os";
import Anthropic from "@anthropic-ai/sdk";
import { MAX_INPUT, PER_VISITOR, RESULT_SCHEMA, SYSTEM_PROMPT, isDetectResult } from "@/lib/detect";
import { classify } from "@/lib/classify";
import { findClaude, isClaudePath } from "@/lib/claude";
import { askClaudeApi } from "@/lib/claude-api";

// Locally: runs Claude Code's claude.exe in headless mode (-p) with the user's own Claude login, no API key.
// On Vercel: the Claude API with ANTHROPIC_API_KEY (see askClaudeApi), limited per visitor.
const TIMEOUT_MS = 90_000;

export async function POST(req: Request) {
  let text: unknown, claudePath: unknown, apiKey: unknown;
  try { ({ text, claudePath, apiKey } = await req.json()); } catch { return Response.json({ error: "Send JSON: { \"text\": \"...\" }" }, { status: 400 }); }
  if (typeof text !== "string" || !text.trim()) return Response.json({ error: "Paste something to detect." }, { status: 400 });
  if (text.length > MAX_INPUT) return Response.json({ error: `Too long: max ${MAX_INPUT} characters.` }, { status: 400 });

  // The rule check is computed by code from the exact bytes, so Claude explains it instead of recounting
  const r = classify(text);
  const facts = `RULE CHECK (computed by code): category=${r.category} (${Math.round(r.categoryConfidence * 100)}%), algorithm=${r.algorithm}, ` +
    `representation=${r.representation}, bytes=${r.bytes}. Evidence: ${r.evidence.join(" ")} Could also be: ${r.candidates.join("; ") || "-"}`;
  const input = `${facts}\n\nDATA:\n${text.trim()}`;

  // Vercel has no claude.exe: use the Claude API with the visitor's own key, else the site's key with a per-visitor limit
  if (process.env.VERCEL) {
    const userKey = typeof apiKey === "string" && /^sk-ant-[\w-]{10,250}$/.test(apiKey.trim()) ? apiKey.trim() : undefined;
    if (apiKey !== undefined && !userKey)
      return Response.json({ error: "That doesn't look like a Claude API key. It starts with sk-ant-.", needKey: true }, { status: 400 });
    if (!userKey && !process.env.ANTHROPIC_API_KEY)
      return Response.json({ error: "Enter your Claude API key to use Ask Claude here.", needKey: true }, { status: 401 });
    if (!userKey) {
      const limited = overLimit(req.headers.get("x-forwarded-for")?.split(",")[0].trim() || "unknown");
      if (limited) return Response.json({ error: limited, needKey: true }, { status: 429 });
    }
    try {
      const out = await askClaudeApi(input, userKey);
      if (!isDetectResult(out)) return Response.json({ error: "Claude returned an unexpected answer. Try again." }, { status: 502 });
      return Response.json(out);
    } catch (e) {
      if (userKey && (e instanceof Anthropic.AuthenticationError || e instanceof Anthropic.PermissionDeniedError))
        return Response.json({ error: "Claude rejected that API key. Check it and try again.", needKey: true }, { status: 401 });
      console.error("Claude API", e instanceof Anthropic.APIError ? `${e.status} ${e.name}` : e); // never logs the key
      return Response.json({ error: e instanceof Anthropic.RateLimitError ? "Claude is busy. Try again in a minute." :
        e instanceof Anthropic.APIError ? "Claude is not available right now. Try again later." : (e as Error).message }, { status: 502 });
    }
  }

  // The path comes from the browser and gets executed: only accept an existing file actually named claude(.exe)
  if (claudePath !== undefined && !isClaudePath(claudePath))
    return Response.json({ error: "That is not a path to claude.exe. Enter the full path, e.g. C:\\...\\claude.exe.", needPath: true }, { status: 400 });
  const bin = (claudePath as string | undefined) || findClaude();

  try {
    const out = await runClaude(bin, input);
    const json = JSON.parse(out);
    if (json.is_error) return Response.json({ error: `Claude error: ${json.result ?? json.subtype}` }, { status: 502 });
    if (!isDetectResult(json.structured_output)) return Response.json({ error: "Claude returned an unexpected answer. Try again." }, { status: 502 });
    return Response.json(json.structured_output);
  } catch (e) {
    return Response.json({ error: (e as Error).message, needPath: e instanceof NotFound || undefined }, { status: 502 });
  }
}

class NotFound extends Error {}

// shortcut: counts live in this server instance's memory, so they reset on a cold start and each Vercel instance
// counts on its own; set a monthly spend limit in the Claude Console as the hard cap, and move to Vercel KV/Upstash if abused.
const PER_DAY = 200; // whole site
const uses = new Map<string, number>();
let day = "";

/** Error message when this visitor (by IP) or the whole site is over today's limit, else "" (and counts the use). */
function overLimit(ip: string): string {
  const today = new Date().toISOString().slice(0, 10);
  if (today !== day) { uses.clear(); day = today; }
  const total = uses.get("*") ?? 0, mine = uses.get(ip) ?? 0;
  if (total >= PER_DAY) return "Ask Claude has reached today's limit for this site. Try again tomorrow, or run the site locally.";
  if (mine >= PER_VISITOR) return `You've used Ask Claude ${PER_VISITOR} times today. Try again tomorrow, or run the site locally.`;
  uses.set("*", total + 1); uses.set(ip, mine + 1);
  return "";
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
    p.on("error", (e) => { clearTimeout(timer); reject(new NotFound(`Cannot start claude.exe (${e.message}). Install Claude Code, or enter where claude.exe is stored.`)); });
    p.on("close", (code) => {
      clearTimeout(timer);
      if (code === 0 || stdout.trim().startsWith("{")) resolve(stdout);
      else reject(new Error(`claude.exe exited with code ${code}: ${stderr.slice(0, 300) || "no output"}. Is Claude Code logged in?`));
    });
    p.stdin.end(input);
  });
}
