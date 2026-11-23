// Server only: where the standalone Claude Code (claude.exe) lives. Used by /api/detect and /api/detect/install.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const EXE = process.platform === "win32" ? "claude.exe" : "claude";
/** Where Anthropic's official installer puts it: C:\Users\<you>\.local\bin\claude.exe */
export const INSTALLED = path.join(os.homedir(), ".local", "bin", EXE);

/** CLAUDE_BIN if set, else the official install location, else `claude` on PATH (spawn fails with ENOENT if absent). */
export function findClaude(): string {
  if (process.env.CLAUDE_BIN) return process.env.CLAUDE_BIN;
  return fs.existsSync(INSTALLED) ? INSTALLED : "claude";
}

/** A path from the browser gets executed: only accept an existing file actually named claude(.exe). */
export function isClaudePath(p: unknown): p is string {
  if (typeof p !== "string" || !path.isAbsolute(p) || !/^claude(\.exe)?$/i.test(path.basename(p))) return false;
  try { return fs.statSync(p).isFile(); } catch { return false; }
}
