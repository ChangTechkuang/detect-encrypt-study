import { execFile } from "node:child_process";
import fs from "node:fs";
import { LOCAL_ONLY } from "@/lib/detect";
import { INSTALLED } from "@/lib/claude";

// Runs Anthropic's official Claude Code installer, which puts claude.exe in C:\Users\<you>\.local\bin.
// Local dev server only: never on Vercel or a production build.
const WIN = ["powershell", ["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "irm https://claude.ai/install.ps1 | iex"]] as const;
const UNIX = ["bash", ["-c", "curl -fsSL https://claude.ai/install.sh | bash"]] as const;

export async function POST() {
  if (process.env.VERCEL || process.env.NODE_ENV !== "development") return Response.json({ error: LOCAL_ONLY }, { status: 403 });
  if (fs.existsSync(INSTALLED)) return Response.json({ path: INSTALLED });

  const [cmd, args] = process.platform === "win32" ? WIN : UNIX;
  const log = await new Promise<string>((resolve) =>
    execFile(cmd, args, { timeout: 5 * 60_000, windowsHide: true }, (err, out, errOut) => resolve(`${out}${errOut}${err ? err.message : ""}`)));

  if (!fs.existsSync(INSTALLED))
    return Response.json({ error: `Install failed: ${log.trim().slice(-300) || "no output"}` }, { status: 500 });
  return Response.json({ path: INSTALLED });
}
