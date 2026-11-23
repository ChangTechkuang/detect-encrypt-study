// Server only: Ask Claude on Vercel, through the Claude API (billed to ANTHROPIC_API_KEY). Locally claude.exe is used instead.
import Anthropic from "@anthropic-ai/sdk";
import { RESULT_SCHEMA, SYSTEM_PROMPT } from "@/lib/detect";

// Created on first use: the local claude.exe path imports this file without an API key set
let client: Anthropic | undefined;

/** Same prompt and JSON schema as the claude.exe path; returns the parsed JSON answer. */
export async function askClaudeApi(input: string): Promise<unknown> {
  client ??= new Anthropic(); // reads ANTHROPIC_API_KEY
  const msg = await client.beta.messages.create({
    model: "claude-opus-5-5",
    max_tokens: 8000,
    // Low effort: a short classification, keeps each click cheap and fast
    output_config: { effort: "low", format: { type: "json_schema", schema: RESULT_SCHEMA } },
    // If a safety classifier declines, the API retries on a fallback model within the same call
    betas: ["server-side-fallback-2026-07-01"],
    fallbacks: "default",
    system: SYSTEM_PROMPT,
    messages: [{ role: "user", content: input }],
  });
  if (msg.stop_reason === "refusal") throw new Error("Claude declined to answer this one.");
  if (msg.stop_reason === "max_tokens") throw new Error("Claude's answer was cut off. Try again.");
  const text = msg.content.find((b) => b.type === "text");
  return text ? JSON.parse(text.text) : null;
}
