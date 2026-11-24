---
name: encrypt-ai-detector
description: AI encryption-type detection through the local claude.exe (Claude Code headless). Calculates the exact facts with the rule engine, has Claude analyse them and research algorithm formats on the web, and prints only the result. Use when someone asks for an "AI" / "Claude" / "claude.exe" detection or analysis of a hash, ciphertext, key or encoded value, or wants a researched second opinion beyond the rule-only encrypt-detector.
---

# encrypt-ai-detector

One script does the whole job: **calculate** (rule engine from the Data Encrypt Study website counts bytes and checks
structure), **analyse** (claude.exe headless, the same prompt and answer schema as the website's Ask Claude) and
**research** (claude.exe may use WebSearch for algorithm facts; it is told never to search for the value itself).

## Steps

1. Pass the value on stdin (keeps `$` and PEM newlines intact):

   ```bash
   printf '%s' '<value>' | node <skill-dir>/scripts/ask.mjs
   ```

   `<skill-dir>` is this skill's folder. Add `--json` for the raw result. It can take up to 3 minutes.

2. **Show the script's output only.** Print it as-is in a code block. No intro, no extra explanation, no own guesses
   before or after it. If the script fails, show its one-line error instead.

## Notes

- claude.exe is found at `CLAUDE_BIN`, `~/.local/bin`, `PATH`, then the newest VS Code Claude Code extension. It uses
  the user's own Claude login; the value is sent to Claude (Anthropic), so don't use it for real production secrets.
- Claude gets WebSearch only: no files, shell, settings or MCP servers. The value goes in through stdin.
- `scripts/lib/*.mjs` are generated from `src/lib/{classify,detect}.ts` by `npm run skill:build`. Don't edit them.
- Check without calling Claude: `node scripts/selftest.mjs`.
