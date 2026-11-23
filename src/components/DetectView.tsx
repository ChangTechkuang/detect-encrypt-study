"use client";

// Detect flow: 1 Paste -> 2 Scan (animated 1-100%, the instant rules of classify.ts) -> 3 Key (Continue or Skip,
// only when a key could help) -> 4 Result list -> optional "Ask Claude to explain".
import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { AnimatePresence, motion, useReducedMotion } from "motion/react";
import type { Candidate, DetectResult } from "@/lib/detect";
import { MAX_INPUT } from "@/lib/detect";
import { byId, guessEncoding } from "@/lib/encoding";
import { classify, type Classification } from "@/lib/classify";
import { RSA_TEST_PUB } from "@/lib/impl/rsa";
import { Button, CopyButton, Input, Label, Note, Section, TextArea } from "./impl/ui";
import type { Attempt } from "@/lib/trykey";
import { ACCENT } from "./accent";

// Real values from this project's test vectors and Java runs
const EXAMPLES: [string, string][] = [
  ["MD5 hash", "900150983cd24fb0d6963f7d28e17f72"],
  ["SHA-256 hash", "185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969"],
  ["bcrypt", "$2a$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i"],
  ["Ciphertext (Base64)", "y+VUzkkv67XTQJtc3o162us7DbsvaB2UXZtuFnBOFMKh29fuPKv4U05BZOlfglRX"],
  ["RSA public key", RSA_TEST_PUB],
  ["Base64 text", "SGVsbG8gd29ybGQ="],
  ["URL encoded", "a%20b%26c%20%ED%95%9C%EA%B8%80"],
];

const CONF = {
  certain: "text-ok border-ok/40 bg-ok/10",
  likely: "text-info border-info/40 bg-info/10",
  possible: "text-muted border-line bg-paper",
} as const;

const CATEGORY = { hashing: "Hashing", symmetric: "Symmetric encryption", asymmetric: "Asymmetric (public-key)", encoding: "Encoding (not encrypted)" } as const;

// The whole card takes the same colour as its confidence badge, softer
const CARD = {
  certain: "border-ok/40 bg-ok/5",
  likely: "border-info/40 bg-info/5",
  possible: "border-line bg-paper",
} as const;

type Phase = "input" | "scanning" | "key" | "done";
const SCAN_MS = 2400;
const PATH_KEY = "claudePath";

/** The 5 scan stages, each with the real finding from classify(). */
function stagesOf(r: Classification): [name: string, finding: string][] {
  const notRandom = r.evidence.find((e) => /repeat|pattern|odd number/.test(e));
  return [
    ["Decode", r.representation === "hex" ? `Hex → ${r.bytes} bytes` : r.representation === "base64" ? `Base64 → ${r.bytes} bytes` : r.representation === "structured" ? "Labelled format" : "Not hex or Base64"],
    ["Format labels", r.representation === "structured" ? r.algorithm : "None (no bcrypt, PEM or $6$ prefix)"],
    ["Randomness", r.category === "encoding" ? "Readable text inside" : notRandom ? "✗ Not random" : r.bytes ? "Looks random" : "-"],
    ["Size & structure", r.category === "UNKNOWN" ? "UNKNOWN" : `${CATEGORY[r.category]} (${Math.round(r.categoryConfidence * 100)}%)`],
    ["Algorithm", r.algorithm !== "UNKNOWN" ? r.algorithm : r.shortlist.length > 1 ? `One of ${r.shortlist.length}: needs the key` : "UNKNOWN"],
  ];
}

/** A key can only help with symmetric ciphertext (or a size shared with it). */
const keyHelps = (r: Classification) => r.category === "symmetric" || r.shortlist.some((a) => /AES|SEED|DES|ChaCha/.test(a));

export default function DetectView() {
  const reduce = useReducedMotion();
  const [text, setText] = useState("");
  const [phase, setPhase] = useState<Phase>("input");
  const [pct, setPct] = useState(0);
  const [rule, setRule] = useState<Classification | null>(null);

  const [key, setKey] = useState("");
  const [tries, setTries] = useState<Attempt[] | null>(null);
  const [keyError, setKeyError] = useState("");
  const [trying, setTrying] = useState(false);

  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [res, setRes] = useState<DetectResult | null>(null);
  const [needPath, setNeedPath] = useState(false);
  const [claudePath, setClaudePath] = useState("");

  // Instant decode with the Encoding tab's code: Base64, Base64URL, hex, URL encoding, HTML entities
  const quick = useMemo(() => {
    const id = guessEncoding(text);
    if (!id) return null;
    try { return { name: byId(id).name, ok: true, out: byId(id).decode(text.trim()) }; }
    catch { return null; }
  }, [text]);

  function reset(next = text) {
    setText(next); setPhase("input"); setPct(0); setRule(null);
    setTries(null); setKeyError(""); setRes(null); setError("");
  }

  function scan() {
    setRule(classify(text)); setTries(null); setKeyError(""); setRes(null); setError("");
    setPct(reduce ? 100 : 1); setPhase("scanning");
  }

  // The bar runs 1 -> 100% on a timer; the checks themselves are instant, the bar shows them one by one
  useEffect(() => {
    if (phase !== "scanning") return;
    let raf = 0, done = 0;
    const start = performance.now();
    const tick = (now: number) => {
      const t = reduce ? 1 : Math.min(1, (now - start) / SCAN_MS);
      setPct(Math.max(1, Math.round(100 * (1 - Math.pow(1 - t, 2))))); // ease-out
      if (t < 1) raf = requestAnimationFrame(tick);
      else done = window.setTimeout(() => setPhase(rule && keyHelps(rule) ? "key" : "done"), reduce ? 0 : 350);
    };
    raf = requestAnimationFrame(tick);
    return () => { cancelAnimationFrame(raf); clearTimeout(done); };
  }, [phase, reduce, rule]);

  async function continueWithKey() {
    setTrying(true); setKeyError("");
    const { tryWithKey } = await import("@/lib/trykey"); // loads the cipher code only when used
    const r = await tryWithKey(text, key);
    setTrying(false);
    if (typeof r === "string") { setKeyError(r); return; }
    setTries(r); setPhase("done");
  }

  async function askClaude() {
    setBusy(true); setError(""); setRes(null);
    try {
      let saved = "";
      try { saved = localStorage.getItem(PATH_KEY) ?? ""; } catch {}
      const p = (claudePath.trim() || saved).replace(/^"|"$/g, ""); // "Copy as path" in Explorer adds quotes
      if (!claudePath && saved) setClaudePath(saved);
      const r = await fetch("/api/detect", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ text, claudePath: p || undefined }) });
      const j = await r.json();
      setNeedPath(!!j.needPath);
      if (!r.ok) { setError(j.error ?? "Something went wrong."); return; }
      setRes(j);
      try { if (p) localStorage.setItem(PATH_KEY, p); } catch {}
    } catch {
      setError("Could not reach the server.");
    } finally {
      setBusy(false);
    }
  }

  const stages = rule ? stagesOf(rule) : [];
  const keyStep = rule ? keyHelps(rule) : false;
  const n = { scan: 2, key: 3, result: keyStep ? 4 : 3 };

  return (
    <main style={{ "--accent": "var(--asymmetric)" } as React.CSSProperties}>
      <header>
        <p className="text-xs font-semibold uppercase tracking-[0.14em] text-muted">data-encrypt-method · detect</p>
        <h1 className="mt-3 text-4xl font-semibold tracking-tight sm:text-5xl">Detect</h1>
        <p className="mt-4 max-w-2xl text-lg text-muted">
          Paste a hash or encrypted text and scan it. You get the type and the likely algorithm, and with the key, the exact method and the original text.
        </p>
      </header>

      {/* min-w-0: lets sections shrink on phones; otherwise the one-line scan preview of a long text stretches them */}
      <div className="mt-8 grid gap-5 [&>*]:min-w-0">
        <Section n={1} title="Paste encrypted or hashed text">
          <TextArea mono value={text} onChange={(e) => reset(e.target.value)} maxLength={MAX_INPUT}
            placeholder="e.g. 900150983cd24fb0d6963f7d28e17f72" aria-label="Text to scan" />
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[13px] text-muted">Try an example:</span>
            {EXAMPLES.map(([name, value]) => (
              <button key={name} type="button" onClick={() => reset(value)}
                className="rounded-full border border-line bg-paper px-3 py-1 text-sm hover:border-muted">{name}</button>
            ))}
          </div>
          <div className="flex items-center gap-3">
            <Button onClick={scan} disabled={!text.trim() || phase === "scanning"}>{phase === "input" ? "Scan" : "Scan again"}</Button>
            <Note>{text.length} / {MAX_INPUT} characters. No AI, runs in your browser.</Note>
          </div>
        </Section>

        {rule && phase !== "input" && (
          <Section n={n.scan} title={pct < 100 ? "Scanning…" : "Scan complete"}>
            <div>
              <div className="flex items-baseline justify-between">
                <span className="text-sm text-muted">{pct < 100 ? stages[Math.min(4, Math.floor(pct / 20))][0] + "…" : "All 5 checks done"}</span>
                <span className="font-mono text-2xl font-semibold tabular-nums">{pct}%</span>
              </div>
              <div className="mt-2 h-2.5 overflow-hidden rounded-full bg-paper" role="progressbar" aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100} aria-label="Scan progress">
                <div className="h-full rounded-full bg-[var(--accent)] transition-[width] duration-100" style={{ width: `${pct}%` }} />
              </div>
            </div>
            <div className="relative overflow-hidden rounded-xl border border-line bg-code px-3 py-2.5">
              <p className="truncate font-mono text-sm">{text.trim()}</p>
              {pct < 100 && !reduce && (
                <motion.div aria-hidden className="pointer-events-none absolute inset-y-0 w-24 bg-gradient-to-r from-transparent via-[var(--accent)]/25 to-transparent"
                  initial={{ left: "-6rem" }} animate={{ left: "100%" }} transition={{ duration: 0.9, repeat: Infinity, ease: "linear" }} />
              )}
            </div>
            <ol className="grid gap-1.5">
              {stages.map(([name, finding], i) => {
                const done = pct >= (i + 1) * 20, active = !done && pct >= i * 20;
                return (
                  <li key={name} className="flex items-center gap-3 text-sm">
                    <span className={`grid size-5 shrink-0 place-items-center rounded-full text-[11px] ${done ? "bg-ok text-paper" : active ? "border-2 border-[var(--accent)]" : "border border-line"}`}>
                      {done ? "✓" : ""}
                    </span>
                    <span className={done || active ? "font-medium" : "text-muted"}>{name}</span>
                    <AnimatePresence>
                      {done && (
                        <motion.span initial={{ opacity: 0, x: -6 }} animate={{ opacity: 1, x: 0 }} className="ml-auto text-right text-muted">{finding}</motion.span>
                      )}
                    </AnimatePresence>
                  </li>
                );
              })}
            </ol>
          </Section>
        )}

        {rule && keyStep && (phase === "key" || phase === "done") && (
          <Section n={n.key} title="Have the key?">
            {phase === "key" ? (
              <>
                <Note>
                  Optional. With the key, every method that fits its size is tried, and the one that decrypts names the exact algorithm.
                  It runs in your browser: the key is never sent anywhere. No key? Skip to the result.
                </Note>
                <div>
                  <Label htmlFor="try-key">Key (hex)</Label>
                  <Input id="try-key" value={key} onChange={(e) => { setKey(e.target.value); setKeyError(""); }} spellCheck={false}
                    className="font-mono" placeholder="e.g. d6060d636b84194d06f6afa212d6213e" />
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <Button onClick={continueWithKey} disabled={trying || !key.trim()}>{trying ? "Trying…" : "Continue"}</Button>
                  <button type="button" onClick={() => setPhase("done")}
                    className="rounded-[10px] border border-line bg-paper px-4 py-2 text-sm font-medium hover:border-muted">Skip</button>
                </div>
                {keyError && <p className="font-medium text-bad">✗ {keyError}</p>}
              </>
            ) : (
              <div className="flex flex-wrap items-center gap-3">
                <p className="text-sm">{tries ? <>Tried {tries.length} method{tries.length > 1 ? "s" : ""} with the key.</> : "Skipped: no key."}</p>
                <button type="button" onClick={() => { setPhase("key"); setRes(null); }} className="text-sm font-medium text-[var(--accent)] hover:underline">
                  {tries ? "Try another key" : "Enter a key"}
                </button>
              </div>
            )}
          </Section>
        )}

        {rule && phase === "done" && <ResultList n={n.result} rule={rule} tries={tries} decoded={quick?.ok ? quick : null} />}

        {rule && phase === "done" && (
          <div className="flex flex-wrap items-center gap-3">
            <Button onClick={askClaude} disabled={busy}>{busy ? "Asking Claude…" : res ? "Ask Claude again" : "Ask Claude to explain"}</Button>
            <Note>Optional: Claude explains the result in plain words. Takes a few seconds, and the text is sent to Claude.</Note>
          </div>
        )}
        {error && <p className="font-medium text-bad">✗ {error}</p>}
        {needPath && (
          <div className="grid gap-2">
            <Label htmlFor="claude-path">Path to claude.exe</Label>
            <Input id="claude-path" value={claudePath} onChange={(e) => setClaudePath(e.target.value)} spellCheck={false} className="font-mono"
              placeholder="C:\Users\you\.vscode\extensions\anthropic.claude-code-…\resources\native-binary\claude.exe" />
            <div className="flex flex-wrap items-center gap-3">
              <Button onClick={askClaude} disabled={busy || !claudePath.trim()}>{busy ? "Asking Claude…" : "Save and ask"}</Button>
              <Note>Saved in this browser only. Run <code>where claude</code> in a terminal to find it.</Note>
            </div>
          </div>
        )}

        {res && (
          <Section n={n.result + 1} title="Claude explains">
            <p className="text-[17px]">{res.summary}</p>
            <div className="grid gap-3">
              {res.candidates.map((c, i) => <CandidateCard key={i} c={c} i={i} />)}
            </div>
            {res.nextStep && (
              <p className="rounded-xl border border-line bg-code px-4 py-3 text-sm"><span className="font-semibold">Next step: </span>{res.nextStep}</p>
            )}
          </Section>
        )}

        <p className="rounded-xl border border-warn/40 bg-warn/10 px-4 py-3 text-sm text-muted">
          Detection is an educated guess from the format. Good ciphers look random, so AES and SEED (or DES and 3DES) can&apos;t be told apart without the key.
          The scan and the key check run in your browser. Only &quot;Ask Claude&quot; sends the text to Claude, through your local Claude Code (claude.exe).
        </p>
      </div>
    </main>
  );
}

/** Final result as a list: one row per finding, key result first when a key decrypted it. */
function ResultList({ n, rule, tries, decoded }: { n: number; rule: Classification; tries: Attempt[] | null; decoded: { name: string; out: string } | null }) {
  const found = tries?.find((t): t is Attempt & { verdict: "certain" | "likely" } => t.verdict !== "no");
  const tone = found ? found.verdict : rule.category === "UNKNOWN" ? "possible" : rule.categoryConfidence >= 0.85 ? "certain" : "likely";

  const rows: [label: string, value: React.ReactNode][] = [
    ["Category", <span key="c" className="flex flex-wrap items-center gap-2">
      <span className="font-semibold">{found ? CATEGORY.symmetric : rule.category === "UNKNOWN" ? "UNKNOWN" : CATEGORY[rule.category]}</span>
      <span className={`rounded-full border px-2 py-0.5 text-xs ${CONF[tone]}`}>{found ? `key: ${found.verdict}` : `${Math.round(rule.categoryConfidence * 100)}%`}</span>
    </span>],
    ["Algorithm", found
      ? <span key="a"><span className="font-semibold">{found.name}</span> <span className="text-muted">(the key decrypted it)</span>{" "}
          <Link href={`/${found.methodId}`} className="text-sm font-medium text-symmetric hover:underline">Study it →</Link></span>
      : rule.algorithm !== "UNKNOWN"
        ? <span key="a"><span className="font-semibold">{rule.algorithm}</span> <span className="text-muted">({Math.round(rule.algorithmConfidence * 100)}%)</span></span>
        : <span key="a"><span className="font-semibold">UNKNOWN</span>{rule.shortlist.length > 1 && <span className="text-muted"> · one of: <span className="font-medium text-ink">{rule.shortlist.join(", ")}</span></span>}</span>],
  ];
  if (found) rows.push(["Original text", <span key="t" className="flex flex-wrap items-center gap-2"><span className="font-mono">{found.text}</span><CopyButton text={found.text} /></span>]);
  if (tries && !found) rows.push(["Key", <span key="k" className="text-bad">✗ No method decrypted it: wrong key, or a format this project doesn&apos;t use.</span>]);
  if (tries) rows.push(["Methods tried", <span key="m" className="text-muted">{tries.map((t) => `${t.name} ${t.verdict === "no" ? "✗" : "✓"}`).join(" · ")}</span>]);
  if (decoded) rows.push([`Decoded (${decoded.name})`, <span key="d" className="flex flex-wrap items-center gap-2"><span className="font-mono [overflow-wrap:anywhere]">{decoded.out}</span><CopyButton text={decoded.out} /></span>]);
  rows.push([found ? "Scan (before the key)" : "Why", <ul key="w" className="list-disc space-y-0.5 pl-5 text-muted">{rule.evidence.map((e) => <li key={e}>{e}</li>)}</ul>]);
  if (!found && rule.candidates.length) rows.push(["Could also be", <span key="o" className="text-muted">{rule.candidates.join("; ")}</span>]);

  return (
    <Section n={n} title="Result">
      <ul className={`divide-y divide-line overflow-hidden rounded-xl border ${CARD[tone]}`}>
        {rows.map(([label, value], i) => (
          <motion.li key={label} initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.06 }}
            className="grid gap-1 px-4 py-3 text-sm sm:grid-cols-[150px_1fr] sm:gap-4">
            <span className="text-xs font-semibold uppercase tracking-wider text-muted sm:pt-0.5">{label}</span>
            <div className="min-w-0 [overflow-wrap:anywhere]">{value}</div>
          </motion.li>
        ))}
      </ul>
      {found?.verdict === "likely" && <Note>Likely, not certain: this method has no seal to prove the key, but readable text almost never comes from a wrong key.</Note>}
    </Section>
  );
}

function CandidateCard({ c, i }: { c: Candidate; i: number }) {
  const accent = c.family === "hash" ? ACCENT.hashing : c.family === "symmetric" ? ACCENT.symmetric : c.family === "asymmetric" ? ACCENT.asymmetric : null;
  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.08 }}
      className={`rounded-xl border p-4 ${CARD[c.confidence]}`}>
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-lg font-semibold">{c.type}</span>
        <span className={`rounded-full border px-2 py-0.5 text-xs ${CONF[c.confidence]}`}>{c.confidence}</span>
        <span className={`text-xs uppercase tracking-wider ${accent ? accent.text : "text-muted"}`}>{c.family}</span>
        {c.studyId && (
          <Link href={`/${c.studyId}`} className={`ml-auto text-sm font-medium ${accent ? accent.text : ""} hover:underline`}>Study it →</Link>
        )}
        {!c.studyId && c.family === "encoding" && (
          <Link href="/encoding" className="ml-auto text-sm font-medium text-info hover:underline">Open Encoding →</Link>
        )}
      </div>
      <p className="mt-1.5 text-sm text-muted">{c.reason}</p>
    </motion.div>
  );
}
