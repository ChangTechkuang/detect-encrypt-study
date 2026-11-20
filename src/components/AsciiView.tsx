"use client";

import { useMemo, useState } from "react";
import { motion } from "motion/react";
import { GROUPS, ROWS, explain, type Group } from "@/lib/ascii";

const hex = (n: number) => n.toString(16).padStart(2, "0");
const bin = (n: number) => n.toString(2).padStart(8, "0");

export default function AsciiView() {
  const [text, setText] = useState("Hello");
  const [group, setGroup] = useState<Group | "all">("all");
  const [q, setQ] = useState("");

  const chars = useMemo(() => explain(text), [text]);
  const rows = useMemo(() => {
    const s = q.trim().toLowerCase();
    return ROWS.filter((r) => (group === "all" || r.group === group) &&
      (!s || r.char.toLowerCase() === s || String(r.dec) === s || r.hex === s.replace(/^0x/, "").padStart(2, "0") || r.name.toLowerCase().includes(s)));
  }, [group, q]);

  return (
    <main style={{ "--accent": "var(--symmetric)" } as React.CSSProperties}>
      <header>
        <p className="text-xs font-semibold uppercase tracking-[0.14em] text-muted">data-encrypt-method · ascii</p>
        <h1 className="mt-3 text-4xl font-semibold tracking-tight sm:text-5xl">ASCII Table</h1>
        <p className="mt-4 max-w-2xl text-lg text-muted">
          ASCII gives every letter, digit and symbol a number from 0 to 127. Computers store text as these numbers.
          That&apos;s why &quot;Hello&quot; becomes <code className="font-mono text-ink">48 65 6c 6c 6f</code> in MD5.
        </p>
      </header>

      {/* 1. Converter */}
      <section className="mt-10 rounded-2xl border border-line bg-card p-5 sm:p-6">
        <h2 className="flex items-center gap-3 text-xl font-semibold">
          <span className="grid size-8 place-items-center rounded-full bg-[var(--accent)] text-[15px] text-paper">1</span>
          Type text, see its numbers
        </h2>
        <label htmlFor="ascii-text" className="mt-4 mb-1.5 block text-[13px] text-muted">Text</label>
        <input id="ascii-text" value={text} onChange={(e) => setText(e.target.value)} autoComplete="off"
          className="w-full rounded-[10px] border border-line bg-paper px-3 py-2.5 font-mono text-[15px] outline-none focus:outline-2 focus:outline-[var(--accent)]" />
        <div className="mt-4 flex flex-wrap gap-2">
          {chars.map((c, i) => (
            <motion.div key={`${i}-${c.ch}`} initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.2 }}
              className={`min-w-24 rounded-xl border px-3 py-2 text-center ${c.ascii ? "border-line bg-paper" : "border-warn/50 bg-warn/10"}`}>
              <div className="text-2xl font-semibold">{c.ch === " " ? "␠" : c.ch}</div>
              {c.ascii ? (
                <dl className="mt-1 space-y-0.5 font-mono text-xs">
                  <div><dt className="inline text-muted">dec </dt><dd className="inline">{c.bytes[0]}</dd></div>
                  <div><dt className="inline text-muted">hex </dt><dd className="inline text-[var(--accent)]">{hex(c.bytes[0])}</dd></div>
                  <div><dt className="inline text-muted">bin </dt><dd className="inline">{bin(c.bytes[0])}</dd></div>
                </dl>
              ) : (
                <p className="mt-1 font-mono text-xs">
                  <span className="text-warn">not ASCII</span><br />UTF-8: {c.bytes.map(hex).join(" ")}
                </p>
              )}
            </motion.div>
          ))}
        </div>
        {chars.length > 0 && (
          <p className="mt-4 rounded-[10px] border border-line bg-code px-3 py-2.5 font-mono text-sm break-all">
            <span className="text-muted">hex: </span>{chars.flatMap((c) => c.bytes).map(hex).join(" ")}
          </p>
        )}
        <p className="mt-2 text-[13px] text-muted">
          Characters outside ASCII (like 한글) don&apos;t fit in 0–127, so they use 2–4 bytes in UTF-8, the encoding used almost everywhere today.
        </p>
      </section>

      {/* 2. Tips */}
      <section className="mt-5 grid gap-3 sm:grid-cols-3">
        {[
          ["Letters are 32 apart", "A = 65, a = 97. Capital + 32 = small letter. (In binary: just one bit flips.)"],
          ["Digits start at 48", "The character \"0\" is number 48, \"9\" is 57. The text \"7\" is not the number 7."],
          ["Hex is short", "Every ASCII number fits in 2 hex characters: 00 to 7f. Hex 41 = 65 = \"A\"."],
        ].map(([t, d]) => (
          <div key={t} className="rounded-xl border border-line bg-card p-4">
            <p className="font-semibold text-[var(--accent)]">{t}</p>
            <p className="mt-1 text-sm text-muted">{d}</p>
          </div>
        ))}
      </section>

      {/* 3. Table */}
      <section className="mt-5 rounded-2xl border border-line bg-card p-5 sm:p-6">
        <h2 className="flex items-center gap-3 text-xl font-semibold">
          <span className="grid size-8 place-items-center rounded-full bg-[var(--accent)] text-[15px] text-paper">2</span>
          The full table: 0 to 127
        </h2>
        <div className="mt-4 flex flex-wrap gap-2">
          {GROUPS.map((g) => (
            <button key={g.id} type="button" onClick={() => setGroup(g.id)} aria-pressed={group === g.id}
              className={`rounded-full border px-3.5 py-1.5 text-sm ${group === g.id ? "border-ink bg-ink text-paper" : "border-line bg-paper hover:border-muted"}`}>
              {g.name} <span className={group === g.id ? "opacity-70" : "text-muted"}>{g.range}</span>
            </button>
          ))}
        </div>
        <label htmlFor="ascii-q" className="mt-4 mb-1.5 block text-[13px] text-muted">Search: a character, a number (65), hex (41) or a word (tab)</label>
        <input id="ascii-q" value={q} onChange={(e) => setQ(e.target.value)} autoComplete="off" placeholder="e.g. A, 65, 41, new line"
          className="w-full rounded-[10px] border border-line bg-paper px-3 py-2.5 text-[15px] outline-none focus:outline-2 focus:outline-[var(--accent)]" />

        <div className="mt-4 max-h-[36rem] overflow-auto rounded-xl border border-line">
          <table className="w-full border-collapse text-sm">
            <thead className="sticky top-0 bg-code">
              <tr className="text-left text-[11px] uppercase tracking-wider text-muted">
                <th className="px-3 py-2.5 font-medium">Char</th>
                <th className="px-3 py-2.5 font-medium">Dec</th>
                <th className="px-3 py-2.5 font-medium">Hex</th>
                <th className="px-3 py-2.5 font-medium">Binary</th>
                <th className="px-3 py-2.5 font-medium">Meaning</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.dec} className="border-t border-line">
                  <td className={`px-3 py-2 font-mono ${r.group === "control" ? "text-xs text-muted" : "text-base font-semibold"}`}>{r.char}</td>
                  <td className="px-3 py-2 font-mono">{r.dec}</td>
                  <td className="px-3 py-2 font-mono text-[var(--accent)]">{r.hex}</td>
                  <td className="px-3 py-2 font-mono text-muted">{r.bin}</td>
                  <td className="px-3 py-2 text-muted">{r.name}</td>
                </tr>
              ))}
              {!rows.length && <tr><td colSpan={5} className="px-3 py-6 text-center text-muted">Nothing found.</td></tr>}
            </tbody>
          </table>
        </div>
        <p className="mt-2 text-[13px] text-muted">{rows.length} of 128 shown. Control codes (0–31, 127) are invisible: they tell machines what to do, like a new line or a tab.</p>
      </section>
    </main>
  );
}
