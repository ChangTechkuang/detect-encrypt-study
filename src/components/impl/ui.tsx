"use client";

// UI kit for the Implement panels, in the Study look (paper, ink, category accent via the --accent CSS variable).
import { useEffect, useRef, useState } from "react";

/** Numbered card, like the Study steps. */
export function Section({ n, title, children }: { n: number; title: React.ReactNode; children: React.ReactNode }) {
  return (
    <section className="rounded-2xl border border-line bg-card p-5 sm:p-6">
      <h2 className="mb-4 flex items-center gap-3 text-xl font-semibold tracking-tight">
        <span className="grid size-8 shrink-0 place-items-center rounded-full bg-[var(--accent)] text-[15px] text-paper">{n}</span>
        {title}
      </h2>
      <div className="space-y-3">{children}</div>
    </section>
  );
}

/** Intro text at the top of a panel. */
export const About = ({ children }: { children: React.ReactNode }) => <p className="max-w-3xl text-[17px]">{children}</p>;
/** Small muted text. */
export const Note = ({ children }: { children: React.ReactNode }) => <p className="text-sm text-muted">{children}</p>;
/** Amber warning box at the bottom of a panel. */
export const Warning = ({ children }: { children: React.ReactNode }) =>
  <p className="rounded-xl border border-warn/40 bg-warn/10 px-4 py-3 text-sm text-muted">{children}</p>;

export const Label = ({ htmlFor, children }: { htmlFor: string; children: React.ReactNode }) =>
  <label htmlFor={htmlFor} className="mb-1.5 block text-[13px] text-muted">{children}</label>;

const field = "w-full rounded-[10px] border border-line bg-paper px-3 py-2.5 text-[15px] text-ink outline-none focus:outline-2 focus:outline-offset-1 focus:outline-[var(--accent)]";

export function TextArea({ mono, className = "", ...p }: React.TextareaHTMLAttributes<HTMLTextAreaElement> & { mono?: boolean }) {
  return <textarea autoComplete="off" {...p} className={`${field} min-h-24 resize-y ${mono ? "font-mono text-xs min-h-36" : ""} ${className}`} />;
}
export function Input({ className = "", ...p }: React.InputHTMLAttributes<HTMLInputElement>) {
  return <input autoComplete="off" {...p} className={`${field} ${className}`} />;
}
export function Select({ className = "", ...p }: React.SelectHTMLAttributes<HTMLSelectElement>) {
  return <select {...p} className={`${field} ${className}`} />;
}

export function Button({ className = "", ...p }: React.ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button type="button" {...p}
      className={`shrink-0 rounded-[10px] bg-[var(--accent)] px-4 py-2 text-sm font-medium text-paper hover:opacity-90 disabled:cursor-default disabled:opacity-60 ${className}`} />
  );
}

/** Copies text; falls back silently if the clipboard is blocked. */
export function CopyButton({ text }: { text: string }) {
  const [done, setDone] = useState(false);
  return (
    <Button disabled={!text} onClick={async () => {
      try { await navigator.clipboard.writeText(text); setDone(true); setTimeout(() => setDone(false), 1200); } catch { /* blocked */ }
    }}>{done ? "Copied ✓" : "Copy"}</Button>
  );
}

/** A read-only value box with buttons beside it (Copy, "Verify this", ...). */
export function OutputRow({ id, value, plain, children }: { id?: string; value: string; plain?: boolean; children?: React.ReactNode }) {
  return (
    <div className="flex flex-wrap items-center gap-2">
      <output id={id} aria-live="polite"
        className={`min-h-11 min-w-0 flex-[1_1_260px] rounded-[10px] border border-line bg-code px-3 py-2.5 font-mono text-sm ${plain ? "whitespace-pre-wrap [overflow-wrap:anywhere]" : "break-all"}`}>
        {value}
      </output>
      {children}
    </div>
  );
}

export const Meta = ({ children, bad }: { children: React.ReactNode; bad?: boolean }) =>
  <p className={`text-[13px] ${bad ? "text-bad" : "text-muted"}`}>{children}</p>;

export type ResultState = { ok: boolean; text: string } | null;
/** ✓ / ✗ result line. */
export const Result = ({ r }: { r: ResultState }) =>
  <p aria-live="polite" className={`min-h-6 font-medium ${r ? (r.ok ? "text-ok" : "text-bad") : ""}`}>{r?.text}</p>;

/** Key/value or check tables, styled like the Study example cards. */
export function Table({ head, rows }: { head?: string[]; rows: React.ReactNode[][] }) {
  return (
    <div className="overflow-x-auto rounded-xl border border-line">
      <table className="w-full border-collapse text-[13px]">
        {head && (
          <thead className="bg-code">
            <tr>{head.map((h) => <th key={h} className="px-3.5 py-2.5 text-left text-[11px] font-medium uppercase tracking-wider text-muted">{h}</th>)}</tr>
          </thead>
        )}
        <tbody>
          {rows.map((r, i) => (
            <tr key={i} className="border-t border-line first:border-t-0">
              {r.map((c, j) => <td key={j} className="px-3.5 py-2.5 align-top [overflow-wrap:anywhere]">{c}</td>)}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export const Pass = ({ ok }: { ok: boolean | null }) =>
  ok === null ? <span className="text-muted">…</span> : <span className={ok ? "text-ok" : "text-bad"}>{ok ? "✓ pass" : "✗ fail"}</span>;

export type Check = [name: string, run: () => Promise<boolean> | boolean];

/**
 * Runs self-checks one after another when the panel mounts (again when `key` changes).
 * A check that throws counts as a fail. Returns rows for <Table> and a summary line.
 */
export function useSelfChecks(make: () => Check[], key: string) {
  const [results, setResults] = useState<{ name: string; ok: boolean | null }[]>([]);
  const makeRef = useRef(make);
  useEffect(() => { makeRef.current = make; }); // runs before the effect below, so it always sees the latest checks
  useEffect(() => {
    let alive = true;
    const checks = makeRef.current();
    setResults(checks.map(([name]) => ({ name, ok: null })));
    (async () => {
      for (let i = 0; i < checks.length; i++) {
        let ok = false;
        try { ok = !!(await checks[i][1]()); } catch { /* fail */ }
        if (!alive) return;
        setResults((r) => r.map((x, j) => (j === i ? { ...x, ok } : x)));
      }
    })();
    return () => { alive = false; };
  }, [key]);
  const done = results.length > 0 && results.every((r) => r.ok !== null);
  const passed = results.filter((r) => r.ok).length;
  return {
    results,
    summary: done ? `${passed} / ${results.length} passed — run live in your browser.` : "Running…",
    allPassed: done && passed === results.length,
  };
}

/** Self-check table: name + pass/fail. */
export function ChecksTable({ results, head = ["Check", "Result"] }: { results: { name: React.ReactNode; ok: boolean | null }[]; head?: string[] }) {
  return <Table head={head} rows={results.map((r) => [r.name, <Pass key="p" ok={r.ok} />])} />;
}
