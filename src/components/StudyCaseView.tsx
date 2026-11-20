"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { AnimatePresence, motion, useReducedMotion } from "motion/react";
import type { Example, StudyCase } from "@/content/types";
import { ACCENT, TONE } from "./accent";

const STEPS = [
  { id: "what", label: "What is it?" },
  { id: "how", label: "How does it work?" },
  { id: "where", label: "Where is it used?" },
  { id: "verify", label: "How is it verified?" },
  { id: "summary", label: "Summary + algorithm" },
] as const;

const rise = {
  hidden: { opacity: 0, y: 16 },
  show: { opacity: 1, y: 0, transition: { duration: 0.45, ease: [0.22, 1, 0.36, 1] as const } },
};

export default function StudyCaseView({ c, prev, next }: { c: StudyCase; prev?: StudyCase; next?: StudyCase }) {
  const a = ACCENT[c.category];
  const [active, setActive] = useState<string>("what");

  // Highlight the step whose section is in the middle of the screen
  useEffect(() => {
    const io = new IntersectionObserver(
      (entries) => entries.forEach((e) => e.isIntersecting && setActive(e.target.id)),
      { rootMargin: "-45% 0px -50% 0px" },
    );
    STEPS.forEach((s) => { const el = document.getElementById(s.id); if (el) io.observe(el); });
    return () => io.disconnect();
  }, [c.id]);

  return (
    <article>
      <Link href="/" className="text-sm text-muted hover:text-ink">← All study cases</Link>

      <motion.header initial="hidden" animate="show" variants={rise} className="mt-6">
        <p className={`text-xs font-semibold uppercase tracking-[0.14em] ${a.text}`}>{c.category} · study case</p>
        <h1 className="mt-2 text-4xl font-semibold tracking-tight sm:text-5xl">{c.name}</h1>
        <p className="mt-2 text-muted">{c.fullName}</p>
        <p className="mt-4 max-w-2xl text-lg">{c.tagline}</p>
        <div className="mt-5 flex flex-wrap items-center gap-2">
          <span className={`rounded-full border px-3 py-1 text-xs font-medium ${TONE[c.status.tone]}`}>{c.status.label}</span>
          <Link href={`/playground/${c.id}`} className={`rounded-full px-3 py-1 text-xs font-medium text-paper ${a.bg} hover:opacity-90`}>
            Try it live →
          </Link>
        </div>
        <dl className="mt-6 grid grid-cols-2 gap-3 sm:grid-cols-4">
          {c.facts.map((f) => (
            <div key={f.label} className="rounded-xl border border-line bg-card p-3">
              <dt className="text-xs uppercase tracking-wider text-muted">{f.label}</dt>
              <dd className="mt-1 font-medium">{f.value}</dd>
            </div>
          ))}
        </dl>
      </motion.header>

      <div className="mt-12 grid gap-10 lg:grid-cols-[200px_1fr]">
        <nav aria-label="Steps" className="hidden lg:block">
          <ol className="sticky top-10 space-y-1">
            {STEPS.map((s, i) => (
              <li key={s.id}>
                <a href={`#${s.id}`}
                  className={`flex items-center gap-3 rounded-lg px-2 py-2 text-sm transition-colors ${active === s.id ? "bg-card font-medium text-ink" : "text-muted hover:text-ink"}`}>
                  <span className={`grid size-6 place-items-center rounded-full text-xs font-semibold ${active === s.id ? `${a.bg} text-paper` : "border border-line"}`}>{i + 1}</span>
                  {s.label}
                </a>
              </li>
            ))}
          </ol>
        </nav>

        <div className="min-w-0 space-y-14">
          <Step n={1} id="what" title={`What is ${c.name}?`} accent={a.bg}>
            <p className="text-lg">{c.what.summary}</p>
            <div className={`rounded-xl border-l-4 ${a.border} ${a.soft} px-4 py-3`}>
              <p className={`text-xs font-semibold uppercase tracking-wider ${a.text}`}>In everyday terms</p>
              <p className="mt-1">{c.analogy}</p>
            </div>
            <Bullets items={c.what.points} dot={a.bg} />
            <div className="rounded-xl border border-line bg-card">
              <p className="border-b border-line px-4 py-2 text-xs uppercase tracking-wider text-muted">Words to know</p>
              <dl className="grid gap-x-6 gap-y-3 p-4 sm:grid-cols-2">
                {c.terms.map((t) => (
                  <div key={t.term}>
                    <dt className={`font-semibold ${a.text}`}>{t.term}</dt>
                    <dd className="text-sm text-muted">{t.meaning}</dd>
                  </div>
                ))}
              </dl>
            </div>
          </Step>

          <Step n={2} id="how" title="How does it work?" accent={a.bg}>
            <p>{c.how.summary}</p>
            <Flow steps={c.how.steps} accent={a} />
          </Step>

          <Step n={3} id="where" title="Where is it used?" accent={a.bg}>
            <p>{c.where.summary}</p>
            <div className="grid gap-3 sm:grid-cols-3">
              {c.where.uses.map((u, i) => (
                <motion.div key={u.place} variants={rise} initial="hidden" whileInView="show" viewport={{ once: true }}
                  transition={{ delay: i * 0.08 }} className="rounded-xl border border-line bg-card p-4">
                  <p className={`font-semibold ${a.text}`}>{u.place}</p>
                  <p className="mt-1 text-sm text-muted">{u.detail}</p>
                </motion.div>
              ))}
            </div>
            <ExampleCard ex={c.where.example} />
          </Step>

          <Step n={4} id="verify" title="How does verification work?" accent={a.bg}>
            <p>{c.verify.summary}</p>
            <ol className="space-y-2">
              {c.verify.steps.map((s, i) => (
                <li key={i} className="flex gap-3">
                  <span className={`mt-0.5 shrink-0 text-sm font-semibold ${a.text}`}>{i + 1}.</span>
                  <span>{s}</span>
                </li>
              ))}
            </ol>
            <ExampleCard ex={c.verify.example} />
          </Step>

          <Step n={5} id="summary" title="Summary" accent={a.bg}>
            <Bullets items={c.summary.points} dot={a.bg} />
            <div className="overflow-hidden rounded-xl border border-line bg-code">
              <p className="border-b border-line px-4 py-2 text-xs uppercase tracking-wider text-muted">Algorithm</p>
              <pre className="overflow-x-auto p-4 font-mono text-sm leading-relaxed"><code>{c.summary.algorithm}</code></pre>
            </div>
          </Step>

          <nav className="flex justify-between gap-4 border-t border-line pt-6 text-sm" aria-label="More study cases">
            {prev ? <Link href={`/${prev.id}`} className="text-muted hover:text-ink">← {prev.name}</Link> : <span />}
            {next ? <Link href={`/${next.id}`} className="text-muted hover:text-ink">{next.name} →</Link> : <span />}
          </nav>
        </div>
      </div>
    </article>
  );
}

function Step({ n, id, title, accent, children }: { n: number; id: string; title: string; accent: string; children: React.ReactNode }) {
  return (
    <motion.section id={id} variants={rise} initial="hidden" whileInView="show" viewport={{ once: true, margin: "-80px" }}
      className="scroll-mt-10 space-y-5">
      <h2 className="flex items-center gap-3 text-2xl font-semibold tracking-tight">
        <span className={`grid size-9 shrink-0 place-items-center rounded-full ${accent} text-base text-paper`}>{n}</span>
        {title}
      </h2>
      {children}
    </motion.section>
  );
}

function Bullets({ items, dot }: { items: string[]; dot: string }) {
  return (
    <ul className="space-y-2">
      {items.map((t, i) => (
        <li key={i} className="flex gap-3">
          <span className={`mt-2.5 size-1.5 shrink-0 rounded-full ${dot}`} />
          <span>{t}</span>
        </li>
      ))}
    </ul>
  );
}

/**
 * The "how" steps as a step-by-step player: one step at a time, like slides.
 * Numbered dots jump to a step; Back / Next (or ← → keys) move through them; the box shows the real data.
 */
function Flow({ steps, accent }: { steps: StudyCase["how"]["steps"]; accent: (typeof ACCENT)[keyof typeof ACCENT] }) {
  const reduce = useReducedMotion();
  const [i, setI] = useState(0);
  const [dir, setDir] = useState(1);
  const go = (n: number) => { if (n < 0 || n >= steps.length) return; setDir(n > i ? 1 : -1); setI(n); };
  // Relative moves use the latest step, so fast repeated clicks never skip
  const step = (d: number) => { setDir(d); setI((cur) => Math.min(steps.length - 1, Math.max(0, cur + d))); };
  const s = steps[i];
  const last = i === steps.length - 1;

  return (
    <div className="overflow-hidden rounded-2xl border border-line bg-card"
      onKeyDown={(e) => { if (e.key === "ArrowRight") step(1); if (e.key === "ArrowLeft") step(-1); }}>
      {/* progress: one dot per step, the bar fills as you go */}
      <div className="flex items-center gap-2 border-b border-line px-4 py-3">
        {steps.map((st, n) => (
          <button key={st.title} onClick={() => go(n)} aria-label={`Step ${n + 1}: ${st.title}`} aria-current={n === i ? "step" : undefined}
            className={`grid size-7 shrink-0 place-items-center rounded-full text-xs font-semibold transition-colors ${n === i ? `${accent.bg} text-paper` : n < i ? `${accent.soft} ${accent.text}` : "border border-line text-muted hover:text-ink"}`}>
            {n + 1}
          </button>
        ))}
        <span className="ml-auto shrink-0 text-xs text-muted">Step {i + 1} of {steps.length}</span>
      </div>
      <div className="h-1 bg-line/60">
        <motion.div className={`h-full ${accent.bg}`} animate={{ width: `${((i + 1) / steps.length) * 100}%` }} transition={{ duration: reduce ? 0 : 0.35 }} />
      </div>

      <div className="min-h-64 p-5 sm:p-6" aria-live="polite">
        <AnimatePresence mode="wait" initial={false} custom={dir}>
          <motion.div key={i}
            initial={reduce ? false : { opacity: 0, x: 24 * dir }} animate={{ opacity: 1, x: 0 }} exit={reduce ? undefined : { opacity: 0, x: -24 * dir }}
            transition={{ duration: 0.25, ease: "easeOut" }}>
            <h3 className="text-lg font-semibold">
              <span className={`mr-2 font-mono ${accent.text}`}>{String(i + 1).padStart(2, "0")}</span>{s.title}
            </h3>
            <p className="mt-2 max-w-2xl">{s.detail}</p>
            {s.show && (
              <pre className="mt-4 overflow-x-auto rounded-xl border border-line bg-code p-4 font-mono text-[13px] leading-relaxed">{s.show}</pre>
            )}
          </motion.div>
        </AnimatePresence>
      </div>

      <div className="flex items-center justify-between gap-3 border-t border-line px-4 py-3">
        <button onClick={() => step(-1)} disabled={i === 0}
          className="rounded-lg px-3 py-1.5 text-sm text-muted hover:text-ink disabled:opacity-40">← Back</button>
        <button onClick={() => (last ? go(0) : step(1))}
          className={`rounded-lg px-4 py-1.5 text-sm font-medium text-paper ${accent.bg} hover:opacity-90`}>
          {last ? "Start again ↺" : "Next →"}
        </button>
      </div>
    </div>
  );
}

function ExampleCard({ ex }: { ex: Example }) {
  return (
    <div className="rounded-xl border border-line bg-card">
      <p className="border-b border-line px-4 py-2 text-xs uppercase tracking-wider text-muted">Example · {ex.title}</p>
      <dl className="divide-y divide-line">
        {ex.rows.map((r, i) => (
          <div key={i} className="grid gap-1 px-4 py-2.5 sm:grid-cols-[140px_1fr] sm:gap-4">
            <dt className="text-sm text-muted">{r.label}</dt>
            <dd className={`min-w-0 break-all text-sm ${r.mono ? "font-mono" : ""} ${r.tone === "ok" ? "text-ok" : r.tone === "bad" ? "text-bad" : ""}`}>
              {r.tone === "ok" ? "✓ " : r.tone === "bad" ? "✗ " : ""}{r.value}
            </dd>
          </div>
        ))}
      </dl>
      {ex.note && <p className="border-t border-line px-4 py-2 text-sm text-muted">{ex.note}</p>}
    </div>
  );
}
