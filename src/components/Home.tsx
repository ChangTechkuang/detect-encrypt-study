"use client";

import Link from "next/link";
import { motion } from "motion/react";
import { CASES, CATEGORIES } from "@/content";
import { ACCENT, TONE } from "./accent";

const STEPS = ["What is it?", "How does it work?", "Where is it used?", "How is it verified?", "Summary + algorithm"];

export default function Home() {
  return (
    <main>
      <motion.header initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5 }}>
        <p className="text-xs font-semibold uppercase tracking-[0.14em] text-muted">data-encrypt-method · study case</p>
        <h1 className="mt-3 text-4xl font-semibold tracking-tight sm:text-5xl">Study Cases</h1>
        <p className="mt-4 max-w-2xl text-lg text-muted">
          Every hashing, symmetric and asymmetric method in this project, explained in the same five short steps.
        </p>
        <ol className="mt-6 flex flex-wrap gap-2">
          {STEPS.map((s, i) => (
            <li key={s} className="rounded-full border border-line bg-card px-3 py-1 text-sm">
              <span className="mr-1.5 font-mono text-muted">{i + 1}</span>{s}
            </li>
          ))}
        </ol>
      </motion.header>

      <div className="mt-14 space-y-12">
        {CATEGORIES.map((cat) => {
          const a = ACCENT[cat.id];
          const cases = CASES.filter((c) => c.category === cat.id);
          return (
            <section key={cat.id}>
              <div className="flex items-baseline gap-3 border-b border-line pb-3">
                <span className={`size-2.5 rounded-full ${a.bg}`} />
                <h2 className="text-xl font-semibold">{cat.name}</h2>
                <p className="text-sm text-muted">{cat.desc}</p>
              </div>
              <div className="mt-5 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
                {cases.map((c, i) => (
                  <motion.div key={c.id} initial={{ opacity: 0, y: 14 }} whileInView={{ opacity: 1, y: 0 }}
                    viewport={{ once: true }} transition={{ delay: i * 0.06 }} whileHover={{ y: -3 }}>
                    <Link href={`/${c.id}`}
                      className={`group block h-full rounded-2xl border border-line bg-card p-5 transition-colors ${a.hover}`}>
                      <div className="flex items-start justify-between gap-3">
                        <h3 className="text-lg font-semibold">{c.name}</h3>
                        <span className={`shrink-0 rounded-full border px-2 py-0.5 text-xs ${TONE[c.status.tone]}`}>{c.status.label}</span>
                      </div>
                      <p className="mt-2 text-sm text-muted">{c.tagline}</p>
                      <p className={`mt-4 text-sm font-medium ${a.text}`}>Study it →</p>
                    </Link>
                  </motion.div>
                ))}
                {!cases.length && <p className="text-sm text-muted">Coming soon.</p>}
              </div>
            </section>
          );
        })}
      </div>
    </main>
  );
}
