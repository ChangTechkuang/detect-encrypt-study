"use client";

import Link from "next/link";
import dynamic from "next/dynamic";
import { motion } from "motion/react";
import { CASES, CATEGORIES, caseById } from "@/content";
import { ACCENT } from "../accent";

// Each panel (and the crypto library it needs) is its own chunk, so a page only downloads its own method:
// /playground/md5 no longer pulls in node-forge, crypto-js or bcryptjs.
const loading = () => <p className="text-sm text-muted">Loading…</p>;
const HashPanel = dynamic(() => import("./HashPanel"), { loading });
const BcryptPanel = dynamic(() => import("./BcryptPanel"), { loading });
const SymPanel = dynamic(() => import("./SymPanel"), { loading });
const RsaPanel = dynamic(() => import("./RsaPanel"), { loading });
const GongdongPanel = dynamic(() => import("./GongdongPanel"), { loading });

/** Which live panel each study case uses. */
function Panel({ id }: { id: string }) {
  switch (id) {
    case "md5":
    case "sha1":
    case "sha256":
    case "sha512": return <HashPanel method={id} />;
    case "bcrypt": return <BcryptPanel />;
    case "des":
    case "tripledes":
    case "aes":
    case "seed":
    case "aria":
    case "chacha20": return <SymPanel method={id} />;
    case "rsa": return <RsaPanel />;
    case "gongdong": return <GongdongPanel />;
    default: return null;
  }
}

export default function ImplementView({ id }: { id: string }) {
  const c = caseById(id)!;
  const a = ACCENT[c.category];
  const tabs = CASES.filter((x) => x.category === c.category);

  return (
    // --accent drives buttons, step numbers and focus rings inside the panels
    <main style={{ "--accent": `var(--${c.category})` } as React.CSSProperties}>
      <header>
        <p className="text-xs font-semibold uppercase tracking-[0.14em] text-muted">data-encrypt-method · playground</p>
        <h1 className="mt-3 text-4xl font-semibold tracking-tight sm:text-5xl">Playground</h1>
        <p className="mt-4 max-w-2xl text-lg text-muted">
          Pick a category, then a method. Every method runs its official test vectors live in your browser.
        </p>
      </header>

      <nav aria-label="Category" className="mt-8 flex flex-wrap gap-2">
        {CATEGORIES.map((cat) => {
          const on = cat.id === c.category;
          const first = CASES.find((x) => x.category === cat.id)!;
          return (
            <Link key={cat.id} href={`/playground/${first.id}`} aria-current={on ? "page" : undefined}
              className={`flex items-center gap-2 rounded-full border px-4 py-1.5 text-sm font-medium ${on ? "border-ink bg-ink text-paper" : "border-line bg-card hover:border-muted"}`}>
              <span className={`size-2 rounded-full ${ACCENT[cat.id].bg}`} />{cat.name}
            </Link>
          );
        })}
      </nav>
      <p className="mt-3 text-sm text-muted">{CATEGORIES.find((x) => x.id === c.category)!.desc}</p>

      <div className="mt-4 flex flex-wrap items-center gap-x-4 gap-y-2 border-b border-line pb-3.5">
        <nav aria-label="Method" className="flex flex-wrap gap-2">
          {tabs.map((t) => {
            const on = t.id === id;
            return (
              <Link key={t.id} href={`/playground/${t.id}`} aria-current={on ? "page" : undefined}
                className={`rounded-[10px] border px-3.5 py-1.5 text-[15px] font-semibold ${on ? `${a.border} ${a.soft} ${a.text}` : "border-transparent text-muted hover:text-ink"}`}>
                {t.name}
              </Link>
            );
          })}
        </nav>
        <Link href={`/${id}`} className={`ml-auto text-sm font-medium ${a.text} hover:underline`}>Study {c.name} →</Link>
      </div>

      <motion.div key={id} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }}
        className="mt-6 grid gap-5">
        <Panel id={id} />
      </motion.div>
    </main>
  );
}
