"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const LAYOUTS = [
  { href: "/", name: "Study" },
  { href: "/ascii", name: "ASCII" },
  { href: "/encoding", name: "Encoding" },
  { href: "/playground", name: "Playground" },
  { href: "/detect", name: "Detect" },
];

/** Study | ASCII | Playground switch at the top of every page. */
export default function LayoutSwitch() {
  const path = usePathname();
  // Study owns "/" and every /<method> page; the others own their own prefix
  const active = LAYOUTS.slice(1).find((l) => path.startsWith(l.href))?.href ?? "/";
  return (
    <nav aria-label="Layout" className="mb-10 flex w-fit gap-1 rounded-full border border-line bg-card p-1 text-sm">
      {LAYOUTS.map((l) => {
        const on = l.href === active;
        return (
          <Link key={l.href} href={l.href} aria-current={on ? "page" : undefined}
            className={`rounded-full px-4 py-1.5 ${on ? "bg-ink font-medium text-paper" : "text-muted hover:text-ink"}`}>
            {l.name}
          </Link>
        );
      })}
    </nav>
  );
}
