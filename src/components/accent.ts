import type { Category } from "@/content/types";

// Full class names so Tailwind can see them.
export const ACCENT: Record<Category, { text: string; bg: string; border: string; soft: string; hover: string }> = {
  hashing: { text: "text-hashing", bg: "bg-hashing", border: "border-hashing", soft: "bg-hashing/10", hover: "hover:border-hashing" },
  symmetric: { text: "text-symmetric", bg: "bg-symmetric", border: "border-symmetric", soft: "bg-symmetric/10", hover: "hover:border-symmetric" },
  asymmetric: { text: "text-asymmetric", bg: "bg-asymmetric", border: "border-asymmetric", soft: "bg-asymmetric/10", hover: "hover:border-asymmetric" },
};

export const TONE = {
  good: "text-ok border-ok/40 bg-ok/10",
  warn: "text-warn border-warn/40 bg-warn/10",
  bad: "text-bad border-bad/40 bg-bad/10",
} as const;
