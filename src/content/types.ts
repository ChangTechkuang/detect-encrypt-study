// One study case = one method, always the same 5 steps. Keep every string short and easy to catch.

export type Category = "hashing" | "symmetric" | "asymmetric";

/** A worked example: label/value rows, shown as a small card. Use real values (the project's test vectors). */
export type Example = {
  title: string;
  rows: { label: string; value: string; mono?: boolean; tone?: "ok" | "bad" }[];
  note?: string;
};

export type StudyCase = {
  id: string; // URL slug, e.g. "seed"
  name: string; // short name, e.g. "SEED"
  fullName: string; // e.g. "SEED block cipher (KISA, RFC 4269)"
  category: Category;
  tagline: string; // one line, shown on cards
  status: { label: string; tone: "good" | "warn" | "bad" }; // e.g. Recommended / Legacy / Broken
  facts: { label: string; value: string }[]; // 3-5 key numbers: block, key, output size, year...
  java: string; // the project's Java file, e.g. "java/seed/Seed.java" (inside this Next.js project)

  /** Everyday comparison shown in step 1, e.g. "Like a house key: the same key locks and unlocks the door." */
  analogy: string;
  /** "Words to know": the few technical words the page cannot avoid, each explained in plain words. */
  terms: { term: string; meaning: string }[];

  /** 1. What is it? */
  what: { summary: string; points: string[] };
  /**
   * 2. How does it work? Shown one step at a time (Back / Next).
   * `show` = what the data actually looks like at this step, with real values (monospace box).
   */
  how: { summary: string; steps: { title: string; detail: string; show?: string }[] };
  /** 3. Where is it used? */
  where: { summary: string; uses: { place: string; detail: string }[]; example: Example };
  /** 4. How does verification work? */
  verify: { summary: string; steps: string[]; example: Example };
  /** 5. Summary with the algorithm (short pseudo-code). */
  summary: { points: string[]; algorithm: string };
};
