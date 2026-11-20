import type { StudyCase } from "./types";

// Written for a complete beginner: one idea per sentence, examples before explanations.
export const md5: StudyCase = {
  id: "md5",
  name: "MD5",
  fullName: "Message-Digest Algorithm 5 · makes a fingerprint of any data (1991)",
  category: "hashing",
  tagline: "Turns any data into a 32-character fingerprint. Old and broken: never use it for security.",
  status: { label: "Broken", tone: "bad" },
  facts: [
    { label: "Hash size", value: "128 bits (32 hex characters)" },
    { label: "Turn it back?", value: "No, impossible" },
    { label: "Safe for security?", value: "No (broken)" },
    { label: "Made", value: "1991" },
  ],
  java: "java/md5/Md5.java",

  analogy:
    "Like a fingerprint. Every person has one, and it's always the same for the same person. But from a fingerprint alone you can't rebuild the person.",
  terms: [
    { term: "Hash / fingerprint", meaning: "The 32-character result MD5 makes. Same data → same fingerprint." },
    { term: "One-way", meaning: "You can make a fingerprint, but never turn it back into the data." },
    { term: "Broken", meaning: "People found a way to make two different files with the same fingerprint." },
    { term: "Bit & byte", meaning: "A bit is a single 0 or 1. 8 bits = 1 byte = enough for one letter." },
    { term: "Hex", meaning: "A way to write numbers with 16 symbols: 0–9 then a–f. 2 hex characters = 1 byte. Hex 28 = 2×16 + 8 = 40." },
  ],

  what: {
    summary: "MD5 (Message-Digest Algorithm 5) converts input data into a fixed-length hash value of 128 bits (32 hex characters).",
    points: [
      "Same input → always the same fingerprint.",
      "Change one letter → a completely different fingerprint.",
      "No way back: from the fingerprint you can't get the input.",
    ],
  },

  how: {
    summary: "Think of a blender. Follow the word \"Hello\" through MD5, one step at a time. Every value below is real.",
    steps: [
      {
        title: "Turn letters into numbers",
        detail: "A computer only stores numbers. Each letter becomes one number from 0 to 255 (one byte). We write it in hex, 2 characters per byte. For example H is 72 in normal counting, which is 48 in hex.",
        show: `"Hello"  →  48 65 6c 6c 6f
             H  e  l  l  o

H = 72 = hex 48   (4×16 + 8 = 72)
5 letters = 5 bytes = 40 bits   (1 byte = 8 bits)`,
      },
      {
        title: "Fill the box to 64 bytes",
        detail: "MD5 always blends exactly 64 bytes. \"Hello\" is only 5 bytes, so MD5 fills the rest of the box in 3 parts: a marker that says where the data ends, empty zeros, and the length of the data at the very end.",
        show: `48 65 6c 6c 6f 80 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 28 00 00 00 00 00 00 00

① 48 65 6c 6c 6f  = "Hello" (5 bytes)
② 80              = marker: in bits 10000000, one "1" that says
                    "the real data ends here"
③ 00 00 … 00      = empty space
④ 28              = length of "Hello" in bits:
                    hex 28 = 2×16 + 8 = 40 bits = 5 bytes = 5 letters`,
      },
      {
        title: "Start with 4 fixed numbers",
        detail: "MD5 works on 4 numbers at once, called A, B, C and D. Think of them as the 4 blades of the blender. They always start at the same values, written in the MD5 standard (RFC 1321). The values are just simple counting, so nobody could hide a trick in them. Same start for everyone → same fingerprint for everyone.",
        show: `A = 01234567    B = 89abcdef    C = fedcba98    D = 76543210

A, B count up:    0 1 2 3 4 5 6 7 8 9 a b c d e f
C, D count down:  f e d c b a 9 8 7 6 5 4 3 2 1 0`,
      },
      {
        title: "Blend 64 times",
        detail: "MD5 cuts the 64-byte box into 16 small parts of 4 bytes. Then it does 64 mixing steps (4 rounds × 16 steps). Each step takes one small part, mixes it into A, B, C and D, adds a fixed number, and turns (rotates) the bits. After 64 steps, every letter of \"Hello\" has changed every part of A, B, C and D.",
        show: `the box as 16 parts of 4 bytes:
48656c6c 6f800000 00000000 00000000 00000000 00000000 00000000 00000000
00000000 00000000 00000000 00000000 00000000 00000000 28000000 00000000

round 1: steps  1–16      round 2: steps 17–32
round 3: steps 33–48      round 4: steps 49–64`,
      },
      {
        title: "Read the fingerprint",
        detail: "After the 64 steps, MD5 adds the mixed A, B, C, D to their start values. Those 4 numbers together ARE the fingerprint: 4 × 8 = 32 hex characters = 128 bits.",
        show: `start:  01234567  89abcdef  fedcba98  76543210
end:    8b1a9953  c4611296  a827abf8  c47804d7
           A          B          C          D

MD5("Hello") = 8b1a9953c4611296a827abf8c47804d7`,
      },
      {
        title: "Change one letter",
        detail: "Change just the last letter (o → p) and blend again. The whole fingerprint changes, not just one part.",
        show: `"Hello"  →  8b1a9953 c4611296 a827abf8 c47804d7
"Hellp"  →  62ac2dcd ae264b4a ac4e9b26 31692514`,
      },
      {
        title: "Why you can't go back",
        detail: "To get \"Hello\" back you would have to un-blend 64 mixes. Like a smoothie, the fruit is gone. That's why MD5 is one-way.",
        show: `8b1a9953c4611296a827abf8c47804d7  →  ???   (impossible)`,
      },
    ],
  },

  where: {
    summary: "Only for quick checks where nobody is trying to cheat.",
    uses: [
      { place: "✓ Checking downloads", detail: "A site shows a file's MD5. After downloading, you compare: same → the file isn't damaged." },
      { place: "✓ Finding duplicates", detail: "Two files with the same MD5 are (almost always) the same file." },
      { place: "✗ Passwords & security", detail: "Never. Use SHA-256, and bcrypt for passwords." },
    ],
    example: {
      title: "Words in, fingerprints out",
      rows: [
        { label: "\"abc\"", value: "900150983cd24fb0d6963f7d28e17f72", mono: true },
        { label: "\"Hello\"", value: "8b1a9953c4611296a827abf8c47804d7", mono: true },
        { label: "\"hello\"", value: "5d41402abc4b2a76b9719d911017c592", mono: true },
      ],
      note: "\"Hello\" and \"hello\" differ only by a capital H, but the fingerprints are completely different.",
    },
  },

  verify: {
    summary: "You can't turn a fingerprint back. To check, make the fingerprint again and compare.",
    steps: [
      "You have some text and its saved fingerprint.",
      "Make the MD5 of the text again.",
      "Same fingerprint → ✓ the text is unchanged.",
      "Different fingerprint → ✗ the text was changed.",
    ],
    example: {
      title: "Check \"abc\" against its saved fingerprint",
      rows: [
        { label: "Saved fingerprint", value: "900150983cd24fb0d6963f7d28e17f72", mono: true },
        { label: "Text \"abc\"", value: "900150983cd24fb0d6963f7d28e17f72 → same", mono: true, tone: "ok" },
        { label: "Text \"abd\"", value: "4911e516e5aa21d327512e0c8b197616 → different", mono: true, tone: "bad" },
      ],
      note: "One letter changed (c → d), and the check fails.",
    },
  },

  summary: {
    points: [
      "MD5 = a 32-character fingerprint of any data.",
      "Same input → same fingerprint. You can't turn it back.",
      "Broken for security: use SHA-256 (or bcrypt for passwords).",
    ],
    algorithm: `fingerprint = MD5("abc")      // 900150983cd24fb0d6963f7d28e17f72

// to check later:
if MD5(text) == savedFingerprint:
    ✓ text is unchanged
else:
    ✗ text was changed`,
  },
};
