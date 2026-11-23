import type { StudyCase } from "./types";

// Written for a complete beginner: one idea per sentence, examples before explanations. Every value is real (Node crypto).
export const sha1: StudyCase = {
  id: "sha1",
  name: "SHA-1",
  fullName: "Secure Hash Algorithm 1 · MD5's successor, now broken too (NSA, 1995)",
  category: "hashing",
  tagline: "Turns any data into a 40-character fingerprint. Broken since 2017: don't use it for security.",
  status: { label: "Broken", tone: "bad" },
  facts: [
    { label: "Fingerprint size", value: "Always 40 characters" },
    { label: "Turn it back?", value: "No, impossible" },
    { label: "Safe for security?", value: "No, fakes were made in 2017" },
    { label: "Made", value: "1995" },
  ],
  java: "java/sha1/Sha1.java",

  analogy:
    "Like a fingerprint that was trusted for 20 years, until someone learned to make two people with the same fingerprint.",
  terms: [
    { term: "Hash / fingerprint", meaning: "The 40-character result SHA-1 makes. Same data → same fingerprint." },
    { term: "One-way", meaning: "You can make a fingerprint, but never turn it back into the data." },
    { term: "Collision", meaning: "Two different inputs with the same fingerprint. For SHA-1, one was made on purpose in 2017." },
  ],

  what: {
    summary: "SHA-1 turns any data into a fingerprint of 40 characters (160 bits).",
    points: [
      "Same input → always the same fingerprint.",
      "Change one letter → a completely different fingerprint.",
      "Broken: two different files with the same SHA-1 were made in 2017.",
    ],
  },

  how: {
    summary: "The same kind of blender as MD5 and SHA-256: fill a box, start from fixed numbers, mix many times. Follow the word \"Hello\" through SHA-1. Every value below is real.",
    steps: [
      {
        title: "Turn letters into numbers",
        detail: "A computer only stores numbers. Each letter becomes one number from 0 to 255 (one byte), written in hex, 2 characters per byte.",
        show: `"Hello"  →  48 65 6c 6c 6f
             H  e  l  l  o

5 letters = 5 bytes = 40 bits   (1 byte = 8 bits)`,
      },
      {
        title: "Fill the box to 64 bytes",
        detail: "SHA-1 blends exactly 64 bytes at a time, like SHA-256. The rest of the box is filled the same way: a marker where the data ends, zeros, and the length at the very end.",
        show: `48 65 6c 6c 6f 80 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 28

① 48 65 6c 6c 6f  = "Hello" (5 bytes)
② 80              = marker: "the real data ends here"
③ 00 00 … 00      = empty space
④ 00 … 00 28      = length in bits (last 8 bytes): hex 28 = 40 bits`,
      },
      {
        title: "Start with 5 fixed numbers",
        detail: "SHA-1 works on 5 numbers, H0 to H4 (SHA-256 uses 8). They always start at the same values, written in the standard. The first four are the same as MD5's, a simple counting pattern; the fifth is a new one in the same style.",
        show: `H0 = 67452301   ← 01 23 45 67 read backwards
H1 = efcdab89   ← 89 ab cd ef read backwards
H2 = 98badcfe   ← fe dc ba 98 read backwards
H3 = 10325476   ← 76 54 32 10 read backwards
H4 = c3d2e1f0   ← f0 e1 d2 c3 read backwards`,
      },
      {
        title: "Blend 80 times",
        detail: "SHA-1 cuts the box into 16 words of 4 bytes, then stretches them to 80 words: each new word mixes 4 earlier words with XOR and turns (rotates) the bits by 1. Then it does 80 mixing steps, one word per step, each one changing the 5 numbers.",
        show: `the box as 16 words of 4 bytes:
48656c6c 6f800000 00000000 00000000 00000000 00000000 00000000 00000000
00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000028

stretched to 80 words. The next 4 are made from the ones above:
word 17–20:  90cad8d8 df000000 00000050 2195b1b1  …up to word 80`,
      },
      {
        title: "Read the fingerprint",
        detail: "After the 80 steps, SHA-1 adds the mixed numbers to their start values. Those 5 numbers together ARE the fingerprint: 5 × 8 = 40 hex characters = 160 bits.",
        show: `start:  67452301 efcdab89 98badcfe 10325476 c3d2e1f0
end:    f7ff9e8b 7bb2e09b 70935a5d 785e0cc5 d9d0abf0
           H0       H1       H2       H3       H4

SHA-1("Hello") = f7ff9e8b7bb2e09b70935a5d785e0cc5d9d0abf0`,
      },
      {
        title: "Change one letter",
        detail: "Change just the last letter (o → p) and blend again. The whole fingerprint changes.",
        show: `"Hello"  →  f7ff9e8b 7bb2e09b 70935a5d 785e0cc5 d9d0abf0
"Hellp"  →  c178d79c dd4365be 456348ae 3f187cbc 4daa4278`,
      },
      {
        title: "Why it's broken",
        detail: "You still can't turn a SHA-1 fingerprint back into the data. But in 2017 Google and CWI made two different PDF files with the SAME SHA-1 fingerprint (the \"SHAttered\" attack). So a cheater can swap a good file for a bad one with a matching fingerprint. 160 bits is also too short by today's standards.",
        show: `good.pdf  →  38762cf7f55934b34d179ae6a4c80cadccbb7f0a
bad.pdf   →  38762cf7f55934b34d179ae6a4c80cadccbb7f0a   ← same! (SHAttered, 2017)`,
      },
    ],
  },

  where: {
    summary: "Still found in old systems. Not for anything new that needs security.",
    uses: [
      { place: "~ Git", detail: "Names every file and commit with SHA-1, with extra checks against SHAttered. Moving to SHA-256." },
      { place: "~ Old checksums", detail: "Old downloads list a SHA-1 to spot broken files. Fine for accidents, not for cheaters." },
      { place: "✗ Certificates & signatures", detail: "Browsers stopped trusting SHA-1 certificates in 2017. Use SHA-256." },
    ],
    example: {
      title: "Words in, fingerprints out",
      rows: [
        { label: "\"abc\"", value: "a9993e364706816aba3e25717850c26c9cd0d89d", mono: true },
        { label: "\"Hello\"", value: "f7ff9e8b7bb2e09b70935a5d785e0cc5d9d0abf0", mono: true },
        { label: "\"hello\"", value: "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d", mono: true },
      ],
      note: "\"Hello\" and \"hello\" differ only by a capital H, but the fingerprints are completely different.",
    },
  },

  verify: {
    summary: "You can't turn a fingerprint back. To check, make the fingerprint again and compare.",
    steps: [
      "You have some data and its saved fingerprint.",
      "Make the SHA-1 of the data again.",
      "Same fingerprint → ✓ the data is unchanged (by accident).",
      "Different fingerprint → ✗ the data was changed.",
    ],
    example: {
      title: "Check \"abc\" against its saved fingerprint",
      rows: [
        { label: "Saved fingerprint", value: "a9993e364706816aba3e25717850c26c9cd0d89d", mono: true },
        { label: "Text \"abc\"", value: "a9993e364706816aba3e25717850c26c9cd0d89d → same", mono: true, tone: "ok" },
        { label: "Text \"abd\"", value: "cb4cc28df0fdbe0ecf9d9662e294b118092a5735 → different", mono: true, tone: "bad" },
      ],
      note: "One letter changed (c → d), and the check fails. But a skilled cheater could make a different file that passes.",
    },
  },

  summary: {
    points: [
      "SHA-1 = a 40-character fingerprint of any data.",
      "Same input → same fingerprint. You can't turn it back.",
      "Broken since 2017: use SHA-256 for checks, bcrypt for passwords.",
    ],
    algorithm: `fingerprint = SHA1("abc")   // a9993e36...9cd0d89d

// to check later:
if SHA1(data) == savedFingerprint:
    ✓ data is unchanged (by accident, not by a cheater)
else:
    ✗ data was changed`,
  },
};
