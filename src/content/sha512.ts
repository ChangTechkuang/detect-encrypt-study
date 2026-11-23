import type { StudyCase } from "./types";

// Written for a complete beginner: one idea per sentence, examples before explanations. Every value is real (Node crypto).
export const sha512: StudyCase = {
  id: "sha512",
  name: "SHA-512",
  fullName: "Secure Hash Algorithm, 512-bit · SHA-256's bigger sibling (2001)",
  category: "hashing",
  tagline: "Turns any data into a 128-character fingerprint. Safe, and twice as long as SHA-256.",
  status: { label: "Recommended", tone: "good" },
  facts: [
    { label: "Fingerprint size", value: "Always 128 characters" },
    { label: "Turn it back?", value: "No, impossible" },
    { label: "Safe for security?", value: "Yes" },
    { label: "Made", value: "2001" },
  ],
  java: "java/sha512/Sha512.java",

  analogy:
    "Like SHA-256's fingerprint, but with twice as many lines. Same idea, a bigger and longer fingerprint.",
  terms: [
    { term: "Hash / fingerprint", meaning: "The 128-character result SHA-512 makes. Same data → same fingerprint." },
    { term: "One-way", meaning: "You can make a fingerprint, but never turn it back into the data." },
    { term: "SHA-2 family", meaning: "SHA-256 and SHA-512 are siblings: the same design, different sizes." },
  ],

  what: {
    summary: "SHA-512 turns any data into a fingerprint of 128 characters (512 bits).",
    points: [
      "Same input → always the same fingerprint.",
      "Change one letter → a completely different fingerprint.",
      "Same design as SHA-256, just bigger: twice the fingerprint length.",
    ],
  },

  how: {
    summary: "The same blender as SHA-256, with bigger parts: 8-byte numbers, a 128-byte box and 80 mixes. Follow the word \"Hello\" through SHA-512. Every value below is real.",
    steps: [
      {
        title: "Turn letters into numbers",
        detail: "A computer only stores numbers. Each letter becomes one number from 0 to 255 (one byte), written in hex, 2 characters per byte. Same as SHA-256.",
        show: `"Hello"  →  48 65 6c 6c 6f
             H  e  l  l  o

5 letters = 5 bytes = 40 bits   (1 byte = 8 bits)`,
      },
      {
        title: "Fill the box to 128 bytes",
        detail: "SHA-512 blends 128 bytes at a time, twice SHA-256's 64. \"Hello\" is only 5 bytes, so the rest is filled the same way: a marker where the data ends, zeros, and the length at the very end. The length gets 16 bytes here (SHA-256 used 8).",
        show: `48 65 6c 6c 6f 80 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
          … 4 more rows of 00 …
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 28

① 48 65 6c 6c 6f  = "Hello" (5 bytes)
② 80              = marker: "the real data ends here"
③ 00 00 … 00      = empty space
④ 00 … 00 28      = length in bits (last 16 bytes): hex 28 = 40 bits`,
      },
      {
        title: "Start with 8 fixed numbers",
        detail: "Like SHA-256, SHA-512 starts with 8 numbers, H0 to H7, from the square roots of the first 8 primes. But each number is twice as long: 16 hex characters (8 bytes = 64 bits) instead of 8. Look: the first half of each one is exactly SHA-256's start value.",
        show: `H0 = 6a09e667 f3bcc908   (from √2)     H4 = 510e527f ade682d1   (from √11)
H1 = bb67ae85 84caa73b   (from √3)     H5 = 9b05688c 2b3e6c1f   (from √13)
H2 = 3c6ef372 fe94f82b   (from √5)     H6 = 1f83d9ab fb41bd6b   (from √17)
H3 = a54ff53a 5f1d36f1   (from √7)     H7 = 5be0cd19 137e2179   (from √19)
     ^^^^^^^^ = SHA-256's start value`,
      },
      {
        title: "Blend 80 times",
        detail: "SHA-512 cuts the 128-byte box into 16 words of 8 bytes. It stretches them to 80 words, then does 80 mixing steps (SHA-256 does 64). Each step mixes one word into the 8 numbers, adds a fixed number, and turns (rotates) the bits. After 80 steps, every letter of \"Hello\" has changed every one of the 8 numbers.",
        show: `the box as 16 words of 8 bytes:
48656c6c6f800000 0000000000000000 0000000000000000 0000000000000000
0000000000000000 0000000000000000 0000000000000000 0000000000000000
0000000000000000 0000000000000000 0000000000000000 0000000000000000
0000000000000000 0000000000000000 0000000000000000 0000000000000028

stretched to 80 words → step 1 uses word 1 … step 80 uses word 80`,
      },
      {
        title: "Read the fingerprint",
        detail: "After the 80 steps, SHA-512 adds the mixed numbers to their start values. Those 8 numbers together ARE the fingerprint: 8 × 16 = 128 hex characters = 512 bits.",
        show: `H0 3615f80c9d293ed7   H1 402687f94b22d58e   H2 529b8cc7916f8fac   H3 7fddf7fbd5af4cf7
H4 77d3d795a7a00a16   H5 bf7e7f3fb9561ee9   H6 baae480da9fe7a18   H7 769e71886b03f315

SHA-512("Hello") = 3615f80c9d293ed7402687f94b22d58e529b8cc7916f8fac7fddf7fbd5af4cf7
                   77d3d795a7a00a16bf7e7f3fb9561ee9baae480da9fe7a18769e71886b03f315`,
      },
      {
        title: "Change one letter",
        detail: "Change just the last letter (o → p) and blend again. The whole fingerprint changes.",
        show: `"Hello"  →  3615f80c9d293ed7 402687f94b22d58e 529b8cc7916f8fac 7fddf7fbd5af4cf7 …
"Hellp"  →  db78b5afdd9868cb edbb62b8a5aad72a 78f5bf6f67e6b0d5 a0ffb2bc18ba7382 …`,
      },
      {
        title: "Why you can't go back",
        detail: "To get \"Hello\" back you would have to un-blend 80 mixes. Like a smoothie, the fruit is gone. And with a 512-bit fingerprint, finding two inputs that match is even further out of reach than for SHA-256.",
        show: `3615f80c…6b03f315  →  ???   (impossible)`,
      },
    ],
  },

  where: {
    summary: "Where SHA-256 fits, SHA-512 fits too, when a longer fingerprint is wanted.",
    uses: [
      { place: "✓ File checks", detail: "Many Linux downloads list a SHA-512 checksum next to the file." },
      { place: "✓ Signatures & keys", detail: "Ed25519 signatures and HMAC-SHA512 use it inside." },
      { place: "✗ Passwords alone", detail: "Too fast: a thief can try billions of guesses. Use bcrypt." },
    ],
    example: {
      title: "Words in, fingerprints out",
      rows: [
        { label: "\"abc\"", value: "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f", mono: true },
        { label: "\"Hello\"", value: "3615f80c9d293ed7402687f94b22d58e529b8cc7916f8fac7fddf7fbd5af4cf777d3d795a7a00a16bf7e7f3fb9561ee9baae480da9fe7a18769e71886b03f315", mono: true },
        { label: "\"hello\"", value: "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043", mono: true },
      ],
      note: "\"Hello\" and \"hello\" differ only by a capital H, but the fingerprints are completely different.",
    },
  },

  verify: {
    summary: "You can't turn a fingerprint back. To check, make the fingerprint again and compare.",
    steps: [
      "You have some data and its saved fingerprint.",
      "Make the SHA-512 of the data again.",
      "Same fingerprint → ✓ the data is unchanged.",
      "Different fingerprint → ✗ the data was changed.",
    ],
    example: {
      title: "Check \"abc\" against its saved fingerprint",
      rows: [
        { label: "Saved fingerprint", value: "ddaf35a193617aba…a54ca49f", mono: true },
        { label: "Text \"abc\"", value: "ddaf35a193617aba…a54ca49f → same", mono: true, tone: "ok" },
        { label: "Text \"abd\"", value: "1a9840c27a5cf22d…5b6f64c4 → different", mono: true, tone: "bad" },
      ],
      note: "One letter changed (c → d), and the check fails. (Fingerprints shortened with … to fit.)",
    },
  },

  summary: {
    points: [
      "SHA-512 = a 128-character fingerprint of any data.",
      "Same design as SHA-256, but 64-bit numbers, 128-byte blocks and 80 rounds.",
      "Safe for checks. For passwords, use bcrypt.",
    ],
    algorithm: `fingerprint = SHA512("abc")   // ddaf35a1...a54ca49f

// to check later:
if SHA512(data) == savedFingerprint:
    ✓ data is unchanged
else:
    ✗ data was changed`,
  },
};
