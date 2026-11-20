import type { StudyCase } from "./types";

// Written for a complete beginner: one idea per sentence, examples before explanations.
export const sha256: StudyCase = {
  id: "sha256",
  name: "SHA-256",
  fullName: "Secure Hash Algorithm, 256-bit · the secure fingerprint of any data (2001)",
  category: "hashing",
  tagline: "Turns any data into a 64-character fingerprint. Safe: today's standard.",
  status: { label: "Recommended", tone: "good" },
  facts: [
    { label: "Fingerprint size", value: "Always 64 characters" },
    { label: "Turn it back?", value: "No, impossible" },
    { label: "Safe for security?", value: "Yes" },
    { label: "Made", value: "2001" },
  ],
  java: "java/sha256/Sha256.java",

  analogy:
    "Like a fingerprint, but one nobody can fake. The same data always gives the same fingerprint, and you can't rebuild the data from it.",
  terms: [
    { term: "Hash / fingerprint", meaning: "The 64-character result SHA-256 makes. Same data → same fingerprint." },
    { term: "One-way", meaning: "You can make a fingerprint, but never turn it back into the data." },
    { term: "Collision", meaning: "Two different inputs with the same fingerprint. Nobody has ever found one for SHA-256." },
  ],

  what: {
    summary: "SHA-256 turns any data into a fingerprint of 64 characters.",
    points: [
      "Same input → always the same fingerprint.",
      "Change one letter → a completely different fingerprint.",
      "No way back, and nobody can fake a match.",
    ],
  },

  how: {
    summary: "Like MD5's blender, but bigger and stronger. Follow the word \"Hello\" through SHA-256, one step at a time. Every value below is real.",
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
        detail: "SHA-256 always blends exactly 64 bytes at a time. \"Hello\" is only 5 bytes, so SHA-256 fills the rest of the box in 3 parts: a marker that says where the data ends, empty zeros, and the length of the data. Unlike MD5, SHA-256 writes the length with its biggest part first, so the 28 lands in the very last byte.",
        show: `48 65 6c 6c 6f 80 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 28

① 48 65 6c 6c 6f  = "Hello" (5 bytes)
② 80              = marker: in bits 10000000, one "1" that says
                    "the real data ends here"
③ 00 00 … 00      = empty space
④ 00 … 00 28      = length of "Hello" in bits (last 8 bytes):
                    hex 28 = 2×16 + 8 = 40 bits = 5 bytes = 5 letters`,
      },
      {
        title: "Start with 8 fixed numbers",
        detail: "SHA-256 works on 8 numbers at once, called H0 to H7. They always start at the same values, written in the SHA-256 standard (FIPS 180-4). Each one comes from a square root: take the square roots of the first 8 prime numbers (2, 3, 5, 7, 11, 13, 17, 19) and keep the part after the dot. Anyone can recompute them, so nobody could hide a trick in them.",
        show: `H0 = 6a09e667   (from √2)     H4 = 510e527f   (from √11)
H1 = bb67ae85   (from √3)     H5 = 9b05688c   (from √13)
H2 = 3c6ef372   (from √5)     H6 = 1f83d9ab   (from √17)
H3 = a54ff53a   (from √7)     H7 = 5be0cd19   (from √19)

√2 = 1.41421356…  →  keep 0.41421356…  →  as hex: 6a09e667`,
      },
      {
        title: "Blend 64 times",
        detail: "SHA-256 cuts the 64-byte box into 16 small parts (words) of 4 bytes. Then it stretches those 16 words into 64 words, by mixing earlier words together. Then it does 64 mixing steps: each step takes one word, mixes it into the 8 numbers, adds a fixed number, and turns (rotates) the bits. After 64 steps, every letter of \"Hello\" has changed every one of the 8 numbers.",
        show: `the box as 16 words of 4 bytes:
48656c6c 6f800000 00000000 00000000 00000000 00000000 00000000 00000000
00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000028

stretched to 64 words. The next 4 are made from the ones above:
word 17–20:  5594884c 6f910000 d53ac55a a01bde7a  …up to word 64

step 1 uses word 1, step 2 uses word 2, … step 64 uses word 64`,
      },
      {
        title: "Read the fingerprint",
        detail: "After the 64 steps, SHA-256 adds the mixed numbers to their start values H0 to H7. Those 8 numbers together ARE the fingerprint: 8 × 8 = 64 hex characters = 256 bits. That's where the name SHA-256 comes from.",
        show: `start:  6a09e667 bb67ae85 3c6ef372 a54ff53a 510e527f 9b05688c 1f83d9ab 5be0cd19
end:    185f8db3 2271fe25 f561a6fc 938b2e26 4306ec30 4eda5180 07d17648 26381969
           H0       H1       H2       H3       H4       H5       H6       H7

SHA-256("Hello") = 185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969`,
      },
      {
        title: "Change one letter",
        detail: "Change just the last letter (o → p) and blend again. The whole fingerprint changes, not just one part.",
        show: `"Hello"  →  185f8db3 2271fe25 f561a6fc 938b2e26 4306ec30 4eda5180 07d17648 26381969
"Hellp"  →  2113cd4a 7aebc3a4 00a234c3 de8a5c0c 4d9fa8c6 ca370d03 0aac9ab5 1e8c4476`,
      },
      {
        title: "Why you can't go back",
        detail: "To get \"Hello\" back you would have to un-blend 64 mixes. Like a smoothie, the fruit is gone. That's why SHA-256 is one-way. And unlike MD5, nobody has ever found two inputs with the same SHA-256 fingerprint.",
        show: `185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969  →  ???   (impossible)`,
      },
    ],
  },

  where: {
    summary: "Everywhere data must be checked and nobody may cheat.",
    uses: [
      { place: "✓ Downloads & Git", detail: "Compare the fingerprint to know a file wasn't changed." },
      { place: "✓ Bitcoin & website certificates", detail: "They rely on SHA-256 to make fakes impossible." },
      { place: "✗ Passwords alone", detail: "Too fast: a thief can try billions of guesses. Use bcrypt." },
    ],
    example: {
      title: "Words in, fingerprints out",
      rows: [
        { label: "\"abc\"", value: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", mono: true },
        { label: "\"Hello\"", value: "185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969", mono: true },
        { label: "\"hello\"", value: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", mono: true },
      ],
      note: "\"Hello\" and \"hello\" differ only by a capital H, but the fingerprints are completely different.",
    },
  },

  verify: {
    summary: "You can't turn a fingerprint back. To check, make the fingerprint again and compare.",
    steps: [
      "You have some data and its saved fingerprint.",
      "Make the SHA-256 of the data again.",
      "Same fingerprint → ✓ the data is unchanged.",
      "Different fingerprint → ✗ the data was changed.",
    ],
    example: {
      title: "Check \"abc\" against its saved fingerprint",
      rows: [
        { label: "Saved fingerprint", value: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", mono: true },
        { label: "Text \"abc\"", value: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad → same", mono: true, tone: "ok" },
        { label: "Text \"abd\"", value: "a52d159f262b2c6ddb724a61840befc36eb30c88877a4030b65cbe86298449c9 → different", mono: true, tone: "bad" },
      ],
      note: "One letter changed (c → d), and the check fails.",
    },
  },

  summary: {
    points: [
      "SHA-256 = a 64-character fingerprint of any data.",
      "Same input → same fingerprint. You can't turn it back.",
      "Safe for checks. For passwords, use bcrypt.",
    ],
    algorithm: `fingerprint = SHA256("abc")   // ba7816bf...f20015ad

// to check later:
if SHA256(data) == savedFingerprint:
    ✓ data is unchanged
else:
    ✗ data was changed`,
  },
};
