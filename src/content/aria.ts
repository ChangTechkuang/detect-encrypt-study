import type { StudyCase } from "./types";

// Written for a complete beginner, in the same style as seed.ts. Every value is real: src/lib/aria.ts,
// and each round value matches RFC 5794 appendix A.1 exactly.
export const aria: StudyCase = {
  id: "aria",
  name: "ARIA",
  fullName: "Academy, Research Institute, Agency · Korea's second lock for data (NSRI, 2004)",
  category: "symmetric",
  tagline: "Korea's national lock, built like AES. One secret key locks it, the same key unlocks it.",
  status: { label: "Korean standard", tone: "good" },
  facts: [
    { label: "Key size", value: "16, 24 or 32 bytes" },
    { label: "Same key to lock & unlock?", value: "Yes" },
    { label: "Safe today?", value: "Yes" },
    { label: "Made", value: "2004, Korea" },
  ],
  java: "java/aria/Aria.java",

  analogy:
    "Like a combination lock with many dials. Each turn swaps every number for another and then mixes them all together. After 12 turns nobody can guess the start, unless they have the key.",
  terms: [
    { term: "Key", meaning: "The secret that locks and unlocks. Same key for both." },
    { term: "Round", meaning: "One turn of the lock: mix in a key, swap every byte, spread every byte. ARIA does 12, 14 or 16." },
    { term: "S-box", meaning: "A fixed swap table: each byte value (0–255) is swapped for another. ARIA uses 4 of them." },
  ],

  what: {
    summary: "ARIA locks data so only someone with the secret key can read it. Its name comes from the three groups that built it: Academy, Research Institute and Agency.",
    points: [
      "One key locks, the same key unlocks.",
      "Locks 16 bytes at a time, like AES, with a 16, 24 or 32-byte key.",
      "A Korean national standard (KS X 1213), next to SEED.",
    ],
  },

  how: {
    summary: "Think of a lock with dials: every turn swaps and mixes all 16 bytes. Follow the official RFC 5794 example (a 16-byte key, so 12 rounds) one step at a time. Every value below is real.",
    steps: [
      {
        title: "The text is one block of 16 bytes",
        detail: "ARIA locks exactly 16 bytes at a time (one block), the same as AES and SEED. The text is written in hex: 2 characters = 1 byte. A longer message is cut into 16-byte blocks.",
        show: `text = 00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff
       └──────────────── 16 bytes ────────────────┘
key  = 000102030405060708090a0b0c0d0e0f   (16 bytes → 12 rounds)`,
      },
      {
        title: "Grow 13 round keys from the one key",
        detail: "Each round needs its own key, plus one extra at the end. ARIA first runs the key through 3 mini-rounds, using 3 fixed numbers taken from 1/π (so nobody could hide a trick in them). That gives 4 values, W0 to W3. Each round key is two of them mixed with a rotation.",
        show: `1/π constants:  517cc1b7…  6db14acc…  db92371d…

W0 = 000102030405060708090a0b0c0d0e0f   (the key itself)
W1 = 2afbea741e1746dd55c63ba1afcea0a5
   …
round key  1 = d415a75c794b85c5e0d2a0b3cb793bf6   = W0 XOR (W1 turned 19 bits)
round key  2 = 369c65e4b11777ab713a3e1e6601b8f4
   …
round key 13 = 0f0aa16daee61bd7dfee5a599970fb35`,
      },
      {
        title: "Round 1, part 1: mix in the round key",
        detail: "XOR the text with round key 1: wherever the key has a 1 bit, the text bit flips. Without the key, nobody knows which bits flipped.",
        show: `text          00112233445566778899aabbccddeeff
round key 1   d415a75c794b85c5e0d2a0b3cb793bf6
              ────────────────────────────────  XOR
result        d404856f3d1ee3b2684b0a0807a4d509`,
      },
      {
        title: "Round 1, part 2: swap every byte (S-boxes)",
        detail: "Each byte is swapped using a fixed table called an S-box. ARIA has 4 different S-boxes and uses them in turn: byte 1 → S-box 1, byte 2 → S-box 2, and so on. S-box 1 is the same one AES uses. This swap is what makes the lock impossible to undo with simple math.",
        show: `before  d4 04 85 6f 3d 1e e3 b2 68 4b 0a 08 07 a4 d5 09
         S1 S2 S3 S4 S1 S2 S3 S4 S1 S2 S3 S4 S1 S2 S3 S4
after   48 94 67 d9 27 59 4d d5 45 95 a3 50 c5 a9 b5 39

e.g. S-box 1 swaps d4 → 48`,
      },
      {
        title: "Round 1, part 3: spread every byte",
        detail: "Now each new byte is made by XORing 7 of the 16 bytes together (the \"diffusion layer\"). So one changed byte touches 7 others, and after 2 rounds it has touched them all. Doing this twice gives the bytes back, so unlocking can use the same step.",
        show: `new byte 1 = byte 4 XOR byte 5 XOR byte 7 XOR byte 9 XOR byte 10 XOR byte 14 XOR byte 15
   … the same for all 16 bytes, each with its own 7

after round 1 = 7fc7f12befd0a0791de87fa96b469f52`,
      },
      {
        title: "Repeat: 12 rounds in total",
        detail: "Rounds 2 to 11 do the same three parts, each with the next round key. Odd and even rounds use the S-boxes in a different order. Round 12 swaps the bytes once more and adds the extra 13th key instead of spreading. The result is the locked block.",
        show: `after round  1:  7fc7f12befd0a0791de87fa96b469f52
after round  2:  ac8de17e49f7c5117618993162b189e9
   …
after round 11:  e7e0d2457ed73d23d481424095afdca0
round 12 (swap + key 12, then key 13):

locked = d718fbd6ab644c739da95f3be6451778   ✓ same as the RFC`,
      },
      {
        title: "Unlock: same rounds, keys reversed",
        detail: "To unlock, ARIA runs the same 12 rounds again. It uses the round keys from last to first, each passed once through the spreading step. The S-box swaps and the spreading undo themselves in that order.",
        show: `locked  d718fbd6ab644c739da95f3be6451778
   │  same 12 rounds, round keys 13 → 1
   ▼
text    00112233445566778899aabbccddeeff   ✓ back again`,
      },
    ],
  },

  where: {
    summary: "In Korea: public-sector systems, banks and payment services.",
    uses: [
      { place: "✓ Korean public sector", detail: "Systems must use validated Korean ciphers (KCMVP), and ARIA and SEED are on that list." },
      { place: "✓ Banking & payments", detail: "Korean financial apps and payment modules use ARIA or SEED to protect card and account data." },
      { place: "✓ HTTPS (TLS)", detail: "TLS has ARIA cipher suites (RFC 6209), used by some Korean sites." },
      { place: "✗ Outside Korea", detail: "Few libraries support it. AES-GCM is the world default." },
    ],
    example: {
      title: "\"Hello, ARIA!\" locked with ARIA-128 (CBC)",
      rows: [
        { label: "Key", value: "4706480851e61be85d74bfb3fd956185", mono: true },
        { label: "IV", value: "000102030405060708090a0b0c0d0e0f", mono: true },
        { label: "Text + padding", value: "48656c6c6f2c20415249412104040404", mono: true },
        { label: "Locked", value: "376d59ce3ff89ad4e4dcc2224b50cf5c", mono: true, tone: "ok" },
        { label: "Sent (Base64)", value: "AAECAwQFBgcICQoLDA0ODzdtWc4/+JrU5NzCIktQz1w=", mono: true },
      ],
      note: "\"Hello, ARIA!\" is 12 bytes, so 4 bytes of 04 fill the block. Checked against OpenSSL's ARIA. The example IV is fixed so you can repeat it; real messages use a random one.",
    },
  },

  verify: {
    summary: "ARIA in CBC mode has no seal. You know the key was right because the unlocked data makes sense.",
    steps: [
      "Unlock with the key.",
      "Check the padding at the end, and if the result looks right.",
      "Looks right → ✓ unlocked.",
      "Bad padding or garbage → ✗ wrong key, or the data was changed.",
    ],
    example: {
      title: "Changing one character",
      rows: [
        { label: "\"Hello, ARIA!\"", value: "376d59ce3ff89ad4e4dcc2224b50cf5c", mono: true, tone: "ok" },
        { label: "\"Hello, ARIA?\"", value: "a726c2a6712b51200f46a2754b7e4e90", mono: true, tone: "bad" },
      ],
      note: "One character changed, and the whole locked block changed. Same key and IV for both.",
    },
  },

  summary: {
    points: [
      "ARIA = Korea's national lock. One key locks and unlocks.",
      "16-byte blocks like AES; 12, 14 or 16 rounds of key, swap and spread.",
      "Safe today. Used in Korean public, banking and payment systems.",
    ],
    algorithm: `locked = ARIA.lock(key, text)        // 12 / 14 / 16 rounds

// to unlock later:
result = ARIA.unlock(key, locked)     // same rounds, keys reversed
if result looks right:
    ✓ unlocked
else:
    ✗ wrong key or changed data`,
  },
};
