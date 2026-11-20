import type { StudyCase } from "./types";

// Written for a complete beginner, in the same style as md5.ts (the reference page).
export const seed: StudyCase = {
  id: "seed",
  name: "SEED",
  fullName: "SEED is a name, not an abbreviation · Korea's own lock for data (KISA, 1998)",
  category: "symmetric",
  tagline: "Korea's own lock for data. One secret key locks it, the same key unlocks it.",
  status: { label: "Korean standard", tone: "warn" },
  facts: [
    { label: "Key size", value: "16 bytes" },
    { label: "Same key to lock & unlock?", value: "Yes" },
    { label: "Safe today?", value: "Yes, but use AES for new work" },
    { label: "Made", value: "1998, Korea" },
  ],
  java: "java/seed/Seed.java",

  analogy:
    "Korea's own lock. It works like a house key: the same key locks and unlocks the door.",
  terms: [
    { term: "Key", meaning: "The secret that locks and unlocks. Same key for both." },
    { term: "Encrypt / decrypt", meaning: "Lock the data / unlock it again." },
    { term: "공동인증서", meaning: "Korea's online ID certificate. Its secret file is locked with SEED." },
  ],

  what: {
    summary: "SEED locks data so only someone with the secret key can read it.",
    points: [
      "One key locks, the same key unlocks.",
      "Without the key → the data is just noise.",
      "Mostly used in Korea. The world default is AES.",
    ],
  },

  how: {
    summary: "Think of a house key: turn it one way to lock, the other way to unlock. Follow the official RFC 4269 example through SEED, one step at a time. Every value below is real.",
    steps: [
      {
        title: "Split the 16 bytes into two halves",
        detail: "SEED locks exactly 16 bytes at a time (one \"block\"). Our text is 16 bytes, written in hex (2 characters = 1 byte). SEED cuts it into a left half (L) and a right half (R), 8 bytes each.",
        show: `text = 83a2f8a288641fb9 a4e9a5cc2f131c7d

L (left half)  = 83a2f8a2 88641fb9   (8 bytes)
R (right half) = a4e9a5cc 2f131c7d   (8 bytes)`,
      },
      {
        title: "Turn the key into 16 round keys",
        detail: "SEED does 16 rounds, and each round needs its own key. A fixed recipe grows 16 round keys (8 bytes each) from the one 16-byte secret key. It slides the key bytes around and mixes in a fixed number from the golden ratio (9e3779b9), which nobody can hide a trick in.",
        show: `key           = 4706480851e61be85d74bfb3fd956185

round key  1  = 56be4a0f e9f62877
   …              (keys 2 to 15)
round key 16  = a9af7241 a3e67359`,
      },
      {
        title: "Round 1: scramble R, mix it into L",
        detail: "A function called F scrambles the right half using the round key (it mixes in the key and swaps bytes with fixed tables called S-boxes). The result is mixed into the left half with XOR: flip the bit wherever F has a 1. Then the halves change places. F itself is never undone, which is why this trick (a \"Feistel\" round) is so useful.",
        show: `rule:  new L = old R
       new R = old L XOR F(old R, round key)

F(R, round key 1) = ff4708b0 cf9cde5f

new L = a4e9a5cc 2f131c7d                       ① old R moves left
new R = 83a2f8a2 88641fb9 XOR ff4708b0 cf9cde5f ② old L mixed with F
      = 7ce5f012 47f8c1e6`,
      },
      {
        title: "Repeat for 16 rounds",
        detail: "SEED does the same move 16 times, each time with the next round key. Each round, the half that was just scrambled moves left and the other half gets scrambled. After 16 rounds, the two halves are joined (right half first) and that is the locked data.",
        show: `after round  1:  L = a4e9a5cc 2f131c7d   R = 7ce5f012 47f8c1e6
after round  2:  L = 7ce5f012 47f8c1e6   R = aac99520 609f4cb7
   …
after round 16:  L = 226bc314 2cd40d4a   R = ee54d13e bcae706d

locked = R + L = ee54d13ebcae706d226bc3142cd40d4a`,
      },
      {
        title: "Unlock: same rounds, keys reversed",
        detail: "To unlock, SEED runs the very same 16 rounds, but uses the round keys in reverse order (16 down to 1). XOR undoes itself, so each round takes back exactly what it added. No separate unlock recipe is needed.",
        show: `locked  ee54d13ebcae706d226bc3142cd40d4a
   │  same rounds, round keys 16 → 1
   ▼
text    83a2f8a288641fb9a4e9a5cc2f131c7d   ✓ back again`,
      },
    ],
  },

  where: {
    summary: "Mostly in Korea, in banks and government systems.",
    uses: [
      { place: "✓ 공동인증서", detail: "Your certificate's secret file is locked with SEED and your password." },
      { place: "✓ Korean banking", detail: "Older online banking programs used SEED." },
      { place: "✗ New projects", detail: "Use AES-GCM instead: it's the world standard." },
    ],
    example: {
      title: "Key + text → locked (official test, RFC 4269)",
      rows: [
        { label: "Key", value: "4706480851e61be85d74bfb3fd956185", mono: true },
        { label: "Text", value: "83a2f8a288641fb9a4e9a5cc2f131c7d", mono: true },
        { label: "Locked", value: "ee54d13ebcae706d226bc3142cd40d4a", mono: true, tone: "ok" },
      ],
      note: "Written in hex: each 2 characters = 1 byte.",
    },
  },

  verify: {
    summary: "SEED has no seal. You know the key was right because the unlocked data makes sense.",
    steps: [
      "Unlock with the key (from your password).",
      "Check if the result looks right.",
      "Looks right → ✓ unlocked.",
      "Garbage → ✗ \"wrong password\".",
    ],
    example: {
      title: "Opening 공동인증서 with a password",
      rows: [
        { label: "test1234!", value: "Looks right → unlocked", mono: true, tone: "ok" },
        { label: "test1234?", value: "Garbage → \"wrong password\"", mono: true, tone: "bad" },
      ],
      note: "One character wrong, and you get garbage.",
    },
  },

  summary: {
    points: [
      "SEED = Korea's lock. One key locks and unlocks.",
      "Without the key, the data is just noise.",
      "Still safe, but use AES for new work.",
    ],
    algorithm: `locked = SEED.lock(key, text)

// to unlock later:
result = SEED.unlock(key, locked)
if result looks right:
    ✓ unlocked
else:
    ✗ wrong password`,
  },
};
