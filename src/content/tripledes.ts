import type { StudyCase } from "./types";

// Written for a complete beginner: one idea per sentence, examples before explanations.
export const tripledes: StudyCase = {
  id: "tripledes",
  name: "3DES",
  fullName: "Triple Data Encryption Standard · the old DES lock used 3 times",
  category: "symmetric",
  tagline: "DES done three times with three keys. Safer than DES, but slow and retired.",
  status: { label: "Retired", tone: "warn" },
  facts: [
    { label: "Key size", value: "24 bytes (3 DES keys)" },
    { label: "Same key to lock & unlock?", value: "Yes" },
    { label: "Safe today?", value: "Retired (use AES)" },
    { label: "Made", value: "1998" },
  ],
  java: "java/tripledes/TripleDes.java",

  analogy:
    "Like locking a box 3 times with 3 different keys. A thief must guess all three.",
  terms: [
    { term: "Key", meaning: "The secret that locks and unlocks. Here it is 3 keys in one." },
    { term: "DES", meaning: "The older lock that 3DES uses three times." },
    { term: "Retired", meaning: "Still works, but experts say: stop using it." },
  ],

  what: {
    summary: "3DES locks data by running the old DES lock three times.",
    points: [
      "The same key locks and unlocks.",
      "The key is really 3 DES keys glued together.",
      "Safer than DES, but slow. Use AES now.",
    ],
  },

  how: {
    summary: "Think of a box with three locks, opened in reverse order. Follow the official NIST sample \"The qufck brown fox jump\" through 3DES, one step at a time. Every value below is real.",
    steps: [
      {
        title: "Split the key into 3 keys",
        detail: "The 3DES key is 24 bytes long. It is really 3 normal DES keys of 8 bytes each, glued together. We call them K1, K2 and K3.",
        show: `0123456789abcdef 23456789abcdef01 456789abcdef0123
       K1               K2               K3

K1 = 0123456789abcdef   (8 bytes)
K2 = 23456789abcdef01   (8 bytes)
K3 = 456789abcdef0123   (8 bytes)`,
      },
      {
        title: "Cut the text into 8-byte blocks",
        detail: "DES only locks 8 bytes (one \"block\") at a time, so 3DES does too. The text is 24 letters (spaces count), so it becomes 3 blocks. Each letter is one byte, written in hex (2 characters per byte).",
        show: `"The qufc"  →  54 68 65 20 71 75 66 63   block 1
"k brown "  →  6b 20 62 72 6f 77 6e 20   block 2
"fox jump"  →  66 6f 78 20 6a 75 6d 70   block 3

T = 84 = hex 54   (5×16 + 4 = 84)`,
      },
      {
        title: "Lock block 1 with K1",
        detail: "First, the normal DES lock runs on block 1 using K1. The result already looks like noise.",
        show: `block 1:          5468652071756663   "The qufc"
① DES lock (K1):  a28e91724c4bba31`,
      },
      {
        title: "\"Unlock\" with K2",
        detail: "Next, 3DES runs the DES unlock on that result, but with K2. K2 is not the key that locked it, so this does not give the text back. It just scrambles the block even more.",
        show: `① after K1 lock:    a28e91724c4bba31
② DES unlock (K2):  5a2ea7f983a2f53f   (not text: just more noise)`,
      },
      {
        title: "Lock again with K3",
        detail: "Finally, the DES lock runs once more, with K3. These 8 bytes are the locked block 1.",
        show: `② after K2 unlock:  5a2ea7f983a2f53f
③ DES lock (K3):    a826fd8ce53b855f   ← locked block 1`,
      },
      {
        title: "Same for the other blocks",
        detail: "Blocks 2 and 3 go through the very same 3 steps (lock K1 → unlock K2 → lock K3). Put the 3 locked blocks side by side and you have the full locked text. To unlock, do it all backwards: unlock K3 → lock K2 → unlock K1.",
        show: `            ① lock K1         ② unlock K2       ③ lock K3
block 1:  a28e91724c4bba31  5a2ea7f983a2f53f  a826fd8ce53b855f
block 2:  167e47ec24f71d63  ea141a7dd69701f0  cce21c8112256fe6
block 3:  2c1a917234425365  8059ee8212e22a79  68d5c05dd9b6b900

locked = a826fd8ce53b855f cce21c8112256fe6 68d5c05dd9b6b900`,
      },
      {
        title: "Why \"unlock\" in the middle?",
        detail: "If all three keys are the same, the K2 unlock cancels the K1 lock, and only the K3 lock is left. So 3DES with K1 = K2 = K3 is exactly plain DES. That let old DES machines and new 3DES machines talk to each other.",
        show: `K1 = K2 = K3 = 0123456789abcdef

"Now is t" → lock K1 → unlock K2 (cancels it) → lock K3
3DES("Now is t") = 3fa40e8a984d4815 = DES("Now is t")`,
      },
    ],
  },

  where: {
    summary: "Old payment systems. Being phased out.",
    uses: [
      { place: "✓ Old payment cards / ATMs", detail: "Many older bank systems still use it." },
      { place: "✓ Learning", detail: "Shows how to make an old lock stronger." },
      { place: "✗ Anything new", detail: "Use AES instead." },
    ],
    example: {
      title: "Text + key → locked result",
      rows: [
        { label: "Text", value: "\"The qufck brown fox jump\"", mono: true },
        { label: "Key (24 bytes)", value: "0123456789abcdef23456789abcdef01456789abcdef0123", mono: true },
        { label: "Locked result", value: "a826fd8ce53b855fcce21c8112256fe668d5c05dd9b6b900", mono: true, tone: "ok" },
      ],
      note: "Official sample (NIST SP 800-67). Written in hex: two characters = one byte.",
    },
  },

  verify: {
    summary: "3DES has no seal. You just unlock and see if the text makes sense.",
    steps: [
      "Unlock with the same key.",
      "Right key → ✓ the text comes back.",
      "Wrong key → ✗ garbage.",
      "3DES can't notice if someone changed the data.",
    ],
    example: {
      title: "Unlock a826fd8c…d9b6b900",
      rows: [
        { label: "Right key", value: "\"The qufck brown fox jump\"", mono: true, tone: "ok" },
        { label: "Key 3 wrong", value: "12a47815ea1e94f04f3e9052… (garbage)", mono: true, tone: "bad" },
      ],
      note: "One of the three keys wrong (key 3 = fedcba9876543210) → garbage.",
    },
  },

  summary: {
    points: [
      "3DES = DES three times, with 3 keys.",
      "Wrong key → garbage. It can't spot changed data.",
      "Retired: slow and old. Use AES.",
    ],
    algorithm: `step1  = DES_lock(key1, text)
step2  = DES_unlock(key2, step1)
locked = DES_lock(key3, step2)

// to read it later: do it backwards
text = DES_unlock(key1, DES_lock(key2, DES_unlock(key3, locked)))`,
  },
};
