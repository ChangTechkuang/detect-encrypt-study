import type { StudyCase } from "./types";

// Written for a complete beginner: one idea per sentence, examples before explanations.
export const des: StudyCase = {
  id: "des",
  name: "DES",
  fullName: "Data Encryption Standard · an old lock for data (USA, 1977)",
  category: "symmetric",
  tagline: "Locks data with a secret key. Its key is far too short today: never use it for new things.",
  status: { label: "Broken", tone: "bad" },
  facts: [
    { label: "Key size", value: "8 bytes (too short)" },
    { label: "Same key to lock & unlock?", value: "Yes" },
    { label: "Safe today?", value: "No (broken)" },
    { label: "Made", value: "1977" },
  ],
  java: "java/des/Des.java",

  analogy:
    "Like a 4-digit bike lock. It works, but a computer can try every code very quickly.",
  terms: [
    { term: "Key", meaning: "The secret that locks and unlocks the data." },
    { term: "Lock / unlock", meaning: "Turn readable text into noise, and back again." },
    { term: "Brute force", meaning: "Trying every possible key until one works." },
  ],

  what: {
    summary: "DES locks data so only someone with the secret key can read it.",
    points: [
      "The same key locks and unlocks.",
      "Without the key, the data looks like noise.",
      "The key is too short: a computer can guess it.",
    ],
  },

  how: {
    summary: "Think of shuffling a deck of cards in a way only your key can undo. Follow the official example \"Now is t\" through DES, one step at a time. Every value below is real.",
    steps: [
      {
        title: "Turn letters into numbers",
        detail: "A computer only stores numbers. Each letter (and the space) becomes one number from 0 to 255 (one byte), written in hex: 2 characters per byte. DES always locks exactly 8 bytes at a time (one \"block\"), and \"Now is t\" is exactly 8 letters.",
        show: `"Now is t"  →  4e 6f 77 20 69 73 20 74
                N  o  w  ␣  i  s  ␣  t

N = 78 = hex 4e   (4×16 + 14 = 78, e = 14)
␣ = space = hex 20
8 letters = 8 bytes = 64 bits   (1 byte = 8 bits)`,
      },
      {
        title: "Take the 8-byte key",
        detail: "The key is also 8 bytes (64 bits). But DES only really uses 56 of them. The last bit of every byte is a check bit: it only helps spot typing mistakes in the key and does nothing for the lock. 8 bytes × 1 check bit = 8 wasted bits, so 64 − 8 = 56 bits really count.",
        show: `key = 01 23 45 67 89 ab cd ef

01 = 0000000①    23 = 0010001①    45 = 0100010①    67 = 0110011①
89 = 1000100①    ab = 1010101①    cd = 1100110①    ef = 1110111①

① = check bit (not part of the secret)
64 bits − 8 check bits = 56 bits that really count`,
      },
      {
        title: "Shuffle, then cut in two halves",
        detail: "First DES moves the 64 bits into a fixed, public order (the same shuffle every time, so it adds no secret). Then it cuts the result into a left half and a right half of 4 bytes each. The shuffle is why the halves don't look like \"Now \" and \"is t\" anymore.",
        show: `text:          4e6f7720 69732074      ("Now is t")
after shuffle: b7a48736 00fe1327

L = b7a48736   (left half, 4 bytes)
R = 00fe1327   (right half, 4 bytes)`,
      },
      {
        title: "Mix 16 rounds",
        detail: "DES now does 16 rounds of mixing. First it makes 16 small round keys from the 56 key bits (48 bits each, a different pick of the key bits every round). In each round, the right half is scrambled together with that round's key, and the result is mixed into the left half (with XOR, a bit-by-bit \"flip where they differ\"). Then the two halves swap places. After 16 rounds, every bit of the text and every bit of the key have touched every bit of the result.",
        show: `one round:
  ① new left  = old right
  ② new right = old left  XOR  scramble(old right, round key)

round  1 → round key  1
round  2 → round key  2
   …
round 16 → round key 16`,
      },
      {
        title: "Read the locked result",
        detail: "After the 16 rounds, DES puts the two halves back together (and undoes the fixed bit-moving from the start). The 8 bytes that come out are the locked text. They look like random noise: no letter of \"Now is t\" can be seen.",
        show: `text:    4e 6f 77 20 69 73 20 74   "Now is t"
key:     01 23 45 67 89 ab cd ef
locked:  3f a4 0e 8a 98 4d 48 15

DES("Now is t") = 3fa40e8a984d4815`,
      },
      {
        title: "Unlock: the same rounds backwards",
        detail: "To unlock, DES runs the very same 16 rounds, but uses the round keys in reverse order (16 first, 1 last). Each round undoes one round of locking, so the text comes back exactly.",
        show: `locked:   3fa40e8a984d4815
round keys used:  16, 15, 14, … , 2, 1
text:     4e6f772069732074  =  "Now is t"`,
      },
      {
        title: "Why DES is broken",
        detail: "56 bits means there are 2^56 possible keys. That sounds huge, but a fast computer can simply try every key until the text makes sense (brute force). Already in 1999, a special machine plus thousands of computers found a DES key in less than a day. That's why DES must not be used for anything new.",
        show: `2^56 = 72,057,594,037,927,936 possible keys

try key 1 → garbage
try key 2 → garbage
   …
try 0123456789abcdef → "Now is t"   ✓ found`,
      },
    ],
  },

  where: {
    summary: "Only in old systems. Never in anything new.",
    uses: [
      { place: "✓ Old bank / ATM systems", detail: "Some old machines still speak DES." },
      { place: "✓ Learning", detail: "A simple start to see how locks work." },
      { place: "✗ Anything new", detail: "Use AES instead." },
    ],
    example: {
      title: "Text + key → locked result",
      rows: [
        { label: "Text", value: "\"Now is t\"", mono: true },
        { label: "Key", value: "0123456789abcdef", mono: true },
        { label: "Locked result", value: "3fa40e8a984d4815", mono: true, tone: "ok" },
      ],
      note: "Official test value (FIPS 81). Written in hex: two characters = one byte.",
    },
  },

  verify: {
    summary: "DES has no seal. You just unlock and see if the text makes sense.",
    steps: [
      "Unlock with the same key.",
      "Right key → ✓ the text comes back.",
      "Wrong key → ✗ garbage.",
      "DES can't notice if someone changed the data.",
    ],
    example: {
      title: "Unlock 3fa40e8a984d4815",
      rows: [
        { label: "Right key 0123456789abcdef", value: "\"Now is t\"", mono: true, tone: "ok" },
        { label: "Wrong key fedcba9876543210", value: "0ef220f064194595 (garbage)", mono: true, tone: "bad" },
      ],
      note: "Only the right key gives the text back.",
    },
  },

  summary: {
    points: [
      "DES = an old lock. One secret key locks and unlocks.",
      "Wrong key → garbage. It can't spot changed data.",
      "Broken: the key is too short. Use AES.",
    ],
    algorithm: `locked = DES_lock(key, "Now is t")    // 3fa40e8a984d4815

// to read it later:
text = DES_unlock(key, locked)          // "Now is t"
// wrong key → garbage`,
  },
};
