import type { StudyCase } from "./types";

// Written for a complete beginner: one idea per sentence, examples before explanations.
export const aes: StudyCase = {
  id: "aes",
  name: "AES",
  fullName: "Advanced Encryption Standard · the world's standard lock for data (2001)",
  category: "symmetric",
  tagline: "The world's standard lock for data. One secret key locks it, the same key unlocks it.",
  status: { label: "Recommended (AES-GCM)", tone: "good" },
  facts: [
    { label: "Key size", value: "16, 24 or 32 bytes" },
    { label: "Same key to lock & unlock?", value: "Yes" },
    { label: "Safe today?", value: "Yes" },
    { label: "Made", value: "2001" },
  ],
  java: "java/aes/Aes.java",

  analogy:
    "Like the standard lock on almost every door in the world. GCM adds a tamper seal, like a sealed medicine bottle: if someone opened it, you see it.",
  terms: [
    { term: "Key", meaning: "The secret that locks and unlocks. Same key for both." },
    { term: "Encrypt / decrypt", meaning: "Lock the data / unlock it again." },
    { term: "GCM", meaning: "The best way to use AES. It adds a tamper seal." },
  ],

  what: {
    summary: "AES locks data so only someone with the secret key can read it.",
    points: [
      "One key locks, the same key unlocks.",
      "Without the key → the data is just noise.",
      "Use AES-GCM: it also catches any change.",
    ],
  },

  how: {
    summary: "Think of a combination lock: turn the dials with your key many times, and the text becomes noise. Follow the official NIST example through AES-128, one step at a time. Every value below is real.",
    steps: [
      {
        title: "Put the 16 bytes in a 4×4 grid",
        detail: "AES locks exactly 16 bytes at a time (one \"block\"). Our text is 16 bytes, written in hex (2 characters = 1 byte). AES puts them into a grid of 4 rows and 4 columns. It fills the grid column by column: the first 4 bytes go down column 1, the next 4 down column 2, and so on.",
        show: `text = 6bc1bee2 2e409f96 e93d7e11 7393172a
        col 1    col 2    col 3    col 4

          col1 col2 col3 col4
row 1:     6b   2e   e9   73
row 2:     c1   40   3d   93
row 3:     be   9f   7e   17
row 4:     e2   96   11   2a`,
      },
      {
        title: "Turn the key into 11 round keys",
        detail: "Our key is 16 bytes (128 bits), so AES does 10 rounds. Each round needs its own key, plus one extra at the start: 11 round keys. AES grows them from the one secret key with a fixed recipe. Round key 0 is just the key itself; every next one is built from the one before.",
        show: `key           = 2b7e151628aed2a6abf7158809cf4f3c

round key  0  = 2b7e151628aed2a6abf7158809cf4f3c   ① the key itself
round key  1  = a0fafe1788542cb123a339392a6c7605   ② built from key 0
   …              (keys 2 to 9)
round key 10  = d014f9a8c9ee2589e13f0cc8b6630ca6   ③ used in the last round`,
      },
      {
        title: "Add the key (XOR)",
        detail: "First AES mixes in round key 0 with XOR. XOR works on bits (0s and 1s): flip the bit of the text wherever the key has a 1, keep it where the key has a 0. AES does this for every byte of the grid. XOR undoes itself: do it again with the same key and you get the text back.",
        show: `text byte  6b = 0110 1011
key byte   2b = 0010 1011
XOR        40 = 0100 0000   (flipped where the key has a 1)

grid after adding the key (text XOR key):
          col1 col2 col3 col4
row 1:     40   06   42   7a
row 2:     bf   ee   ca   5c
row 3:     ab   4d   6b   58
row 4:     f4   30   99   16`,
      },
      {
        title: "Round 1: swap, slide, stir, add",
        detail: "One round has 4 moves. ① Swap bytes: every byte is replaced using a fixed table called the S-box (40 becomes 09). ② Slide rows: row 1 stays, row 2 slides 1 place left, row 3 slides 2, row 4 slides 3. ③ Stir columns: each column is mixed so every byte depends on all 4 bytes of its column. ④ Add round key 1 with XOR, like the step before.",
        show: `① swap (S-box)   ② slide rows     ③ stir columns
09 6f 2c da      09 6f 2c da      52 97 e0 ba
08 28 74 4a  →   28 74 4a 08  →   9f 86 1a 1a
62 e3 7f 6a      7f 6a 62 e3      16 15 ae 26
bf 04 ee 47      47 bf 04 ee      c2 ca 54 59

④ XOR round key 1  →  f265e8d51fd2397bc3b9976d9076505c`,
      },
      {
        title: "Repeat for 10 rounds",
        detail: "AES does the same 4 moves again and again, each time with the next round key. The last round (round 10) skips the stir. After 10 rounds, every byte of the text has changed every byte of the grid. What comes out is the locked data.",
        show: `after round  1:  f265e8d51fd2397bc3b9976d9076505c
after round  2:  fdf37cdb4b0c8c1bf7fcd8e94aa9bbf8
after round  3:  acd1ec9ca242e2c31f690f7ab704b90f
after round  4:  a2616e5f44a54d39c029e20092b764e9
after round  5:  2c4af31432c3efc9c8a9b87b252ecda7
after round  6:  cd4dc0137eb3ba1993b939ff2bd3bcf7
after round  7:  e26dbb7d40d22134e3b7fda26b9b077c
after round  8:  41d7c6537d669140dd2f179d02acc51b
after round  9:  bb36c7eb88334d49a4e7112e74f182c4
after round 10:  3ad77bb40d7a3660a89ecaf32466ef97   ← locked`,
      },
      {
        title: "Unlock: the same steps backwards",
        detail: "To unlock, AES runs every move in reverse order with the same key: remove round key 10, un-slide the rows, un-swap the bytes with the reverse S-box, and so on back to round key 0. Each move has an exact opposite, so the text comes back byte for byte.",
        show: `locked  3ad77bb40d7a3660a89ecaf32466ef97
   │  same key, round keys 10 → 0
   ▼
text    6bc1bee22e409f96e93d7e117393172a   ✓ back again`,
      },
    ],
  },

  where: {
    summary: "Almost everywhere data is locked today.",
    uses: [
      { place: "✓ Websites (HTTPS)", detail: "The padlock in your browser uses AES." },
      { place: "✓ Wi-Fi", detail: "Home Wi-Fi (WPA2/WPA3) locks your traffic with AES." },
      { place: "✓ Disks & zip files", detail: "BitLocker, FileVault and password-locked zips use AES." },
      { place: "✗ Simple ECB mode", detail: "Same pieces lock the same way, so patterns show. Use GCM." },
    ],
    example: {
      title: "Key + text → locked (official NIST test)",
      rows: [
        { label: "Key", value: "2b7e151628aed2a6abf7158809cf4f3c", mono: true },
        { label: "Text", value: "6bc1bee22e409f96e93d7e117393172a", mono: true },
        { label: "Locked", value: "3ad77bb40d7a3660a89ecaf32466ef97", mono: true, tone: "ok" },
      ],
      note: "Written in hex: each 2 characters = 1 byte.",
    },
  },

  verify: {
    summary: "GCM adds a seal when locking. When unlocking, it checks the seal first.",
    steps: [
      "Lock the text → you get locked data + a seal.",
      "To unlock, GCM checks the seal with your key.",
      "Seal matches → ✓ you get the text back.",
      "Anything changed → ✗ rejected, no text.",
    ],
    example: {
      title: "Lock \"Hello\" with AES-GCM, then change one byte",
      rows: [
        { label: "Key", value: "feffe9928665731c6d6a8f9467308308", mono: true },
        { label: "Locked + seal", value: "d3d7408bb6 + 052ee1d3d6863b5c8d49b8446b6538b9", mono: true },
        { label: "Unlock as is", value: "\"Hello\" → seal OK", tone: "ok" },
        { label: "Unlock d2d7408bb6", value: "Seal broken → rejected", mono: true, tone: "bad" },
      ],
      note: "One byte changed (d3 → d2), and AES-GCM refuses it. (IV used: cafebabefacedbaddecaf888)",
    },
  },

  summary: {
    points: [
      "AES = the world's standard lock. One key locks and unlocks.",
      "Without the key, the data is just noise.",
      "Use AES-GCM: it also catches any change.",
    ],
    algorithm: `locked, seal = AES_GCM.lock(key, "Hello")

// to unlock later:
if seal matches (key, locked):
    ✓ text = "Hello"
else:
    ✗ rejected: wrong key or data was changed`,
  },
};
