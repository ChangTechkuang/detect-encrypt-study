import type { StudyCase } from "./types";

// Written for a complete beginner: one idea per sentence, examples before explanations.
// Every value is real: src/lib/chacha.ts, checked against Node's OpenSSL ChaCha20-Poly1305.
export const chacha20: StudyCase = {
  id: "chacha20",
  name: "ChaCha20",
  fullName: "ChaCha, 20 rounds · a dance of add, turn and mix (Daniel J. Bernstein, 2008)",
  category: "symmetric",
  tagline: "A fast lock for data that needs no special chip. One secret key locks and unlocks.",
  status: { label: "Recommended", tone: "good" },
  facts: [
    { label: "Key size", value: "32 bytes" },
    { label: "Same key to lock & unlock?", value: "Yes" },
    { label: "Safe today?", value: "Yes (with Poly1305)" },
    { label: "Made", value: "2008" },
  ],
  java: "java/chacha20/ChaCha20.java",

  analogy:
    "Like a one-time pad of random letters made from your key. You mix each letter of your message with the next random letter. The friend with the same key makes the same pad and un-mixes it.",
  terms: [
    { term: "Key", meaning: "The secret that locks and unlocks. Same key for both." },
    { term: "Nonce", meaning: "\"Number used once\": a fresh random value per message, so the same key never makes the same pad twice." },
    { term: "Keystream", meaning: "The random-looking bytes made from key + nonce. Mixed with the text using XOR." },
    { term: "Poly1305 tag", meaning: "A 16-byte seal at the end. If the key is wrong or one bit was changed, the seal doesn't match." },
  ],

  what: {
    summary: "ChaCha20 locks data so only someone with the secret key can read it. It is used together with Poly1305, a seal that proves nothing was changed.",
    points: [
      "One key locks, the same key unlocks.",
      "A stream cipher: no blocks, no padding. 5 letters in → 5 bytes out.",
      "Fast on phones without AES chips. Used in TLS 1.3, WireGuard and SSH.",
    ],
  },

  how: {
    summary: "ChaCha20 makes random-looking bytes from the key and mixes them with the text. Follow the word \"Hello\" through it, with the key and nonce from RFC 8439's own example. Every value below is real.",
    steps: [
      {
        title: "Lay out the key, counter and nonce",
        detail: "ChaCha20 starts with a grid of 16 numbers (4 bytes each). Row 1 is fixed text, \"expand 32-byte k\". Rows 2 and 3 are the 32-byte key. Row 4 is a block counter (1 for the first 64 bytes) and the 12-byte nonce.",
        show: `61707865 3320646e 79622d32 6b206574   ← "expa" "nd 3" "2-by" "te k"
03020100 07060504 0b0a0908 0f0e0d0c   ← key (first half)
13121110 17161514 1b1a1918 1f1e1d1c   ← key (second half)
00000001 00000000 4a000000 00000000   ← counter = 1, nonce

key   = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
nonce = 000000000000004a00000000   (each word is stored back-to-front)`,
      },
      {
        title: "Dance 20 rounds",
        detail: "Each round mixes 4 numbers at a time with only 3 moves: add, XOR, and turn the bits (rotate). Odd rounds mix each column, even rounds mix each diagonal. After 20 rounds, ChaCha20 adds the start grid back on. No tables and no multiplying, so it is fast on any chip.",
        show: `one \"quarter round\" on 4 numbers a, b, c, d:
a += b;  d ^= a;  d <<<= 16
c += d;  b ^= c;  b <<<= 12
a += b;  d ^= a;  d <<<= 8
c += d;  b ^= c;  b <<<= 7

round 1: the 4 columns     round 2: the 4 diagonals     … × 10 = 20 rounds`,
      },
      {
        title: "Get 64 random-looking bytes",
        detail: "The grid after the dance, read as bytes, is the keystream: 64 bytes that look random. \"Hello\" only needs the first 5. A longer text uses counter 2 for the next 64 bytes, and so on.",
        show: `keystream (first 16 of 64 bytes):
22 4f 51 f3 40 1b d9 e1 2f de 27 6f b8 63 1d ed
^^^^^^^^^^^^^^ \"Hello\" uses these 5`,
      },
      {
        title: "Mix: text XOR keystream",
        detail: "Each letter is mixed with one keystream byte using XOR: the bits flip wherever the keystream has a 1. That's the whole encryption. To decrypt, do the same XOR again: it undoes itself.",
        show: `text       48 65 6c 6c 6f    "Hello"
keystream  22 4f 51 f3 40
           ──────────────  XOR
cipher     6a 2a 3d 9f 2f

H = 48 = 0100 1000
    22 = 0010 0010
         ─────────  XOR
    6a = 0110 1010`,
      },
      {
        title: "Seal it with Poly1305",
        detail: "XOR alone has a weakness: flip one bit of the cipher, and the same bit of the text flips, with no error. So a 16-byte seal (the Poly1305 tag) is added, computed from the ciphertext with a one-time key from counter 0. When unlocking, the seal is checked first.",
        show: `ciphertext  6a2a3d9f2f
tag         9f01c7dcde2774c609b9b001dbdc954b

sent:  nonce + ciphertext + tag
       000000000000004a00000000 6a2a3d9f2f 9f01c7dc…dbdc954b`,
      },
      {
        title: "Change one letter",
        detail: "Change the last letter (o → p). Only the last byte of the ciphertext changes, because each letter is mixed on its own. But the seal changes completely, so any change is caught.",
        show: `"Hello"  →  6a2a3d9f2f  tag 9f01c7dcde2774c609b9b001dbdc954b
"Hellp"  →  6a2a3d9f30  tag 720ad52a87b8a1db6d05bdbf7ec5cfe3
                    ^^ only this byte`,
      },
      {
        title: "Never reuse a nonce",
        detail: "The same key and nonce always make the same keystream. If two messages share it, XORing the two ciphertexts cancels the keystream out and leaks both messages. So every message gets a fresh random nonce. The key stays the same.",
        show: `cipher1 XOR cipher2 = text1 XOR text2   ← keystream gone!

✓ new nonce every message   ✗ same nonce twice`,
      },
    ],
  },

  where: {
    summary: "Wherever AES would be slow because there is no AES chip, and in modern protocols next to AES-GCM.",
    uses: [
      { place: "✓ TLS 1.3 (HTTPS)", detail: "One of the cipher choices. Phones often pick it." },
      { place: "✓ WireGuard VPN & SSH", detail: "WireGuard uses only ChaCha20-Poly1305." },
      { place: "✗ ChaCha20 without Poly1305", detail: "No seal: changed data goes unnoticed. Always use the pair." },
    ],
    example: {
      title: "\"Hello\" locked with ChaCha20-Poly1305",
      rows: [
        { label: "Key", value: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", mono: true },
        { label: "Nonce", value: "000000000000004a00000000", mono: true },
        { label: "Ciphertext + tag", value: "6a2a3d9f2f 9f01c7dcde2774c609b9b001dbdc954b", mono: true },
        { label: "Sent (Base64)", value: "AAAAAAAAAEoAAAAAaio9ny+fAcfc3id0xgm5sAHb3JVL", mono: true },
      ],
      note: "The ciphertext is exactly as long as the text (5 bytes): stream ciphers need no padding. The example key is from RFC 8439; real keys must be random.",
    },
  },

  verify: {
    summary: "Unlocking checks the Poly1305 seal first. If it doesn't match, nothing is unlocked.",
    steps: [
      "You have the key, and the nonce + ciphertext + tag.",
      "Make the seal again from the ciphertext and compare.",
      "Seal matches → ✓ XOR with the keystream to get the text back.",
      "Seal differs → ✗ wrong key, or the data was changed. Stop.",
    ],
    example: {
      title: "Unlock the \"Hello\" example",
      rows: [
        { label: "Right key", value: "seal matches → \"Hello\"", tone: "ok" },
        { label: "One bit flipped", value: "seal differs → rejected", tone: "bad" },
        { label: "Wrong key", value: "seal differs → rejected", tone: "bad" },
      ],
      note: "This is why ChaCha20 is always used with Poly1305: without the seal, the flipped bit would quietly change the text.",
    },
  },

  summary: {
    points: [
      "ChaCha20 = keystream from key + nonce, XOR with the text.",
      "Poly1305 = a 16-byte seal that catches any change.",
      "Safe and fast. A fresh nonce for every message.",
    ],
    algorithm: `nonce  = random(12 bytes)                 // new for every message
stream = ChaCha20(key, nonce, counter = 1)
cipher = text XOR stream
tag    = Poly1305(oneTimeKey(key, nonce), cipher)
send(nonce + cipher + tag)

// unlock: check tag first, then cipher XOR stream = text`,
  },
};
