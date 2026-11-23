---
name: encrypt-detector
description: Identify what a pasted value is (a hash, a ciphertext, a key, a signature or just encoded text) and, with a key, which cipher made it and what it says. Runs a tested rule engine locally instead of guessing. Use this whenever someone pastes a hex or Base64 string, a $2a$/pbkdf2_ hash, a PEM block or any random-looking token and asks what it is, which algorithm, whether it is MD5/SHA/AES/SEED/ARIA/RSA/ECDSA, whether it is encrypted or only encoded, whether a value looks real or made up, or wants to decrypt something with a key they have, even if they never say "detect". Covers the algorithms used in Korean finance and shopping (AES, SEED, ARIA, RSA-OAEP, ECDSA, SHA-256/384/512, HMAC, PBKDF2).
---

# encrypt-detector

Tell people what a value is, from evidence, and say plainly what cannot be known.

## Why a script instead of your own judgment

Looking at a hex string and "recognising" it is exactly where guesses go wrong. On 45 real test values, Claude on its own
got only 58% of the categories right: AES ciphertexts were called "SHA-256" and ECIES was called "AES-GCM". The rule
engine in `scripts/detect.mjs` (the same code as the Data Encrypt Study website's Detect tab) made no wrong category calls
on those values. It counts bytes exactly, checks real structure (DER layouts, curve points, PBKDF2 and bcrypt formats),
catches values that are not random, and says UNKNOWN when two answers fit equally well. Use its result as the facts,
then explain them.

## Steps

1. **Run the scan.** Pass the value on stdin, not as an argument, so `$` in bcrypt hashes and newlines in PEM blocks
   survive the shell:

   ```bash
   printf '%s' '<value>' | node <skill-dir>/scripts/detect.mjs
   ```

   `<skill-dir>` is this skill's folder (where this SKILL.md is). The output is JSON with `scan`: `category`
   (hashing / symmetric / asymmetric / encoding / UNKNOWN), `categoryConfidence`, `algorithm` (or `UNKNOWN`),
   `shortlist` (algorithms still possible), `candidates` and `evidence`.

2. **If the user has the key**, add it. Every method that fits the key size is tried: DES (8 bytes), 3DES (24),
   AES-GCM/CBC/CTR/ECB (16/24/32), SEED (16), ARIA (16/24/32), ChaCha20-Poly1305 (32):

   ```bash
   printf '%s' '<ciphertext>' | node <skill-dir>/scripts/detect.mjs --key <hex-key>
   ```

   `key.found` is the method that decrypted it, with `verdict` `certain` (a GCM or Poly1305 tag proved the key) or
   `likely` (readable text, but CBC/CTR have no tag), and the `text`. `key.found: null` means nothing worked.
   Only offer this when the user already has the key: never ask them to paste a real production key into a chat.

3. **Report** in this shape, in plain words for someone who may be new to cryptography:

   - **What it is:** the category, with the confidence as "likely" / "almost certainly", not a raw number.
   - **Algorithm:** the name, or "can't be named from the data alone: one of …" with the shortlist.
   - **Why:** 2–4 short points from `evidence`, translated into everyday language (e.g. "32 bytes, exactly the size
     of a SHA-256 fingerprint").
   - **What would settle it:** the key (for ciphertext), the original text (for a hash: hash it and compare),
     or where the value came from.

   If the key worked, lead with the method and the decrypted text.

## Honesty rules (the reason this skill exists)

- **Don't overrule the script.** If it says UNKNOWN, don't swap in your own guess. Explain why the answer is UNKNOWN:
  for example, 32 bytes fits both SHA-256 and a one-block AES/SEED/ARIA-CBC message.
- **A cipher can't be named from ciphertext alone.** AES, SEED and ARIA output is random-looking by design. Say
  "one of …, the key decides", never "this is AES".
- **Keyed and plain hashes look the same.** HMAC-SHA-256 and raw PBKDF2 output are exactly as long as SHA-256. Mention
  that when it matters.
- **Say clearly when a value looks made up.** A `scan.evidence` line about repeats, letter/digit patterns or an odd
  hex length means it is probably not real output (often hand-typed or AI-made, or cut off when copying).
  Say so kindly. It saves the user a lot of confusion.
- **Encoding is not encryption.** If the category is `encoding`, show the decoded text and say anyone can read it.

## Limits to mention when relevant

- The key check expects this layout: IV or nonce first, GCM/Poly1305 tag last, PKCS#7 padding for CBC. Ciphertext
  from a tool with another layout (separate IV, tag first, no padding) shows "nothing worked" even with the right key.
- Asymmetric ciphertext (RSA, ECIES) can't be decrypted here: that needs the private key and a different tool.
- Lengths shared by hashes and short ciphertexts (32, 48, 64 bytes) come back as "likely" (hex) or UNKNOWN (Base64).
  Measured accuracy is in the project's `eval/report-test.md`.

## Example

Input: "what is this? `dyjC2xjmP3+S3V0qVwjbdDtxfLl5jOZo`"

Script: `category: symmetric (0.65)`, `algorithm: UNKNOWN`, `shortlist: DES-CBC, 3DES-CBC, AES-CTR`

Report: "This is most likely **encrypted data** (symmetric encryption), not a hash. It's 24 bytes: too short for
AES-GCM, but exactly right for a short DES/3DES-CBC message (8-byte IV + 2 blocks) or AES-CTR with an 8-byte text.
Which one can't be told from the data: those ciphers all produce random-looking bytes. If you have the key, I can try
every method and show the original text."

## Keeping it in sync

`scripts/lib/classify.mjs` and `scripts/lib/seed.mjs` are generated from the website's `src/lib/*.ts` by
`npm run skill:build` (in the project root). Don't edit them by hand. Check the skill with `node scripts/selftest.mjs`.
