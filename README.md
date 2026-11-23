# Data Encrypt Study

A learning project about **hashing**, **symmetric encryption** and **asymmetric encryption**.
Every method is explained in plain words, shown step by step with real values, runnable in the browser,
and implemented in Java with self-checks against official test vectors.
The Detect engine also comes as a Claude Code skill, [encrypt-detector](#claude-skill-encrypt-detector).

**Live site:** https://study-beta-two.vercel.app (every push to `main` redeploys it). There, Ask Claude on the Detect
page uses the Claude API, billed to the `ANTHROPIC_API_KEY` set in the Vercel project, and is limited to 10 uses per
visitor and 200 for the whole site per day. Locally it uses your own Claude Code instead (see below).

## What's inside

The site has five parts, switched with the tabs at the top:

| Part | URL | What it does |
|---|---|---|
| **Study** | `/`, `/md5`, `/seed`, … | Each method in 5 short steps: what it is, how it works (a step-by-step player with real data), where it's used, how it's verified, and a summary |
| **ASCII** | `/ascii` | Type text and see each character as decimal, hex and binary, plus the full ASCII table (0–127) |
| **Encoding** | `/encoding` | Encode and decode Hex, Base64, Base64URL, URL encoding and HTML entities, with auto-detect and a comparison table. Encoding is not encryption: anyone can undo it |
| **Playground** | `/playground/md5`, … | Try each method live: hash, encrypt, decrypt, sign, verify. Every page runs its official test vectors in your browser |
| **Detect** | `/detect` | Paste a hash or encrypted text and find out what it is (see below) |

### Detect

Paste a hash, ciphertext, key or encoded text, then press **Scan**:

1. **Scan** (no AI, in your browser): five checks run with a 1–100% progress bar. They look at the encoding, format labels
   (bcrypt, PBKDF2, PEM…), randomness, size and structure, and the algorithm. The checks come from `src/lib/classify.ts`.
2. **Have the key?** (optional, only for symmetric ciphertext): paste the key in hex. Every method that fits its size is
   tried (DES, 3DES, AES in 4 modes, SEED, ARIA, ChaCha20), and the one that decrypts names the exact algorithm and shows
   the original text. Or press **Skip**. The key never leaves the browser.
3. **Result**: the category (hashing / symmetric / asymmetric / encoding), the algorithm or a shortlist, the decoded text,
   and why.
4. **Ask Claude to explain** (optional): Claude explains the result in plain words. This is the only step that sends the
   text anywhere.

What it can and can't tell from the data alone:

- It can tell the **category** from length and structure: hashes have fixed sizes, RSA output is exactly the key size,
  and ECDSA signatures and ECIES have a structure you can check. It also catches values that are not random (probably made up).
- It **can't name the cipher** without the key. AES, SEED and ARIA ciphertexts all look like random bytes, so the
  answer is a shortlist. Some lengths are shared too: 32, 48 or 64 bytes can be a SHA-256/384/512 hash or a short CBC
  message. Those come back as "likely" or UNKNOWN, never as a confident guess.
- It covers the algorithms used in Korean finance and shopping: AES, SEED, ARIA, RSA-2048/4096, RSA-OAEP, ECC/ECDSA,
  SHA-256/384/512, HMAC-SHA-256 and PBKDF2.

The scan and the key check need nothing extra. **Ask Claude** runs your local Claude Code in headless mode, with no
API key. It uses the standalone Claude Code from Anthropic's installer (`C:\Users\<you>\.local\bin\claude.exe`).
If it isn't installed, the Detect page offers an **Install Claude Code** button that runs the official installer and
fills in the path; sign in once by running `claude.exe` in a terminal. A `claude.exe` elsewhere on C: or D: can be
entered in the path box, or set in `.env.local` (then restart the site):

```
CLAUDE_BIN=C:\path\to\claude.exe
```

This only works on a computer where Claude Code is installed and logged in. Accuracy on real test data is in
`eval/report-test.md` (see [Test the detection engine](#test-the-detection-engine)).

## Methods

| Category | Method | Stands for | Status |
|---|---|---|---|
| Hashing | MD5 | Message-Digest Algorithm 5 | Broken: checksums only |
| Hashing | SHA-1 | Secure Hash Algorithm 1 | Broken: collisions since 2017 |
| Hashing | SHA-256 | Secure Hash Algorithm, 256-bit | Recommended |
| Hashing | SHA-512 | Secure Hash Algorithm, 512-bit | Recommended |
| Hashing | bcrypt | Blowfish-based crypt | Recommended for passwords |
| Symmetric | DES | Data Encryption Standard | Broken |
| Symmetric | 3DES | Triple Data Encryption Standard | Retired |
| Symmetric | AES | Advanced Encryption Standard | Recommended (AES-GCM) |
| Symmetric | SEED | A name (KISA, Korea) | Korean standard |
| Symmetric | ARIA | Academy, Research Institute, Agency (NSRI, Korea) | Korean standard |
| Symmetric | ChaCha20 | ChaCha, 20 rounds (with Poly1305) | Recommended |
| Asymmetric | RSA | Rivest–Shamir–Adleman | Recommended (2048+ bits) |
| Asymmetric | 공동인증서 | Korean joint certificate (NPKI) | In use in Korea |

Test vectors come from the official sources: RFC 1321 (MD5), NIST FIPS 180 (SHA-1, SHA-256, SHA-512), the OpenBSD bcrypt suite,
FIPS 46 / SP 800-67 (DES, 3DES), NIST SP 800-38A and the GCM spec (AES), RFC 4269 (SEED), RFC 5794 (ARIA), RFC 8439 (ChaCha20-Poly1305).

## Run the website

Requires **Node.js 20.9 or newer**.

```bash
npm install
npm run dev        # http://localhost:3000
```

Other commands:

```bash
npm run build      # production build
npm start          # serve the production build
npm run lint       # check the code
```

## Claude skill: encrypt-detector

The Detect engine is also a [Claude Code skill](https://docs.claude.com/en/docs/claude-code/skills) in
`.claude/skills/encrypt-detector/`. With this repo open in Claude Code, paste a hash or ciphertext into the chat and ask
what it is. Claude runs the same rules as the Detect tab, locally, instead of guessing, and explains the result in plain
words. With a key, it tries every symmetric method and shows the original text.

```bash
printf '%s' '900150983cd24fb0d6963f7d28e17f72' | node .claude/skills/encrypt-detector/scripts/detect.mjs          # scan
printf '%s' '<ciphertext>' | node .claude/skills/encrypt-detector/scripts/detect.mjs --key <hex>                  # + key
node .claude/skills/encrypt-detector/scripts/selftest.mjs                                                         # check it
```

To use it in every project, copy the folder to `~/.claude/skills/encrypt-detector/`. It needs only Node 18+, with no
packages. After changing `src/lib/classify.ts` or `src/lib/seed.ts`, run `npm run skill:build` to refresh the skill's copy,
then copy the folder to `~/.claude/skills/` again: the personal copy doesn't update itself.

## Test the detection engine

```bash
node eval/gen.mjs              # real test data: eval/data/dev.json (to build rules) + test.json (to score them)
node eval/gen-kr.mjs           # Korean finance set: ARIA, SHA-384, HMAC, PBKDF2, ECDSA, RSA-OAEP -> data/kr-dev.json + kr-test.json
node eval/evaluate.mts test    # scores src/lib/classify.ts -> eval/report-test.md (confusion matrix, precision, recall, F1)
node eval/run-ai.mjs data/ai-before.json   # optional: same scores for the Claude engine (needs npm start, uses claude.exe)
```

## Run the Java code

Requires **Java 17 or newer**. Each file runs on its own, with no build step, and prints its self-checks:

```bash
cd java/aes && java Aes.java
cd java/seed && java Seed.java
cd java/aria && java Aria.java
cd java/bcrypt && java -cp lib/jbcrypt-0.4.jar Bcrypt.java   # bcrypt needs its library
```

Most files also accept arguments, for example:

```bash
cd java/md5 && java Md5.java "Hello"
cd java/aes && java Aes.java encrypt GCM <hex-key> "Hello"
cd java/rsa && java Rsa.java genkey 2048
cd java/gongdong && java Gongdong.java issue 홍길동 test1234! out
```

## Project structure

```
src/
  app/                  pages: Study (/[id]), ASCII (/ascii), Encoding (/encoding), Playground (/playground/[id]), Detect (/detect)
  app/api/detect/       runs claude.exe for "Ask Claude to explain" (no tools, input through stdin)
  content/              the study text for each method (one file per method)
  components/           page layouts, the step player, the ASCII, Encoding and Detect views
  lib/encoding.ts       Hex, Base64, Base64URL, URL encoding, HTML entities + auto-detect
  lib/trykey.ts         Detect's key check: tries every method that fits the key size
  lib/detect.ts         Claude's instructions and answer format for Detect
  components/impl/      Playground panels (one per method family) + shared UI kit
  lib/impl/             Playground logic and test vectors, no React
  lib/seed.ts           SEED cipher, written by hand (browsers and Java don't include it)
  lib/classify.ts       Detect's rule engine: hash / symmetric / asymmetric from structure, UNKNOWN when unsure
  lib/aria.ts           ARIA cipher (Korean standard, RFC 5794), written by hand (browsers and Java don't include it)
  lib/chacha.ts         ChaCha20-Poly1305, written by hand (browsers don't include it)
eval/                   detection test data, scoring scripts and reports
java/                   one runnable Java file per method, with self-checks
scripts/build-skill.mjs copies classify.ts and seed.ts into the skill as plain JavaScript (npm run skill:build)
.claude/skills/
  encrypt-detector/     the Claude skill: SKILL.md + scripts/detect.mjs, selftest.mjs, lib/ (generated)
```

## Adding a new method

1. Add a Java file in `java/<method>/` with self-checks against official test vectors.
2. Add the study text in `src/content/<method>.ts` (follow `md5.ts`) and register it in `src/content/index.ts`.
3. Add a Playground panel in `src/components/impl/` and connect it in `ImplementView.tsx`.

## ⚠️ Learning only

- The code includes **test keys on purpose**: an RSA key pair and 공동인증서 test sets (password `test1234!`),
  so the self-checks can prove the browser and Java produce the same formats. They are public: never use them for anything real.
  The test data in `eval/data/` also contains throwaway keys made only for testing.
- Don't paste real secrets into Detect if you press **Ask Claude**: that step sends the text to Claude.
- MD5, SHA-1, DES and 3DES are included to show why they are broken or retired. Use SHA-256, bcrypt and AES-GCM for real work.
