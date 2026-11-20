# Data Encrypt Study

A learning project about **hashing**, **symmetric encryption** and **asymmetric encryption**.
Every method is explained in plain words, shown step by step with real values, runnable in the browser,
and implemented in Java with self-checks against official test vectors.

## What's inside

The site has three parts, switched with the tabs at the top:

| Part | URL | What it does |
|---|---|---|
| **Study** | `/`, `/md5`, `/seed`, … | Each method in 5 short steps: what it is, how it works (a step-by-step player with real data), where it's used, how it's verified, and a summary |
| **ASCII** | `/ascii` | Type text and see each character as decimal, hex and binary, plus the full ASCII table (0–127) |
| **Playground** | `/playground/md5`, … | Try each method live: hash, encrypt, decrypt, sign, verify. Every page runs its official test vectors in your browser |

## Methods

| Category | Method | Stands for | Status |
|---|---|---|---|
| Hashing | MD5 | Message-Digest Algorithm 5 | Broken: checksums only |
| Hashing | SHA-256 | Secure Hash Algorithm, 256-bit | Recommended |
| Hashing | bcrypt | Blowfish-based crypt | Recommended for passwords |
| Symmetric | DES | Data Encryption Standard | Broken |
| Symmetric | 3DES | Triple Data Encryption Standard | Retired |
| Symmetric | AES | Advanced Encryption Standard | Recommended (AES-GCM) |
| Symmetric | SEED | A name (KISA, Korea) | Korean standard |
| Asymmetric | RSA | Rivest–Shamir–Adleman | Recommended (2048+ bits) |
| Asymmetric | 공동인증서 | Korean joint certificate (NPKI) | In use in Korea |

Test vectors come from the official sources: RFC 1321 (MD5), NIST FIPS 180 (SHA-256), the OpenBSD bcrypt suite,
FIPS 46 / SP 800-67 (DES, 3DES), NIST SP 800-38A and the GCM spec (AES), RFC 4269 (SEED).

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

## Run the Java code

Requires **Java 17 or newer**. Each file runs on its own, with no build step, and prints its self-checks:

```bash
cd java/aes && java Aes.java
cd java/seed && java Seed.java
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
  app/                  pages: Study (/[id]), ASCII (/ascii), Playground (/playground/[id])
  content/              the study text for each method (one file per method)
  components/           page layouts, the step player, the ASCII view
  components/impl/      Playground panels (one per method family) + shared UI kit
  lib/impl/             Playground logic and test vectors, no React
  lib/seed.ts           SEED cipher, written by hand (browsers and Java don't include it)
java/                   one runnable Java file per method, with self-checks
```

## Adding a new method

1. Add a Java file in `java/<method>/` with self-checks against official test vectors.
2. Add the study text in `src/content/<method>.ts` (follow `md5.ts`) and register it in `src/content/index.ts`.
3. Add a Playground panel in `src/components/impl/` and connect it in `ImplementView.tsx`.

## ⚠️ Learning only

- The code includes **test keys on purpose**: an RSA key pair and 공동인증서 test sets (password `test1234!`),
  so the self-checks can prove the browser and Java produce the same formats. They are public: never use them for anything real.
- MD5, DES and 3DES are included to show why they are broken or retired. Use SHA-256, bcrypt and AES-GCM for real work.
