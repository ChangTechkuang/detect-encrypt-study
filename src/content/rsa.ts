import type { StudyCase } from "./types";

// Written for a complete beginner: one idea per sentence, examples before explanations.
export const rsa: StudyCase = {
  id: "rsa",
  name: "RSA",
  fullName: "Rivest–Shamir–Adleman (the 3 inventors' names) · the classic two-key method (1977)",
  category: "asymmetric",
  tagline: "Two keys: a public one you share with everyone, and a private one only you keep.",
  status: { label: "Recommended (2048+ bits)", tone: "good" },
  facts: [
    { label: "Keys", value: "2 (public + private)" },
    { label: "Share the public key?", value: "Yes, with everyone" },
    { label: "Safe today?", value: "Yes (2048 bits+)" },
    { label: "Made", value: "1977" },
  ],
  java: "java/rsa/Rsa.java",

  analogy:
    "Like a mailbox. Anyone can drop a letter in, but only the owner's key opens it.",
  terms: [
    { term: "Public key", meaning: "The key you give to everyone. It locks messages for you and checks your signatures." },
    { term: "Private key", meaning: "The key only you keep. It unlocks messages and makes signatures." },
    { term: "Signature", meaning: "A mark only your private key can make. Anyone can check it with your public key." },
  ],

  what: {
    summary: "RSA locks and signs data with two different keys.",
    points: [
      "Anyone locks with your public key. Only your private key unlocks.",
      "Only your private key signs. Anyone checks with your public key.",
      "You never have to send a secret to anyone.",
    ],
  },

  how: {
    summary: "Think of a mailbox: the slot is public, the key is private. Follow the tiny textbook example (message 65) through RSA, one step at a time. Every value below is real.",
    steps: [
      {
        title: "Pick two secret primes",
        detail: "A prime is a number that only divides by 1 and by itself, like 2, 3, 5, 7. RSA starts with two primes, called p and q. They stay secret forever. Real RSA picks huge ones; we use tiny ones so you can follow the math.",
        show: `p = 61     (secret)
q = 53     (secret)

61 is prime: only 1 × 61 makes 61
53 is prime: only 1 × 53 makes 53`,
      },
      {
        title: "Multiply them → n (public)",
        detail: "Multiply p and q. The result n is part of both keys and is shared with everyone. Multiplying is easy, but going back (finding 61 and 53 from 3233 alone) is very hard when the numbers are huge. That one-way trick is what keeps RSA safe. We also compute (p-1) × (q-1) = 3120. It stays secret and is used only to make the keys.",
        show: `n = p × q = 61 × 53 = 3233             (public)

(p-1) × (q-1) = 60 × 52 = 3120         (secret)`,
      },
      {
        title: "Make the public number e and the private number d",
        detail: "Pick a public number e = 17. Then find a private number d that fits e like a key fits a lock: e × d must leave 1 when divided by 3120. \"Leaves 1\" means: take away 3120 as many times as you can, and 1 is left over. The number that works is d = 2753. Only someone who knows 3120 (so knows 61 and 53) can find d.",
        show: `e = 17      (public)
d = 2753    (private)

17 × 2753 = 46801 = 15 × 3120 + 1
                     ①           ②
① 3120 fits 15 times into 46801
② 1 is left over  →  e and d are a matching pair

public key  = (n = 3233, e = 17)
private key = (n = 3233, d = 2753)`,
      },
      {
        title: "Lock: 65 → 2790",
        detail: "A message must be a number smaller than n. Our message is 65. To lock it, multiply 65 by itself 17 times (that's e), divide by 3233 (that's n), and keep only the remainder. The remainder is what's left over after dividing, like 7 ÷ 3 = 2 with 1 left over. Anyone can do this, because e and n are public.",
        show: `65^17 = 6599743590836592050933837890625      (31 digits)

6599743590836592050933837890625 ÷ 3233
  = 2041368261935227977399887995, remainder 2790

locked message = 2790`,
      },
      {
        title: "Unlock: 2790 → 65",
        detail: "To unlock, do the same thing with the private number d instead of e: multiply 2790 by itself 2753 times, divide by 3233, keep the remainder. The answer is 65 again: the original message. Only the owner knows d = 2753, so only the owner can unlock.",
        show: `2790^2753                 (a 9486-digit number)
÷ 3233  →  remainder 65

unlocked message = 65   ✓ same as the start`,
      },
      {
        title: "Sign: the same thing the other way",
        detail: "To sign, the owner uses the private number d first: 65^2753, remainder after ÷ 3233 = 588. That 588 is the signature. Anyone can check it with the public number e: 588^17, remainder after ÷ 3233 = 65. Getting 65 back proves the signature was made with d, so it came from the owner.",
        show: `sign  (private d):  65^2753 ÷ 3233  →  remainder 588
check (public  e):  588^17  ÷ 3233  →  remainder 65

65 = the message  →  ✓ signature is valid`,
      },
      {
        title: "Real RSA: much bigger numbers",
        detail: "3233 is so small anyone could find 61 × 53 in a second. Real RSA uses an n of 2048 bits, which is about 617 digits long. Nobody can split that back into its two primes. Real RSA also adds random bytes (padding) to the message before locking, so the same message never locks to the same result twice.",
        show: `tiny example:  n = 3233                     (4 digits)
real RSA:      n = 2048 bits                (about 617 digits)
               e = 65537 (usual public number)
               + random padding on every message`,
      },
    ],
  },

  where: {
    summary: "Wherever two sides meet with no shared secret.",
    uses: [
      { place: "✓ HTTPS (the lock icon)", detail: "Your browser checks the website's RSA-signed certificate." },
      { place: "✓ SSH logins", detail: "Your private key signs in, the server checks with your public key." },
      { place: "✓ App updates", detail: "Updates are signed so you know who made them." },
      { place: "✗ Big files", detail: "RSA locks only small data. It locks an AES key, and AES locks the file." },
    ],
    example: {
      title: "RSA with tiny numbers (only for learning)",
      rows: [
        { label: "Message", value: "65", mono: true },
        { label: "Locked with public key", value: "2790", mono: true, tone: "ok" },
        { label: "Unlocked with private key", value: "65", mono: true, tone: "ok" },
      ],
      note: "Real keys are 2048 bits long, not 3233.",
    },
  },

  verify: {
    summary: "The private key signs. Anyone checks with the public key.",
    steps: [
      "You sign a message with your private key.",
      "You send the message and the signature.",
      "Anyone checks them with your public key.",
      "Match → ✓ it's from you and unchanged. Changed → ✗.",
    ],
    example: {
      title: "Check a signed message",
      rows: [
        { label: "\"Version 1.2 release approved\"", value: "✓ valid", mono: true, tone: "ok" },
        { label: "\"Version 1.3 release approved\"", value: "✗ invalid", mono: true, tone: "bad" },
      ],
      note: "One number changed (2 → 3), and the check fails.",
    },
  },

  summary: {
    points: [
      "RSA = two keys. Share the public one, keep the private one.",
      "Public key locks and checks. Private key unlocks and signs.",
      "Use 2048 bits or more.",
    ],
    algorithm: `signature = sign(privateKey, message)     // only you

// anyone can check:
if check(publicKey, message, signature):
    ✓ from you, unchanged
else:
    ✗ changed or not from you`,
  },
};
