import type { StudyCase } from "./types";

// Written for a complete beginner: one idea per sentence, examples before explanations.
export const gongdong: StudyCase = {
  id: "gongdong",
  name: "공동인증서",
  fullName: "공동 = joint, 인증서 = certificate (formerly 공인인증서) · Korea's digital ID certificate",
  category: "asymmetric",
  tagline: "Korea's digital ID card and seal (도장) for banks and government sites.",
  status: { label: "In use in Korea", tone: "warn" },
  facts: [
    { label: "Used for", value: "Banking, 홈택스, government" },
    { label: "Files", value: "2 (certificate + key)" },
    { label: "Opened with", value: "Your password" },
    { label: "Main type", value: "Asymmetric" },
  ],
  java: "java/gongdong/Gongdong.java",

  analogy:
    "Like your ID card plus your personal seal (도장). The seal is kept in a safe, and your password opens the safe.",
  terms: [
    { term: "Certificate", meaning: "Your digital ID card: your name + public key, vouched for by a trusted office (CA)." },
    { term: "Private key", meaning: "Your digital seal. Only you have it, on your own PC." },
    { term: "전자서명", meaning: "Electronic signature: the mark your seal leaves. It proves you agreed." },
  ],

  what: {
    summary: "공동인증서 is your digital ID card and seal for Korean sites.",
    points: [
      "It is asymmetric: your private key signs, the bank checks with your public key.",
      "Your password only opens the safe (SEED) for your key, on your own PC.",
      "Your password and private key never leave your PC.",
    ],
  },

  how: {
    summary: "Think of stamping a paper with your seal, then showing your ID card. Follow 홍길동 getting a certificate and signing \"I agree to the contract\", one step at a time. Every value below is real.",
    steps: [
      {
        title: "Your PC makes a key pair",
        detail: "When 홍길동 asks for a certificate, his own PC makes an RSA key pair: a private key (his seal, 도장) and a public key (anyone can use it to check his seal). Each key is 2048 bits long. The private key never leaves his PC.",
        show: `홍길동's PC  →  RSA key pair (2048 bits)

private key  = the seal (도장)      stays on the PC
public key   = checks the seal      goes to the CA`,
      },
      {
        title: "The CA signs your ID card → signCert.der",
        detail: "A CA (Certificate Authority) is a trusted office, like the office that issues ID cards. It checks that 홍길동 is really 홍길동, then puts his name and public key on a digital card and signs it with the CA's own private key. That card is the file signCert.der.",
        show: `signCert.der  (your digital ID card)

who you are:   cn=홍길동()0123456789   ① name + number
               ou=personal            ② personal certificate
               o=TestCA               ③ the CA that issued it
               c=KR                   ④ country: Korea
your key:      홍길동's public key (RSA 2048 bits)
valid for:     365 days
CA signature:  SHA-256 + RSA, with the CA's private key`,
      },
      {
        title: "Lock the private key → signPri.key",
        detail: "The private key is saved in the file signPri.key, locked with SEED (a Korean lock where one key both locks and unlocks). The SEED key is not saved anywhere: it is rebuilt from the password every time. The password is mixed with a salt (8 random bytes, saved in the file so the same password gives a different key on every PC) and stirred with SHA-1 2048 times. The many rounds make guessing passwords slow. The salt below is an example; a real file gets random bytes.",
        show: `password  test1234!        = 74 65 73 74 31 32 33 34 21
salt      (example)        = 01 02 03 04 05 06 07 08

round 1:     SHA-1(test1234! + salt)
             = 5e8badd66ed9951baf504a18a420a642f4672090
round 2…2048: SHA-1 of the previous result, again and again
result (20 bytes)
             = 6be16b5f0d565f4712a39490ac3c1a4f 7bad811a
                ①                                ②
① first 16 bytes  = SEED key
② last 4 bytes    → SHA-1 → first 16 bytes = start value (IV)
                  = b6e6216113455d0bea4504cce402a145

private key  →  SEED (key ①, start value)  →  signPri.key`,
      },
      {
        title: "Sign: password → key → SHA-256 → RSA",
        detail: "To sign, 홍길동 types his password. The same 2048 stirs rebuild the same SEED key, and it unlocks signPri.key. A wrong password gives a wrong SEED key, and the key stays locked. Then the message is turned into a 32-byte fingerprint with SHA-256, and the private key signs that fingerprint with RSA. The result is the 전자서명 (electronic signature), 256 bytes long.",
        show: `① "test1234!"  →  SEED key  →  unlock signPri.key  →  private key
② SHA-256("I agree to the contract")
   = a5343339fee1e84bdd370de70c59076a
     7fd2807fdfcb7bd988ade0a9fa945db9
③ RSA sign (private key, fingerprint ②)  →  signature (256 bytes)

sent to the bank:  message + signature + signCert.der`,
      },
      {
        title: "The bank checks two signatures",
        detail: "The bank never sees the password or the private key. It checks 2 things. First: is the signature right? It uses the public key inside signCert.der. Second: is signCert.der a real card? It uses the CA's public key to check the CA's signature on it. Both pass → 홍길동 really agreed. Change one letter of the message and the first check fails.",
        show: `check 1:  signature  + 홍길동's public key (from signCert.der)
          → matches SHA-256 of the message?     ✓ 홍길동 signed it

check 2:  signCert.der + the CA's public key
          → CA signature is valid?              ✓ the card is real

both ✓  →  accepted`,
      },
    ],
  },

  where: {
    summary: "Korean sites that need proof you agreed.",
    uses: [
      { place: "✓ Online banking", detail: "Log in and approve transfers." },
      { place: "✓ 홈택스", detail: "File your taxes online." },
      { place: "✓ Government sites", detail: "Get official papers online." },
    ],
    example: {
      title: "A test certificate from Gongdong.java",
      rows: [
        { label: "Name on the card", value: "cn=홍길동()0123456789, ou=personal, o=TestCA, c=KR", mono: true },
        { label: "Certificate file", value: "signCert.der", mono: true },
        { label: "Key file", value: "signPri.key", mono: true },
      ],
      note: "Made-up TestCA, only for learning.",
    },
  },

  verify: {
    summary: "Your password opens the key. The bank checks the stamp.",
    steps: [
      "Type your password to open your key.",
      "Sign the message.",
      "The bank checks it with your certificate.",
      "Match → ✓ accepted. Changed or wrong → ✗.",
    ],
    example: {
      title: "Sign \"I agree to the contract\"",
      rows: [
        { label: "Right password, same message", value: "valid", tone: "ok" },
        { label: "Changed: \"I agree to the contract!\"", value: "invalid", tone: "bad" },
        { label: "Wrong password", value: "key stays locked", tone: "bad" },
      ],
      note: "One \"!\" added, and the check fails.",
    },
  },

  summary: {
    points: [
      "공동인증서 = your digital ID card + seal.",
      "Asymmetric: private key signs, the bank checks with your certificate.",
      "The password just opens the safe for your key on your PC.",
    ],
    algorithm: `key = openSafe(password)              // on your PC
signature = sign(key, document)

// at the bank:
if check(certificate, document, signature):
    ✓ you agreed
else:
    ✗ rejected`,
  },
};
