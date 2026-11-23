// Self-check for the encrypt-detector skill: node selftest.mjs
// Fixed values from the Data Encrypt Study project + fresh ciphertexts made with Node's OpenSSL for the key check.
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { detect } from "./detect.mjs";

const scan = (v) => detect(v).scan;
const cases = [
  ["MD5", "900150983cd24fb0d6963f7d28e17f72", "hashing", /MD5/],
  ["SHA-1", "a9993e364706816aba3e25717850c26c9cd0d89d", "hashing", /SHA-1/],
  ["SHA-256 (hex)", "185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969", "hashing", /SHA-256/],
  ["bcrypt", "$2a$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i", "hashing", /bcrypt/],
  ["PBKDF2 (Django)", "pbkdf2_sha256$600000$abc123salt$" + crypto.pbkdf2Sync("pw", "abc123salt", 1000, 32, "sha256").toString("base64"), "hashing", /PBKDF2/],
  ["CBC ciphertext (48 B Base64)", "y+VUzkkv67XTQJtc3o162us7DbsvaB2UXZtuFnBOFMKh29fuPKv4U05BZOlfglRX", "UNKNOWN", /UNKNOWN/],
  ["DES-CBC size (24 B)", "dyjC2xjmP3+S3V0qVwjbdDtxfLl5jOZo", "symmetric", /UNKNOWN/],
  ["Base64 text", "SGVsbG8gd29ybGQ=", "encoding", /Base64/],
  ["made-up repeating hex", "7f2a9c4e8b1d6f3a5c7e9b2d4f6a8c1e3b5d7f9a2c4e6b8d1f3a5c7e9b2d4f6a8c1e3b5d7f9a2c4e6b8d1f3a5c7e9b2d4f6a8c1e3b5d7f9a2c4e6b8d", "UNKNOWN", /UNKNOWN/],
  ["cut-off SHA-512 (127 hex)", "1212e2633e2f05c68c991c478a5cac50e239703cd258ecbc1c313a6537e051b74e3ee12866f87c2444e455e7689fbacf527e2ce30519aecac88216fc306f733", "UNKNOWN", /UNKNOWN/],
];
for (const [name, value, category, algo] of cases) {
  const r = scan(value);
  assert.equal(r.category, category, `${name}: category ${r.category}`);
  assert.match(r.algorithm, algo, `${name}: algorithm ${r.algorithm}`);
}

// Asymmetric, made fresh
const ec = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
assert.match(scan(crypto.sign("sha256", Buffer.from("Hello123"), ec.privateKey).toString("base64")).algorithm, /ECDSA signature \(P-256\)/);
const rsa = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
assert.equal(scan(crypto.publicEncrypt(rsa.publicKey, Buffer.from("Hello123")).toString("base64")).algorithm, "RSA-2048");
assert.match(scan(rsa.publicKey.export({ type: "spki", format: "pem" })).algorithm, /RSA public key/);

// Key check: each method must decrypt its own ciphertext and nothing else must claim it
const pt = "Hello, 결제 승인 ✓";
const enc = (name, key, iv, tag) => { const c = crypto.createCipheriv(name, key, iv, tag ? { authTagLength: 16 } : undefined); const ct = Buffer.concat([c.update(pt), c.final()]); return Buffer.concat([iv ?? Buffer.alloc(0), ct, tag ? c.getAuthTag() : Buffer.alloc(0)]).toString("base64"); };
const k16 = crypto.randomBytes(16), k24 = crypto.randomBytes(24), k32 = crypto.randomBytes(32), k8 = crypto.randomBytes(8);
const keyCases = [
  ["AES-256-GCM", enc("aes-256-gcm", k32, crypto.randomBytes(12), true), k32, "certain"],
  ["AES-128-CBC", enc("aes-128-cbc", k16, crypto.randomBytes(16)), k16, "likely"],
  ["ARIA-192-CBC", enc("aria-192-cbc", k24, crypto.randomBytes(16)), k24, "likely"],
  ["ChaCha20-Poly1305", enc("chacha20-poly1305", k32, crypto.randomBytes(12), true), k32, "certain"],
  ["DES-CBC", enc("des-ede3-cbc", Buffer.concat([k8, k8, k8]), crypto.randomBytes(8)), k8, "likely"],
  ["3DES-CBC", enc("des-ede3-cbc", k24, crypto.randomBytes(8)), k24, "likely"],
  ["SEED-CBC", "y+VUzkkv67XTQJtc3o162us7DbsvaB2UXZtuFnBOFMKh29fuPKv4U05BZOlfglRX", Buffer.from("d6060d636b84194d06f6afa212d6213e", "hex"), "likely", "Hello, SEED! café ✓"],
];
for (const [method, value, key, verdict, text = pt] of keyCases) {
  const r = detect(value, key.toString("hex")).key;
  assert.equal(r.found?.method, method, `${method}: found ${r.found?.method}`);
  assert.equal(r.found.verdict, verdict, `${method}: verdict`);
  assert.equal(r.found.text, text, `${method}: text`);
  assert.equal(detect(value, crypto.randomBytes(key.length).toString("hex")).key.found, null, `${method}: a wrong key must find nothing`);
}
assert.match(detect("abcd", "xyz").key.error, /hex/);
assert.match(detect("abcd", "0011223344").key.error, /fits no method/);
console.log(`encrypt-detector self-test: all passed (${cases.length + 3} scans, ${keyCases.length} key methods + wrong keys, 2 key errors)`);
