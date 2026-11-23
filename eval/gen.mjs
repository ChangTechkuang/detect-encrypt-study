// Generates REAL test data for the detection engine: node eval/gen.mjs
// Two separate sets (different keys AND different plaintexts): data/dev.json to build rules, data/test.json to score them.
// Every ciphertext is decrypted again before it is saved (SEED also by java/seed/Seed.java, an independent implementation).
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const { seed } = await import(new URL("../src/lib/seed.ts", import.meta.url)); // checked against RFC 4269 on the Playground

// Both sets contain "Hello123". The other lengths differ, and some are chosen to hit hash-sized outputs on purpose
// (CBC of <16 bytes = 32 bytes = SHA-256 size; GCM of 36 bytes = 64 bytes = SHA-512 size), because real data does too.
const SETS = {
  dev: ["Hello123", "ok", "Hello123Hello12", "The quick brown fox jumps over the lazy dog", "0123456789".repeat(5), "b".repeat(180)],
  test: ["Hello123", "Z", "password", "Hello123 world!!!", "abcdefghijklmnopqrstuvwxyz0123456789", "a".repeat(120)],
};

const hex = (b) => Buffer.from(b).toString("hex");
const pkcs7 = (b, n) => { const p = n - (b.length % n); return Buffer.concat([b, Buffer.alloc(p, p)]); };

function makeSet(name, plaintexts) {
  const samples = [];
  const add = (algorithm, category, plaintext, bytes, params) => {
    for (const encoding of ["hex", "base64"])
      samples.push({ id: `${name}-${samples.length + 1}`, algorithm, category, plaintext, encoding,
        value: Buffer.from(bytes).toString(encoding), bytes: bytes.length, params });
  };

  const rsa = Object.fromEntries([2048, 4096].map((bits) => [bits, crypto.generateKeyPairSync("rsa", { modulusLength: bits,
    publicKeyEncoding: { type: "spki", format: "pem" }, privateKeyEncoding: { type: "pkcs8", format: "pem" } })]));
  const ec = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const keys = { "RSA-2048": rsa[2048], "RSA-4096": rsa[4096],
    "ECIES-P256": { publicKey: ec.publicKey.export({ type: "spki", format: "pem" }), privateKey: ec.privateKey.export({ type: "pkcs8", format: "pem" }) } };

  for (const pt of plaintexts) {
    const P = Buffer.from(pt);
    // Hashing (hex is the usual way to write a hash, Base64 also appears, e.g. HTML integrity="sha256-...")
    for (const [algorithm, a] of [["MD5", "md5"], ["SHA-1", "sha1"], ["SHA-256", "sha256"], ["SHA-512", "sha512"]])
      add(algorithm, "hashing", pt, crypto.createHash(a).update(P).digest(), {});

    // AES-GCM and AES-CBC, 3 key sizes. Format = this project's: IV + ciphertext (+ 16-byte tag)
    for (const bits of [128, 192, 256]) {
      const key = crypto.randomBytes(bits / 8);
      const iv12 = crypto.randomBytes(12), g = crypto.createCipheriv(`aes-${bits}-gcm`, key, iv12);
      const gct = Buffer.concat([g.update(P), g.final()]), tag = g.getAuthTag();
      const gd = crypto.createDecipheriv(`aes-${bits}-gcm`, key, iv12); gd.setAuthTag(tag);
      assert.equal(Buffer.concat([gd.update(gct), gd.final()]).toString(), pt);
      add(`AES-${bits}-GCM`, "symmetric", pt, Buffer.concat([iv12, gct, tag]), { key: hex(key), iv: hex(iv12), tag: hex(tag), padding: "none", layout: "IV(12) + ciphertext + tag(16)" });

      const iv16 = crypto.randomBytes(16), c = crypto.createCipheriv(`aes-${bits}-cbc`, key, iv16);
      const cct = Buffer.concat([c.update(P), c.final()]);
      const cd = crypto.createDecipheriv(`aes-${bits}-cbc`, key, iv16);
      assert.equal(Buffer.concat([cd.update(cct), cd.final()]).toString(), pt);
      add(`AES-${bits}-CBC`, "symmetric", pt, Buffer.concat([iv16, cct]), { key: hex(key), iv: hex(iv16), padding: "PKCS#7", layout: "IV(16) + ciphertext" });
    }

    { // SEED-CBC (no SEED in Node's OpenSSL): project's seed.ts encrypts, seed.ts AND Java decrypt
      const key = crypto.randomBytes(16), iv = crypto.randomBytes(16);
      const ct = Buffer.from(seed(true, key, iv, pkcs7(P, 16)));
      const back = Buffer.from(seed(false, key, iv, ct)); assert.equal(back.subarray(0, back.length - back.at(-1)).toString(), pt);
      const all = Buffer.concat([iv, ct]);
      const java = execFileSync("java", ["Seed.java", "decrypt", hex(key), all.toString("base64")], { cwd: path.join(here, "../java/seed") }).toString().trim();
      assert.equal(java, pt, "Java SEED decrypt");
      add("SEED-CBC", "symmetric", pt, all, { key: hex(key), iv: hex(iv), padding: "PKCS#7", layout: "IV(16) + ciphertext" });
    }

    { // ChaCha20-Poly1305 (RFC 8439)
      const key = crypto.randomBytes(32), nonce = crypto.randomBytes(12);
      const c = crypto.createCipheriv("chacha20-poly1305", key, nonce, { authTagLength: 16 });
      const ct = Buffer.concat([c.update(P), c.final()]), tag = c.getAuthTag();
      const d = crypto.createDecipheriv("chacha20-poly1305", key, nonce, { authTagLength: 16 }); d.setAuthTag(tag);
      assert.equal(Buffer.concat([d.update(ct), d.final()]).toString(), pt);
      add("ChaCha20-Poly1305", "symmetric", pt, Buffer.concat([nonce, ct, tag]), { key: hex(key), nonce: hex(nonce), tag: hex(tag), padding: "none", layout: "nonce(12) + ciphertext + tag(16)" });
    }

    // RSA-OAEP (SHA-256). Max plaintext: 190 bytes for 2048, 446 for 4096
    for (const bits of [2048, 4096]) {
      const opt = (key) => ({ key, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" });
      const ct = crypto.publicEncrypt(opt(rsa[bits].publicKey), P);
      assert.equal(crypto.privateDecrypt(opt(rsa[bits].privateKey), ct).toString(), pt);
      add(`RSA-${bits}`, "asymmetric", pt, ct, { padding: "OAEP SHA-256", key: `keys["RSA-${bits}"]` });
    }

    { // ECIES: ephemeral ECDH P-256 + HKDF-SHA256 + AES-256-GCM. Layout: ephemeral point(65) + IV(12) + ciphertext + tag(16)
      const eph = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
      const jwk = eph.publicKey.export({ format: "jwk" });
      const point = Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, "base64url"), Buffer.from(jwk.y, "base64url")]);
      const kdf = (shared) => Buffer.from(crypto.hkdfSync("sha256", shared, Buffer.alloc(0), point, 32));
      const k = kdf(crypto.diffieHellman({ privateKey: eph.privateKey, publicKey: ec.publicKey })), iv = crypto.randomBytes(12);
      const c = crypto.createCipheriv("aes-256-gcm", k, iv), ct = Buffer.concat([c.update(P), c.final()]), tag = c.getAuthTag();
      const k2 = kdf(crypto.diffieHellman({ privateKey: ec.privateKey, publicKey: crypto.createPublicKey({ key: { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y }, format: "jwk" }) }));
      const d = crypto.createDecipheriv("aes-256-gcm", k2, iv); d.setAuthTag(tag);
      assert.equal(Buffer.concat([d.update(ct), d.final()]).toString(), pt);
      add("ECIES-P256", "asymmetric", pt, Buffer.concat([point, iv, ct, tag]), { scheme: "ECDH P-256 + HKDF-SHA256 + AES-256-GCM", layout: "point(65) + IV(12) + ciphertext + tag(16)", key: 'keys["ECIES-P256"]' });
    }
  }
  return { set: name, note: "Throwaway keys for testing only.", keys, samples };
}

fs.mkdirSync(path.join(here, "data"), { recursive: true });
for (const [name, pts] of Object.entries(SETS)) {
  const data = makeSet(name, pts);
  fs.writeFileSync(path.join(here, "data", `${name}.json`), JSON.stringify(data, null, 1));
  console.log(`${name}: ${data.samples.length} samples, all decrypted back and checked`);
}
