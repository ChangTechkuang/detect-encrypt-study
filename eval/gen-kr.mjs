// Real test data for the Korean finance / shopping algorithms: node eval/gen-kr.mjs
// Writes data/kr-dev.json and data/kr-test.json (separate keys and plaintexts), same shape as gen.mjs.
// Kept apart from dev/test.json so the earlier sets (and the Claude baseline scored on them) stay unchanged.
// Every ciphertext is decrypted back and every signature verified before saving.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const { aria } = await import(new URL("../src/lib/aria.ts", import.meta.url)); // checked against RFC 5794 + OpenSSL

const SETS = {
  "kr-dev": ["Hello123", "카드번호 1234-5678", "order=20261123&amount=59000", "x".repeat(100)],
  "kr-test": ["Hello123", "결제 승인", "{\"user\":\"kim\",\"point\":1500}", "y".repeat(150)],
};
const hex = (b) => Buffer.from(b).toString("hex");

function makeSet(name, plaintexts) {
  const samples = [];
  const add = (algorithm, category, plaintext, bytes, params) => {
    for (const encoding of ["hex", "base64"])
      samples.push({ id: `${name}-${samples.length + 1}`, algorithm, category, plaintext, encoding,
        value: Buffer.from(bytes).toString(encoding), bytes: bytes.length, params });
  };
  const addText = (algorithm, category, plaintext, value, params) =>
    samples.push({ id: `${name}-${samples.length + 1}`, algorithm, category, plaintext, encoding: "text", value, bytes: 0, params });

  const ec = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const ec384 = crypto.generateKeyPairSync("ec", { namedCurve: "secp384r1" });
  const rsa = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });

  for (const pt of plaintexts) {
    const P = Buffer.from(pt);
    // Hashing
    add("SHA-384", "hashing", pt, crypto.createHash("sha384").update(P).digest(), {});
    const hk = crypto.randomBytes(32);
    add("HMAC-SHA-256", "hashing", pt, crypto.createHmac("sha256", hk).update(P).digest(), { key: hex(hk) });
    const salt = crypto.randomBytes(12).toString("base64").replace(/[+/=]/g, "");
    const dk = crypto.pbkdf2Sync(P, salt, 600000 / 100, 32, "sha256"); // 6,000 rounds keeps the run fast; the format is the same
    addText("PBKDF2-SHA256", "hashing", pt, `pbkdf2_sha256$6000$${salt}$${dk.toString("base64")}`, { salt, rounds: 6000, format: "Django" });
    add("PBKDF2-SHA256", "hashing", pt, dk, { salt, rounds: 6000, format: "raw output" });

    // ARIA-CBC, 3 key sizes, this project's layout IV(16) + ciphertext. Made by OpenSSL, decrypted by our aria.ts
    for (const bits of [128, 192, 256]) {
      const key = crypto.randomBytes(bits / 8), iv = crypto.randomBytes(16);
      const c = crypto.createCipheriv(`aria-${bits}-cbc`, key, iv), ct = Buffer.concat([c.update(P), c.final()]);
      const back = Buffer.from(aria(false, key, iv, ct)); assert.equal(back.subarray(0, back.length - back.at(-1)).toString(), pt, `ARIA-${bits}`);
      add(`ARIA-${bits}-CBC`, "symmetric", pt, Buffer.concat([iv, ct]), { key: hex(key), iv: hex(iv), padding: "PKCS#7", layout: "IV(16) + ciphertext" });
    }

    // ECDSA signatures (DER), P-256 and P-384, verified with the public key
    for (const [crv, kp, h] of [["P-256", ec, "sha256"], ["P-384", ec384, "sha384"]]) {
      const sig = crypto.sign(h, P, kp.privateKey);
      assert.ok(crypto.verify(h, P, kp.publicKey, sig), "ECDSA verify");
      add(`ECDSA-${crv}`, "asymmetric", pt, sig, { hash: h, format: "DER (r, s)" });
    }
    // RSA-OAEP (SHA-256) ciphertext; the RSA-2048 key is generated above
    if (P.length <= 190) {
      const ct = crypto.publicEncrypt({ key: rsa.publicKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" }, P);
      assert.equal(crypto.privateDecrypt({ key: rsa.privateKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" }, ct).toString(), pt);
      add("RSA-2048-OAEP", "asymmetric", pt, ct, { padding: "OAEP SHA-256" });
    }
  }
  // Raw ECC public key (uncompressed point), once per set
  const jwk = ec.publicKey.export({ format: "jwk" });
  add("ECC-P256-public-key", "asymmetric", "", Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, "base64url"), Buffer.from(jwk.y, "base64url")]), {});
  return { set: name, note: "Throwaway keys for testing only.", samples };
}

for (const [name, pts] of Object.entries(SETS)) {
  const data = makeSet(name, pts);
  fs.writeFileSync(path.join(here, "data", `${name}.json`), JSON.stringify(data, null, 1));
  console.log(`${name}: ${data.samples.length} samples, all decrypted / verified`);
}
