#!/usr/bin/env node
// encrypt-detector: what is this hash / ciphertext / key / encoded text?
//
//   node detect.mjs '<value>'                 scan only (no key needed)
//   node detect.mjs '<value>' --key <hex>     scan + try every symmetric method that fits the key size
//   printf '%s' '<value>' | node detect.mjs   value from stdin (best for PEM blocks and anything with $ or quotes)
//
// Prints JSON. The scan is src/lib/classify.ts from the Data Encrypt Study website (same rules, same answers).
// Nothing is sent anywhere: everything runs locally with Node's built-in crypto (SEED: the project's own code).
import crypto from "node:crypto";
import { pathToFileURL } from "node:url";
import { classify } from "./lib/classify.mjs";
import { seed } from "./lib/seed.mjs";

const decoder = new TextDecoder("utf-8", { fatal: true });
// Readable text: letters, digits, punctuation, symbols, spaces, valid UTF-8 (same test as the website)
function readable(bytes) {
  try {
    const s = decoder.decode(bytes);
    return s.length > 0 && /^[\p{L}\p{N}\p{P}\p{S}\p{M}\s]*$/u.test(s) ? s : null;
  } catch { return null; }
}

function toBytes(value) {
  const v = value.replace(/\s+/g, "");
  if (/^([0-9a-fA-F]{2})+$/.test(v)) return Buffer.from(v, "hex");
  const b64 = v.replace(/-/g, "+").replace(/_/g, "/");
  if (/^[A-Za-z0-9+/]+={0,2}$/.test(b64)) return Buffer.from(b64, "base64");
  return null;
}

// Node's OpenSSL: cipher + IV + data -> plaintext (throws on bad padding / bad tag)
function openssl(name, key, iv, data, tag) {
  const d = crypto.createDecipheriv(name, key, iv, tag ? { authTagLength: 16 } : undefined);
  if (tag) d.setAuthTag(tag);
  return Buffer.concat([d.update(data), d.final()]);
}

/** Every method that fits the key size, in this project's layout: IV/nonce first, GCM/Poly1305 tag last. */
export function tryKey(value, keyHex) {
  const k = String(keyHex).replace(/\s+/g, "");
  if (!/^([0-9a-fA-F]{2})+$/.test(k)) return { error: "The key must be hex: pairs of 0-9 and a-f." };
  const key = Buffer.from(k, "hex"), all = toBytes(value);
  if (!all) return { error: "The value is not hex or Base64, so it can't be ciphertext in this format." };
  const n = key.length, methods = [];
  const gcm = (name) => () => openssl(name, key, all.subarray(0, 12), all.subarray(12, -16), all.subarray(-16));
  const cbc = (name, ivLen, k2 = key) => () => openssl(name, k2, all.subarray(0, ivLen), all.subarray(ivLen));

  if (n === 8) methods.push(["DES-CBC", cbc("des-ede3-cbc", 8, Buffer.concat([key, key, key]))]); // 3DES with K|K|K = DES
  if (n === 24) methods.push(["3DES-CBC", cbc("des-ede3-cbc", 8)]);
  if ([16, 24, 32].includes(n)) {
    const bits = n * 8;
    methods.push([`AES-${bits}-GCM`, gcm(`aes-${bits}-gcm`)], [`AES-${bits}-CBC`, cbc(`aes-${bits}-cbc`, 16)],
      [`AES-${bits}-CTR`, cbc(`aes-${bits}-ctr`, 16)], [`AES-${bits}-ECB`, () => openssl(`aes-${bits}-ecb`, key, null, all)]);
  }
  if (n === 16) methods.push(["SEED-CBC", () => { // not in OpenSSL 3: the project's own SEED, PKCS#7 checked by hand
    const p = seed(false, key, all.subarray(0, 16), all.subarray(16)), pad = p[p.length - 1];
    if (all.length < 32 || all.length % 16 || pad < 1 || pad > 16 || p.subarray(p.length - pad).some((b) => b !== pad)) throw new Error("bad padding");
    return Buffer.from(p.subarray(0, p.length - pad));
  }]);
  if ([16, 24, 32].includes(n)) methods.push([`ARIA-${n * 8}-CBC`, cbc(`aria-${n * 8}-cbc`, 16)]);
  if (n === 32) methods.push(["ChaCha20-Poly1305", gcm("chacha20-poly1305")]);
  if (!methods.length) return { error: `A ${n}-byte key fits no method here. Key sizes: DES 8, 3DES 24, AES 16/24/32, SEED 16, ARIA 16/24/32, ChaCha20 32 bytes.` };

  const attempts = methods.map(([name, run]) => {
    try {
      const text = readable(run());
      if (!text) return { method: name, verdict: "no", note: "decrypted to unreadable bytes: wrong key or wrong method" };
      // Only a tag (GCM, Poly1305) proves the key. CBC padding can pass by luck and CTR never fails: "likely" at best.
      return { method: name, verdict: /GCM|Poly1305/.test(name) ? "certain" : "likely", text };
    } catch (e) {
      return { method: name, verdict: "no", note: /auth|tag/i.test(e.message) ? "tag check failed: wrong key or changed data" : "failed: " + e.message.split("\n")[0] };
    }
  });
  const rank = { certain: 0, likely: 1, no: 2 };
  attempts.sort((a, b) => rank[a.verdict] - rank[b.verdict]);
  return { found: attempts.find((a) => a.verdict !== "no") ?? null, attempts };
}

export function detect(value, keyHex) {
  const scan = classify(value);
  const r2 = (x) => Math.round(x * 100) / 100; // 0.7999999 -> 0.8
  return { scan: { ...scan, categoryConfidence: r2(scan.categoryConfidence), algorithmConfidence: r2(scan.algorithmConfidence) },
    ...(keyHex ? { key: tryKey(value, keyHex) } : {}) };
}

// ---- command line
if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  const args = process.argv.slice(2);
  if (args.includes("--help") || args.includes("-h")) {
    console.log("usage: node detect.mjs '<value>' [--key <hex>]   (or pipe the value on stdin)");
    process.exit(0);
  }
  const ki = args.indexOf("--key");
  const keyHex = ki >= 0 ? args[ki + 1] : undefined;
  const rest = ki < 0 ? args : args.filter((_, i) => i !== ki && i !== ki + 1);
  let value = rest.join(" ");
  if (!value && !process.stdin.isTTY) value = await new Promise((res) => { let s = ""; process.stdin.on("data", (d) => (s += d)); process.stdin.on("end", () => res(s)); });
  if (!value.trim()) { console.error("No value given. usage: node detect.mjs '<value>' [--key <hex>]"); process.exit(2); }
  console.log(JSON.stringify(detect(value, keyHex), null, 2));
}
