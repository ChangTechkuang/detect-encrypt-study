// ChaCha20 and ChaCha20-Poly1305 (RFC 8439), written by hand: browsers' Web Crypto doesn't have them.
// Same algorithm as java/chacha20/ChaCha20.java (which uses Java's built-in cipher).
// SYMMETRIC: one 32-byte key encrypts and decrypts. ChaCha20 is a STREAM cipher: it makes a keystream
// from key + nonce + counter, and XORs it with the text. XOR undoes itself, so encrypt = decrypt.
// Poly1305 adds a 16-byte tag, so a wrong key or changed data is detected (like AES-GCM).

const rotl = (x: number, n: number) => (x << n | x >>> (32 - n)) >>> 0;
const le32 = (b: Uint8Array, i: number) => (b[i] | b[i + 1] << 8 | b[i + 2] << 16 | b[i + 3] << 24) >>> 0;

/** One 64-byte keystream block: 16 words, 20 rounds of add-rotate-XOR, then add the start words back. */
export function chachaBlock(key: Uint8Array, counter: number, nonce: Uint8Array) {
  const start = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, // "expand 32-byte k"
    ...[0, 4, 8, 12, 16, 20, 24, 28].map((i) => le32(key, i)), counter >>> 0, ...[0, 4, 8].map((i) => le32(nonce, i))];
  const x = start.slice();
  const qr = (a: number, b: number, c: number, d: number) => {
    x[a] = (x[a] + x[b]) >>> 0; x[d] = rotl(x[d] ^ x[a], 16);
    x[c] = (x[c] + x[d]) >>> 0; x[b] = rotl(x[b] ^ x[c], 12);
    x[a] = (x[a] + x[b]) >>> 0; x[d] = rotl(x[d] ^ x[a], 8);
    x[c] = (x[c] + x[d]) >>> 0; x[b] = rotl(x[b] ^ x[c], 7);
  };
  for (let i = 0; i < 10; i++) { // 10 double rounds = 20 rounds: columns, then diagonals
    qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15);
    qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14);
  }
  const out = new Uint8Array(64);
  x.forEach((w, i) => { const v = (w + start[i]) >>> 0; out[i * 4] = v; out[i * 4 + 1] = v >>> 8; out[i * 4 + 2] = v >>> 16; out[i * 4 + 3] = v >>> 24; });
  return out;
}

/** Plain ChaCha20: XOR data with the keystream starting at block `counter`. Encrypt and decrypt are the same. */
export function chacha20(key: Uint8Array, nonce: Uint8Array, counter: number, data: Uint8Array) {
  const out = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i += 64) {
    const ks = chachaBlock(key, counter + i / 64, nonce);
    for (let j = 0; j < 64 && i + j < data.length; j++) out[i + j] = data[i + j] ^ ks[j];
  }
  return out;
}

/** Poly1305 one-time MAC: 16-byte tag of msg under a 32-byte one-time key. */
export function poly1305(otk: Uint8Array, msg: Uint8Array) {
  const B = BigInt; // the project targets ES2017, which has no 123n literals
  const num = (b: Uint8Array) => b.reduceRight((acc, v) => (acc << B(8)) | B(v), B(0)); // little-endian bytes -> number
  const r = num(otk.slice(0, 16)) & B("0x0ffffffc0ffffffc0ffffffc0fffffff"), s = num(otk.slice(16, 32));
  const p = (B(1) << B(130)) - B(5);
  let acc = B(0);
  for (let i = 0; i < msg.length; i += 16) {
    const block = msg.slice(i, i + 16);
    acc = ((acc + num(block) + (B(1) << B(8 * block.length))) * r) % p;
  }
  acc = (acc + s) & ((B(1) << B(128)) - B(1));
  return Uint8Array.from({ length: 16 }, (_, i) => Number((acc >> B(8 * i)) & B(255)));
}

function macData(aad: Uint8Array, ct: Uint8Array) {
  const pad16 = (n: number) => (16 - (n % 16)) % 16;
  const out = new Uint8Array(aad.length + pad16(aad.length) + ct.length + pad16(ct.length) + 16);
  out.set(aad); out.set(ct, aad.length + pad16(aad.length));
  const view = new DataView(out.buffer, out.length - 16);
  view.setBigUint64(0, BigInt(aad.length), true); view.setBigUint64(8, BigInt(ct.length), true);
  return out;
}

/** ChaCha20-Poly1305 (RFC 8439 section 2.8): returns ciphertext + 16-byte tag. */
export function aeadEncrypt(key: Uint8Array, nonce: Uint8Array, pt: Uint8Array, aad = new Uint8Array(0)) {
  const ct = chacha20(key, nonce, 1, pt);
  const tag = poly1305(chachaBlock(key, 0, nonce).slice(0, 32), macData(aad, ct));
  const out = new Uint8Array(ct.length + 16); out.set(ct); out.set(tag, ct.length);
  return out;
}

/** Checks the tag first; throws if the key is wrong or the data was changed. */
export function aeadDecrypt(key: Uint8Array, nonce: Uint8Array, data: Uint8Array, aad = new Uint8Array(0)) {
  if (data.length < 16) throw new Error("too short");
  const ct = data.slice(0, -16), tag = data.slice(-16);
  const want = poly1305(chachaBlock(key, 0, nonce).slice(0, 32), macData(aad, ct));
  if (want.reduce((d, v, i) => d | (v ^ tag[i]), 0)) throw new Error("tag mismatch"); // compare every byte
  return chacha20(key, nonce, 1, ct);
}
