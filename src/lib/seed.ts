// SEED block cipher (RFC 4269), written by hand: no library has it. Same code as java/seed/Seed.java.
// SYMMETRIC: one 16-byte key encrypts and decrypts (same round keys, reverse order).
// S-boxes S1/S2 swap bytes -> G mixes 4 S-box bytes -> F mixes a 64-bit half with a round key (3 x G)
// -> 16 Feistel rounds: L, R -> R, L XOR F(R, roundKey). XOR undoes itself, so F is never reversed.

const S1 = "a985d6d3541dac255d43181e51fcca632844209de0e2c817a58f037bbb13d2ee708c3fa832ddf674ec950b575c5bbd01241c739810ccf2d92ce772839bd186c96050a3eb0db69e4fb75ac678a612afd561c3b441527d8d081f9900190453f7e1fd762f27b08b0eaba26e934d697c090abfeff3c58714fe64de2e4b1a06216b6602f5928a0cb37ed07a4796e52680addfa13037ae36152238f4a7454c81e9849735cbce3c7111c78975fbdaf8945982c4ff493967c0cfd7b80f8e4223916cdba434f148c26f3d2d40be3ebcc1aaba4e553bdc687f9cd84a5677a0ed46b52b65fae3b9b19f5ef9e6b231ea6d5fe4f0cd88163a58d462290733e81b0579906a2a9a";
const S2 = "38e82da6cfdeb3b8af6055c7446f6b5bc36233b529a0e2a7d39111061cbc364bef886ca817c416f4c245e1d63f3d8e98284ef63ea5f90ddfd82b667a272ff17242d441c07367ac8bf7ad801fca2caa34d20beee95d9418f857ae08c513cd86b9ff7dc131f58a6ab1d120d7022204687107db9d9961bee659dd5190dc9aa3abd0810f471ae3ec8dbf967b5ca2a163234dc89e9c3a0c2eba6e9f5af292f34978cc15fb70757f351003646dc674d5b4ea097619fe4012e0bd05fa01f02a5ea956438514899bb0e5487997fc1e82218c1b5f7754b21d254f0046ed5852eb7edac9fd3095653cb6e4bb7c0e5039263284699337e724a4cb530a87d94c838fce3b4ab7";

const s1 = S1.match(/../g)!.map((h) => parseInt(h, 16));
const s2 = S2.match(/../g)!.map((h) => parseInt(h, 16));
const M = [0xfc, 0xf3, 0xcf, 0x3f];
const SS = [s1, s2, s1, s2].map((s, b) => s.map((v) =>
  ((v & M[(b + 3) % 4]) << 24 | (v & M[(b + 2) % 4]) << 16 | (v & M[(b + 1) % 4]) << 8 | (v & M[b])) >>> 0));
const G = (x: number) => (SS[0][x & 255] ^ SS[1][(x >>> 8) & 255] ^ SS[2][(x >>> 16) & 255] ^ SS[3][x >>> 24]) >>> 0;
const words = (b: Uint8Array) => [0, 4, 8, 12].map((i) => (b[i] << 24 | b[i + 1] << 16 | b[i + 2] << 8 | b[i + 3]) >>> 0);

/** Key schedule: the one secret key -> 16 rounds x 2 subkeys. Encrypt and decrypt share them. */
function keys(key: Uint8Array) {
  let [k0, k1, k2, k3] = words(key);
  const out: number[] = [];
  for (let i = 0; i < 16; i++) {
    const kc = (0x9e3779b9 << i | 0x9e3779b9 >>> (32 - i)) >>> 0; // golden ratio rotated left i
    out.push(G((k0 + k2 - kc) >>> 0), G((k1 - k3 + kc) >>> 0));
    if (i % 2 === 0) [k0, k1] = [(k0 >>> 8 | k1 << 24) >>> 0, (k1 >>> 8 | k0 << 24) >>> 0]; // K0||K1 >>> 8
    else [k2, k3] = [(k2 << 8 | k3 >>> 24) >>> 0, (k3 << 8 | k2 >>> 24) >>> 0];             // K2||K3 <<< 8
  }
  return out;
}

/** One 16-byte block through 16 Feistel rounds. */
function block(k: number[], encrypt: boolean, b: Uint8Array) {
  let [l0, l1, r0, r1] = words(b); // L = l0|l1, R = r0|r1
  for (let i = 0; i < 16; i++) {
    const j = 2 * (encrypt ? i : 15 - i); // decrypt: same keys, reverse order
    let c = (r0 ^ k[j]) >>> 0, d = (r1 ^ k[j + 1]) >>> 0;                        // mix R with the round key
    d = G(c ^ d); c = G((c + d) >>> 0); d = G((d + c) >>> 0); c = (c + d) >>> 0; // round function F: 3 x G
    [l0, l1, r0, r1] = [r0, r1, (l0 ^ c) >>> 0, (l1 ^ d) >>> 0];                 // L, R -> R, L XOR F(R)
  }
  const out = new Uint8Array(16);
  [r0, r1, l0, l1].forEach((w, i) => out.set([w >>> 24, (w >>> 16) & 255, (w >>> 8) & 255, w & 255], 4 * i)); // undo last swap
  return out;
}

/**
 * ECB if iv is null, else CBC. data must be a whole number of 16-byte blocks (pad it first).
 * CBC: each block is XORed with the previous ciphertext block (IV first), so equal text blocks differ.
 */
export function seed(encrypt: boolean, key: Uint8Array, iv: Uint8Array | null, data: Uint8Array) {
  const k = keys(key), out = new Uint8Array(data.length);
  let prev = iv ? Uint8Array.from(iv) : null;
  for (let o = 0; o < data.length; o += 16) {
    const inp = data.slice(o, o + 16);
    if (encrypt) {
      if (prev) inp.forEach((_, i) => (inp[i] ^= prev![i]));
      const c = block(k, true, inp);
      out.set(c, o);
      if (prev) prev = c;
    } else {
      const p = block(k, false, inp);
      if (prev) { p.forEach((_, i) => (p[i] ^= prev![i])); prev = inp; }
      out.set(p, o);
    }
  }
  return out;
}
