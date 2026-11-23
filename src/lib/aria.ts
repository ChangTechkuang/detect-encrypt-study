// ARIA block cipher (RFC 5794, Korean standard KS X 1213), written by hand: browsers don't have it.
// SYMMETRIC: one key (16, 24 or 32 bytes) encrypts and decrypts. 16-byte blocks like AES and SEED.
// Each round: XOR the round key -> substitution layer (4 S-boxes) -> diffusion layer A (mixes the 16 bytes).
// 12 / 14 / 16 rounds for 128 / 192 / 256-bit keys. Decryption = the same rounds with decryption keys.
// S-boxes copied from RFC 5794 section 2.4.2 by script (SB1 is the AES S-box); SB3/SB4 are their inverses.

const SB1_HEX = "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b27509832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cfd0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdbe0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9ee1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16";
const SB2_HEX = "e24e54fc94c24acc620d6a463c4d8bd15efa64cbb497be2bbc772e03d31959c11d06416b55f09969ea9c18ae63dfe7bb007366fb964c85e43a0945aa0fee10eb2d7ff429accfad918d78c895f92fcecd087a88385c832a2847dbb8c793a41253ff870e3136215848018e377432cae9b1b7ab0cd7c4564226079860d9b6b91140ec208cbda0c984044923f14f501f13dcd8c09e57e3c37b653b028f3ee82592e515ddfd17a9bfd49a7ec53967fe769d43a7e1d0f568f21b347005a38ad57986a830c6514b1ea627f635d26e2416825fdae675a2ef2cb21c9f5d6f800a72449b6c900b5b337d5a52f361a1f7b0d63f7c6ded14e0a53d22b3f889de711aafbab581";

const fromHex = (h: string) => Uint8Array.from(h.match(/../g)!, (x) => parseInt(x, 16));
const inverse = (s: Uint8Array) => { const r = new Uint8Array(256); s.forEach((v, i) => (r[v] = i)); return r; };
const SB1 = fromHex(SB1_HEX), SB2 = fromHex(SB2_HEX), SB3 = inverse(SB1), SB4 = inverse(SB2);
const C = ["517cc1b727220a94fe13abe8fa9a6ee0", "6db14acc9e21c820ff28b1d5ef5de2b0", "db92371d2126e9700324977504e8c90e"].map(fromHex); // 1/π

type Block = Uint8Array;
const xor = (a: Block, b: Block) => a.map((v, i) => v ^ b[i]);
const SL1 = (x: Block) => x.map((v, i) => [SB1, SB2, SB3, SB4][i % 4][v]); // odd rounds
const SL2 = (x: Block) => x.map((v, i) => [SB3, SB4, SB1, SB2][i % 4][v]); // even rounds
// Diffusion layer A (RFC 5794 2.4.3): output byte i = XOR of these 7 input bytes. A(A(x)) = x.
const A_ROWS = [[3, 4, 6, 8, 9, 13, 14], [2, 5, 7, 8, 9, 12, 15], [1, 4, 6, 10, 11, 12, 15], [0, 5, 7, 10, 11, 13, 14],
  [0, 2, 5, 8, 11, 14, 15], [1, 3, 4, 9, 10, 14, 15], [0, 2, 7, 9, 10, 12, 13], [1, 3, 6, 8, 11, 12, 13],
  [0, 1, 4, 7, 10, 13, 15], [0, 1, 5, 6, 11, 12, 14], [2, 3, 5, 6, 8, 13, 15], [2, 3, 4, 7, 9, 12, 14],
  [1, 2, 6, 7, 9, 11, 12], [0, 3, 6, 7, 8, 10, 13], [0, 3, 4, 5, 9, 11, 14], [1, 2, 4, 5, 8, 10, 15]];
const A = (x: Block) => Uint8Array.from(A_ROWS, (row) => row.reduce((acc, j) => acc ^ x[j], 0));
const FO = (d: Block, rk: Block) => A(SL1(xor(d, rk)));
const FE = (d: Block, rk: Block) => A(SL2(xor(d, rk)));

/** Rotate a 128-bit value (16 bytes, big-endian) right by n bits. Left by n = right by 128 - n. */
function rotr(x: Block, n: number) {
  const q = n >> 3, r = n & 7, out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[i] = ((x[(i - q + 16) % 16] >>> r) | (x[(i - q + 15) % 16] << (8 - r))) & 255;
  return out;
}
const rotl = (x: Block, n: number) => rotr(x, 128 - n);

/** Key schedule: encryption round keys ek1..ek{n+1} (n = 12/14/16 rounds). */
function encKeys(key: Uint8Array) {
  const bits = key.length * 8;
  const KL = key.slice(0, 16), KR = new Uint8Array(16); KR.set(key.slice(16));
  const [CK1, CK2, CK3] = bits === 128 ? [C[0], C[1], C[2]] : bits === 192 ? [C[1], C[2], C[0]] : [C[2], C[0], C[1]];
  const W0 = KL, W1 = xor(FO(W0, CK1), KR), W2 = xor(FE(W1, CK2), W0), W3 = xor(FO(W2, CK3), W1);
  const ek = [
    xor(W0, rotr(W1, 19)), xor(W1, rotr(W2, 19)), xor(W2, rotr(W3, 19)), xor(rotr(W0, 19), W3),
    xor(W0, rotr(W1, 31)), xor(W1, rotr(W2, 31)), xor(W2, rotr(W3, 31)), xor(rotr(W0, 31), W3),
    xor(W0, rotl(W1, 61)), xor(W1, rotl(W2, 61)), xor(W2, rotl(W3, 61)), xor(rotl(W0, 61), W3),
    xor(W0, rotl(W1, 31)), xor(W1, rotl(W2, 31)), xor(W2, rotl(W3, 31)), xor(rotl(W0, 31), W3),
    xor(W0, rotl(W1, 19)),
  ];
  return ek.slice(0, { 128: 12, 192: 14, 256: 16 }[bits]! + 1);
}

/** Decryption keys: dk1 = ek{n+1}, dk{i} = A(ek{n+2-i}), dk{n+1} = ek1. */
function decKeys(ek: Block[]) {
  const n = ek.length - 1;
  return ek.map((_, i) => (i === 0 ? ek[n] : i === n ? ek[0] : A(ek[n - i])));
}

/** One 16-byte block: odd rounds FO, even rounds FE, last round SL2 + an extra key. */
function block(keys: Block[], p: Block) {
  const n = keys.length - 1;
  for (let i = 0; i < n - 1; i++) p = i % 2 === 0 ? FO(p, keys[i]) : FE(p, keys[i]);
  return xor(SL2(xor(p, keys[n - 1])), keys[n]);
}

/** ECB if iv is null, else CBC. data must be a whole number of 16-byte blocks. Same shape as seed() in seed.ts. */
export function aria(encrypt: boolean, key: Uint8Array, iv: Uint8Array | null, data: Uint8Array) {
  if (![16, 24, 32].includes(key.length)) throw new Error("ARIA key must be 16, 24 or 32 bytes");
  const ek = encKeys(key), keys = encrypt ? ek : decKeys(ek);
  const out = new Uint8Array(data.length);
  let prev = iv ? iv.slice() : null;
  for (let o = 0; o < data.length; o += 16) {
    const inp = data.slice(o, o + 16);
    if (encrypt) {
      const c = block(keys, prev ? xor(inp, prev) : inp);
      out.set(c, o); if (prev) prev = c;
    } else {
      const p = block(keys, inp);
      out.set(prev ? xor(p, prev) : p, o); if (prev) prev = inp;
    }
  }
  return out;
}
