// Symmetric encryption (DES, 3DES, AES, SEED, ARIA, ChaCha20): logic, method configs and test vectors for SymPanel.
import type CryptoJSNs from "crypto-js";
import type forgeNs from "node-forge";
import { bin, cat, dec, enc, fromB64, fromHex, pad, random, toB64, toHex, unbin, unpad } from "@/lib/bytes";
import { seed } from "@/lib/seed";
import { aria } from "@/lib/aria";
import { aeadDecrypt, aeadEncrypt, chacha20 } from "@/lib/chacha";

type Fn = (key: Uint8Array, iv: Uint8Array, data: Uint8Array) => Promise<Uint8Array>;
/** name, key, iv, plaintext, ciphertext (hex) */
export type Vector = [name: string, key: string, iv: string, plain: string, cipher: string];

/** Everything the shared panel needs for one method (+ mode). */
export type SymConfig = {
  ivBytes: number; minData: number; block: number; format: string;
  ivNote: string; warning: string;
  encrypt: Fn; decrypt: Fn; okMsg: string; failMsg: string;
  source: string; vecEnc: Fn; vecDec: Fn; vectors: Vector[];
  modeAbout?: string;
};
export type AesMode = "GCM" | "CBC" | "CTR" | "ECB";
export type SymMethod = SymConfig & {
  id: "des" | "tripledes" | "aes" | "seed" | "aria" | "chacha20"; name: string; keyBytes: number; about: string;
  keySizes?: number[]; modes?: Record<AesMode, SymConfig>; mode?: AesMode;
};

// The libraries load on first use, so a page only downloads what its method needs:
// SEED needs neither, AES-128/256-GCM use the browser's Web Crypto, only AES-192-GCM needs node-forge.
let cjsLib: typeof CryptoJSNs | undefined, forgeLib: typeof forgeNs | undefined;
const loadCjs = async () => (cjsLib ??= (await import("crypto-js")).default);
const loadForge = async () => (forgeLib ??= (await import("node-forge")).default);

const importKey = (raw: Uint8Array) =>
  crypto.subtle.importKey("raw", raw as BufferSource, "AES-GCM", false, ["encrypt", "decrypt"]);
// AES-128/256 use the browser's Web Crypto; AES-192 uses forge because Chrome rejects 192-bit keys.
const gcm = async (mode: "encrypt" | "decrypt", raw: Uint8Array, iv: Uint8Array, data: Uint8Array) => raw.length === 24
  ? forgeGcm(await loadForge(), mode, raw, iv, data)
  : new Uint8Array(await crypto.subtle[mode]({ name: "AES-GCM", iv: iv as BufferSource, tagLength: 128 }, await importKey(raw), data as BufferSource));

function forgeGcm(forge: typeof forgeNs, mode: "encrypt" | "decrypt", raw: Uint8Array, iv: Uint8Array, data: Uint8Array) { // same input/output as Web Crypto: ciphertext + 16-byte tag
  const key = forge.util.createBuffer(bin(raw));
  if (mode === "encrypt") {
    const c = forge.cipher.createCipher("AES-GCM", key);
    c.start({ iv: bin(iv), tagLength: 128 });
    c.update(forge.util.createBuffer(bin(data)));
    c.finish();
    return unbin(c.output.getBytes() + c.mode.tag.getBytes());
  }
  if (data.length < 16) throw new Error("too short");
  const d = forge.cipher.createDecipher("AES-GCM", key);
  d.start({ iv: bin(iv), tagLength: 128, tag: forge.util.createBuffer(bin(data.slice(-16))) });
  d.update(forge.util.createBuffer(bin(data.slice(0, -16))));
  if (!d.finish()) throw new Error("tag mismatch"); // wrong key or changed data
  return unbin(d.output.getBytes());
}

// crypto-js for DES and AES ECB/CBC: raw blocks, no padding. Padding is done by hand
// because crypto-js does not reject bad padding, and Java does.
const wa = (C: typeof CryptoJSNs, b: Uint8Array) => C.enc.Hex.parse(toHex(b));
const unwa = (C: typeof CryptoJSNs, w: CryptoJSNs.lib.WordArray) => fromHex(w.toString(C.enc.Hex));
async function cjs(algo: "DES" | "TripleDES" | "AES", encrypt: boolean, mode: "CBC" | "ECB", key: Uint8Array, iv: Uint8Array | null, data: Uint8Array) {
  const C = await loadCjs(), opts = { mode: C.mode[mode], padding: C.pad.NoPadding, iv: iv ? wa(C, iv) : undefined };
  return unwa(C, encrypt
    ? C[algo].encrypt(wa(C, data), wa(C, key), opts).ciphertext
    : C[algo].decrypt(C.lib.CipherParams.create({ ciphertext: wa(C, data) }), wa(C, key), opts));
}
// DES (SYMMETRIC: one secret key encrypts and decrypts). Inside crypto-js: initial permutation ->
// 16 Feistel rounds (L, R -> R, L XOR F(R, round key); F = expand 32->48 bits, XOR key, 8 S-boxes, permute)
// -> final permutation. Decrypt = same rounds, keys reversed. Broken only because 56 key bits are too few.
// Full explanation: java/des/Des.java
const desRaw = (encrypt: boolean, key: Uint8Array, iv: Uint8Array | null, data: Uint8Array) =>
  cjs("DES", encrypt, iv ? "CBC" : "ECB", key, iv, data); // iv null -> ECB

// AES-CTR by hand on top of ECB: crypto-js only increments the last 32 bits of the counter,
// Java and NIST increment all 128 bits. Encrypt and decrypt are the same operation.
export async function aesCtr(key: Uint8Array, iv: Uint8Array, data: Uint8Array) {
  const blocks = Math.ceil(data.length / 16), counters = new Uint8Array(blocks * 16), c = Uint8Array.from(iv); // copy: never modify the IV
  for (let i = 0; i < blocks; i++) {
    counters.set(c, i * 16);
    for (let j = 15; j >= 0; j--) { c[j] = (c[j] + 1) & 255; if (c[j]) break; } // +1 with carry
  }
  const keystream = await cjs("AES", true, "ECB", key, null, counters);
  return data.map((b, i) => b ^ keystream[i]);
}

const GCM_P64 = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255";
// NIST SP 800-38A appendix F keys and plaintext blocks (same values as java/aes/Aes.java)
const K128 = "2b7e151628aed2a6abf7158809cf4f3c";
const K192 = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
const K256 = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
const P1 = "6bc1bee22e409f96e93d7e117393172a", P2 = "ae2d8a571e03ac9c9eb76fac45af8e51";
const CBC_IV = "000102030405060708090a0b0c0d0e0f", CTR_IV = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
const KEY_WARNING = "Keep the key secret: anyone with it can decrypt. Showing the key on screen is for learning only.";
const PAD_FAIL = "✗ Decryption failed: padding is invalid (usually the wrong key, or a changed last block)";
const RANDOM_IV = (n: number) => `A new random ${n}-byte IV is used each time, so encrypting the same text twice gives different output. Both still decrypt.`;

// AES (SYMMETRIC: one secret key encrypts and decrypts). The block cipher works on a 4x4 grid of bytes;
// each round = SubBytes (S-box, non-linear) -> ShiftRows -> MixColumns -> AddRoundKey (XOR the round key).
// 10 / 12 / 14 rounds for 128 / 192 / 256-bit keys. Not a Feistel network: decrypt runs each step's inverse.
// The block cipher only handles 16 bytes; the MODE chains blocks:
//   ECB c[i] = AES(p[i])   CBC c[i] = AES(p[i] XOR c[i-1])   CTR c[i] = p[i] XOR AES(counter+i)   GCM = CTR + tag
// Full explanation: java/aes/Aes.java
// Each AES mode: everything the shared symmetric panel needs. Order = order in the Mode dropdown.
export const AES_MODES: Record<AesMode, SymConfig> = {
  GCM: {
    ivBytes: 12, minData: 16, block: 1, format: "IV (12 bytes) + ciphertext + tag (16 bytes)",
    modeAbout: "GCM (Galois/Counter Mode, NIST SP 800-38D) encrypts like CTR and adds a 16-byte authentication tag, so decryption fails if the key is wrong or the data was changed. Recommended.",
    ivNote: RANDOM_IV(12),
    warning: "Never reuse an IV with the same key. This page creates a new one every time. " + KEY_WARNING,
    encrypt: (k, iv, d) => gcm("encrypt", k, iv, d),
    decrypt: (k, iv, d) => gcm("decrypt", k, iv, d),
    okMsg: "✓ Decrypted. The tag checks out, so the data is unchanged.",
    failMsg: "✗ Decryption failed: wrong key, or the data was changed",
    source: "NIST GCM spec, all 3 key sizes",
    vecEnc: (k, iv, d) => gcm("encrypt", k, iv, d),
    vecDec: (k, iv, d) => gcm("decrypt", k, iv, d),
    vectors: [ // name, key, iv, plaintext, ciphertext + tag (hex)
      ["AES-128 · test case 1", "0".repeat(32), "0".repeat(24), "", "58e2fccefa7e3061367f1d57a4e7455a"],
      ["AES-128 · test case 2", "0".repeat(32), "0".repeat(24), "0".repeat(32), "0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf"],
      ["AES-128 · test case 3", "feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888", GCM_P64,
        "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f59854d5c2af327cd64a62cf35abd2ba6fab4"],
      ["AES-192 · test case 7", "0".repeat(48), "0".repeat(24), "", "cd33b28ac773f74ba00ed1f312572435"],
      ["AES-192 · test case 8", "0".repeat(48), "0".repeat(24), "0".repeat(32), "98e7247c07f0fe411c267e4384b0f6002ff58d80033927ab8ef4d4587514f0fb"],
      ["AES-192 · test case 9", "feffe9928665731c6d6a8f9467308308feffe9928665731c", "cafebabefacedbaddecaf888", GCM_P64,
        "3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710acade2569924a7c8587336bfb118024db8674a14"],
      ["AES-256 · test case 13", "0".repeat(64), "0".repeat(24), "", "530f8afbc74536b9a963b4f1c4cb738b"],
      ["AES-256 · test case 14", "0".repeat(64), "0".repeat(24), "0".repeat(32), "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919"],
      ["AES-256 · test case 15", "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888", GCM_P64,
        "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015adb094dac5d93471bdec1a502270e3cc6c"],
    ],
  },
  CBC: {
    ivBytes: 16, minData: 16, block: 16, format: "IV (16 bytes) + ciphertext",
    modeAbout: "CBC (Cipher Block Chaining, NIST SP 800-38A) XORs each block with the previous ciphertext block before encrypting it, starting from a random IV. Uses PKCS#7 padding.",
    ivNote: RANDOM_IV(16),
    warning: "No authentication tag: changed data can decrypt to garbage without an error. Prefer GCM, or add an HMAC. " + KEY_WARNING,
    encrypt: async (k, iv, d) => cjs("AES", true, "CBC", k, iv, pad(d, 16)),
    decrypt: async (k, iv, d) => unpad(await cjs("AES", false, "CBC", k, iv, d), 16),
    okMsg: "✓ Decrypted. CBC has no tag, so this does NOT prove the data is unchanged.",
    failMsg: PAD_FAIL,
    source: "NIST SP 800-38A appendix F.2",
    vecEnc: async (k, iv, d) => cjs("AES", true, "CBC", k, iv, d),
    vecDec: async (k, iv, d) => cjs("AES", false, "CBC", k, iv, d),
    vectors: [
      ["AES-128 · F.2.1", K128, CBC_IV, P1 + P2, "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2"],
      ["AES-192 · F.2.3", K192, CBC_IV, P1, "4f021db243bc633d7178183a9fa071e8"],
      ["AES-256 · F.2.5", K256, CBC_IV, P1, "f58c4c04d6e5f1ba779eabfb5f7bfbd6"],
    ],
  },
  CTR: {
    ivBytes: 16, minData: 0, block: 1, format: "counter (16 bytes) + ciphertext",
    modeAbout: "CTR (Counter mode, NIST SP 800-38A) encrypts a counter (random start, +1 per block) and XORs the result with the text, like a stream cipher. No padding: the output is exactly as long as the input.",
    ivNote: "A new random 16-byte starting counter is used each time, so encrypting the same text twice gives different output. Both still decrypt.",
    warning: "No authentication tag, and decryption never fails: a wrong key gives garbage, and flipping one bit of the ciphertext flips the same bit of the text (\"Hello\" → \"Iello\"). Never reuse a counter with the same key. " + KEY_WARNING,
    encrypt: async (k, iv, d) => aesCtr(k, iv, d),
    decrypt: async (k, iv, d) => aesCtr(k, iv, d),
    okMsg: "✓ Decrypted. CTR has no tag and never fails: with a wrong key this is garbage.",
    failMsg: "✗ Decryption failed",
    source: "NIST SP 800-38A appendix F.5",
    vecEnc: async (k, iv, d) => aesCtr(k, iv, d),
    vecDec: async (k, iv, d) => aesCtr(k, iv, d),
    vectors: [
      ["AES-128 · F.5.1", K128, CTR_IV, P1 + P2, "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff"],
      ["AES-192 · F.5.3", K192, CTR_IV, P1, "1abc932417521ca24f2b0459fe7e6e0b"],
      ["AES-256 · F.5.5", K256, CTR_IV, P1, "601ec313775789a5b7a7f504bbf3d228"],
    ],
  },
  ECB: {
    ivBytes: 0, minData: 16, block: 16, format: "ciphertext (ECB has no IV)",
    modeAbout: "ECB (Electronic Codebook, NIST SP 800-38A) encrypts each 16-byte block on its own with the same key. Uses PKCS#7 padding.",
    ivNote: "No IV: encrypting the same text twice gives the SAME output. Click Encrypt twice to see it.",
    warning: "⚠ ECB is insecure: equal 16-byte plaintext blocks give equal ciphertext blocks, so patterns in the data leak (the famous \"ECB penguin\"). Learning only. Use GCM. " + KEY_WARNING,
    encrypt: async (k, iv, d) => cjs("AES", true, "ECB", k, null, pad(d, 16)),
    decrypt: async (k, iv, d) => unpad(await cjs("AES", false, "ECB", k, null, d), 16),
    okMsg: "✓ Decrypted. ECB has no tag, so this does NOT prove the data is unchanged.",
    failMsg: PAD_FAIL,
    source: "NIST SP 800-38A appendix F.1",
    vecEnc: async (k, iv, d) => cjs("AES", true, "ECB", k, null, d),
    vecDec: async (k, iv, d) => cjs("AES", false, "ECB", k, null, d),
    vectors: [
      ["AES-128 · F.1.1", K128, "", P1 + P2, "3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf"],
      ["AES-192 · F.1.3", K192, "", P1, "bd334f1d6e45f25ff712a214571fa5cc"],
      ["AES-256 · F.1.5", K256, "", P1, "f3eed1bdb5d2a03c064b5a7e3db181f8"],
    ],
  },
};

// To add a symmetric method: add one entry. Output format = Base64( IV + ciphertext ), same as the Java files.
export const SYM_METHODS: Record<SymMethod["id"], SymMethod> = {
  des: {
    id: "des", name: "DES", keyBytes: 8, ivBytes: 8, minData: 8, block: 8,
    about: "DES (Data Encryption Standard, FIPS 46-3, 1977) encrypts 8-byte blocks with a 64-bit key, of which only 56 bits are used (the rest are parity bits). Here: CBC mode with PKCS#5 padding and a random IV. Java: java/des/Des.java",
    format: "IV (8 bytes) + ciphertext",
    warning: "⚠ DES is broken: its 56-bit key can be brute-forced in hours, and it was withdrawn in 2005. It also has no authentication tag: change one bit of the IV and \"Hello\" decrypts to \"Iello\" with no error. Learning only. Use AES-GCM instead.",
    ivNote: RANDOM_IV(8),
    encrypt: async (k, iv, d) => desRaw(true, k, iv, pad(d, 8)),
    decrypt: async (k, iv, d) => unpad(await desRaw(false, k, iv, d), 8),
    okMsg: "✓ Decrypted. DES has no tag, so this does NOT prove the data is unchanged.",
    failMsg: "✗ Decryption failed: padding is invalid (usually the wrong key, or a changed last block)",
    source: "classic single-block DES vectors, ECB",
    vecEnc: async (k, iv, d) => desRaw(true, k, null, d),
    vecDec: async (k, iv, d) => desRaw(false, k, null, d),
    vectors: [ // name, key, iv (unused), plaintext, ciphertext (hex)
      ["Textbook worked example", "133457799bbcdff1", "", "0123456789abcdef", "85e813540f0ab405"],
      ["FIPS 81 \"Now is t\"", "0123456789abcdef", "", "4e6f772069732074", "3fa40e8a984d4815"],
      ["All zeros", "0000000000000000", "", "0000000000000000", "8ca64de9c1b123a7"],
      ["All ones", "ffffffffffffffff", "", "ffffffffffffffff", "7359b2163e4edc58"],
    ],
  },
  // 3DES (SYMMETRIC: one 24-byte key K1|K2|K3 encrypts and decrypts). DES three times per block:
  //   encrypt c = E_K3(D_K2(E_K1(p)))   decrypt p = D_K1(E_K2(D_K3(c)))
  // The middle DEcrypt (EDE) makes K1 = K2 = K3 equal to single DES, for compatibility.
  // 168 key bits but ~112 bits of strength (meet-in-the-middle). Retired: 8-byte block (Sweet32), slow.
  // Full explanation: java/tripledes/TripleDes.java
  tripledes: {
    id: "tripledes", name: "3DES", keyBytes: 24, ivBytes: 8, minData: 8, block: 8,
    about: "Triple DES (3DES / TDEA, NIST SP 800-67) runs DES three times on each 8-byte block: encrypt with K1, decrypt with K2, encrypt with K3. The 24-byte key is K1|K2|K3 (168 bits, about 112 bits of real strength). With K1 = K2 = K3 it is exactly single DES. Here: CBC mode with PKCS#5 padding and a random IV. Java: java/tripledes/TripleDes.java",
    format: "IV (8 bytes) + ciphertext",
    warning: "⚠ 3DES is deprecated: NIST disallowed it for encryption after 2023. Its 8-byte block lets attackers recover data after about 32 GB under one key (Sweet32), and it is slow. No authentication tag. Learning only. Use AES-GCM instead.",
    ivNote: RANDOM_IV(8),
    encrypt: async (k, iv, d) => cjs("TripleDES", true, "CBC", k, iv, pad(d, 8)),
    decrypt: async (k, iv, d) => unpad(await cjs("TripleDES", false, "CBC", k, iv, d), 8),
    okMsg: "✓ Decrypted. 3DES has no tag, so this does NOT prove the data is unchanged.",
    failMsg: PAD_FAIL,
    source: "NIST SP 800-67 sample and DES-compatible keys, ECB",
    vecEnc: async (k, iv, d) => cjs("TripleDES", true, "ECB", k, null, d),
    vecDec: async (k, iv, d) => cjs("TripleDES", false, "ECB", k, null, d),
    vectors: [ // name, key (K1|K2|K3), iv (unused), plaintext, ciphertext (hex)
      ["SP 800-67 \"The qufck brown fox jump\"", "0123456789abcdef23456789abcdef01456789abcdef0123", "",
        "54686520717566636b2062726f776e20666f78206a756d70", "a826fd8ce53b855fcce21c8112256fe668d5c05dd9b6b900"],
      ["K1 = K2 = K3 → same as DES \"Now is t\"", "0123456789abcdef".repeat(3), "", "4e6f772069732074", "3fa40e8a984d4815"],
      ["All zeros", "0".repeat(48), "", "0000000000000000", "8ca64de9c1b123a7"],
    ],
  },
  aes: {
    id: "aes", name: "AES", keyBytes: 32, keySizes: [16, 24, 32],
    modes: AES_MODES, mode: "GCM", ...AES_MODES.GCM,
    about: "AES (Advanced Encryption Standard, FIPS 197) encrypts 16-byte blocks with a 128, 192 or 256-bit key (10, 12 or 14 rounds). All three key sizes are secure today; 256 has the biggest safety margin. The mode decides how blocks are chained. Java: java/aes/Aes.java",
  },
  // SEED (RFC 4269): 16-round Feistel on 16-byte blocks, 16-byte key. Hand-written in src/lib/seed.ts.
  seed: {
    id: "seed", name: "SEED", keyBytes: 16, ivBytes: 16, minData: 16, block: 16,
    about: "SEED (KISA, 1998; RFC 4269) is South Korea's national block cipher: a 16-round Feistel network on 16-byte blocks with a 128-bit key, built to give Korean banking and e-commerce a strong 128-bit cipher. Here: CBC mode with PKCS#7 padding and a random IV. Neither the browser nor Java ships SEED, so both sides implement it by hand. Java: java/seed/Seed.java",
    format: "IV (16 bytes) + ciphertext",
    warning: "SEED has no known practical attack, but it is a regional standard with little support outside Korea, and this CBC mode has no authentication tag. Use AES-GCM unless you must talk to a system that requires SEED. " + KEY_WARNING,
    ivNote: RANDOM_IV(16),
    encrypt: async (k, iv, d) => seed(true, k, iv, pad(d, 16)),
    decrypt: async (k, iv, d) => unpad(seed(false, k, iv, d), 16),
    okMsg: "✓ Decrypted. CBC has no tag, so this does NOT prove the data is unchanged.",
    failMsg: PAD_FAIL,
    source: "RFC 4269 appendix B, ECB",
    vecEnc: async (k, iv, d) => seed(true, k, null, d),
    vecDec: async (k, iv, d) => seed(false, k, null, d),
    vectors: [ // name, key, iv (unused), plaintext, ciphertext (hex)
      ["RFC 4269 B.1", "0".repeat(32), "", "000102030405060708090a0b0c0d0e0f", "5ebac6e0054e166819aff1cc6d346cdb"],
      ["RFC 4269 B.2", "000102030405060708090a0b0c0d0e0f", "", "0".repeat(32), "c11f22f20140505084483597e4370f43"],
      ["RFC 4269 B.3", "4706480851e61be85d74bfb3fd956185", "", "83a2f8a288641fb9a4e9a5cc2f131c7d", "ee54d13ebcae706d226bc3142cd40d4a"],
      ["RFC 4269 B.4", "28dbc3bc49ffd87dcfa509b11d422be7", "", "b41e6be2eba84a148e2eed84593c5ec7", "9b9b7bfcd1813cb95d0b3618f40f5122"],
    ],
  },
  // ARIA (RFC 5794, Korean standard KS X 1213): SPN cipher on 16-byte blocks, 12/14/16 rounds. Hand-written in src/lib/aria.ts.
  aria: {
    id: "aria", name: "ARIA", keyBytes: 16, keySizes: [16, 24, 32], ivBytes: 16, minData: 16, block: 16,
    about: "ARIA (NSRI, 2004; RFC 5794; Korean standard KS X 1213) is South Korea's second national block cipher: 16-byte blocks like AES, with a 128, 192 or 256-bit key (12, 14 or 16 rounds). Korean public-sector and financial systems use it next to SEED and AES. Here: CBC mode with PKCS#7 padding and a random IV. Neither the browser nor plain Java ships ARIA, so both sides implement it by hand. Java: java/aria/Aria.java",
    format: "IV (16 bytes) + ciphertext",
    warning: "ARIA has no known practical attack, but this CBC mode has no authentication tag: changed data can decrypt to garbage without an error. Outside Korea, AES-GCM is the usual choice. " + KEY_WARNING,
    ivNote: RANDOM_IV(16),
    encrypt: async (k, iv, d) => aria(true, k, iv, pad(d, 16)),
    decrypt: async (k, iv, d) => unpad(aria(false, k, iv, d), 16),
    okMsg: "✓ Decrypted. CBC has no tag, so this does NOT prove the data is unchanged.",
    failMsg: PAD_FAIL,
    source: "RFC 5794 appendix A, ECB",
    vecEnc: async (k, iv, d) => aria(true, k, null, d),
    vecDec: async (k, iv, d) => aria(false, k, null, d),
    vectors: [ // name, key, iv (unused), plaintext, ciphertext (hex)
      ["RFC 5794 A.1 (128-bit key)", "000102030405060708090a0b0c0d0e0f", "", "00112233445566778899aabbccddeeff", "d718fbd6ab644c739da95f3be6451778"],
      ["RFC 5794 A.2 (192-bit key)", "000102030405060708090a0b0c0d0e0f1011121314151617", "", "00112233445566778899aabbccddeeff", "26449c1805dbe7aa25a468ce263a9e79"],
      ["RFC 5794 A.3 (256-bit key)", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "", "00112233445566778899aabbccddeeff", "f92bd7c79fb72e2f2b8f80c1972d24fc"],
    ],
  },
  // ChaCha20-Poly1305 (RFC 8439): a stream cipher + a tag, hand-written in src/lib/chacha.ts.
  // Test vectors use plain ChaCha20; their "iv" = 4-byte block counter (little-endian) + 12-byte nonce, like OpenSSL.
  chacha20: {
    id: "chacha20", name: "ChaCha20", keyBytes: 32, ivBytes: 12, minData: 16, block: 1,
    about: "ChaCha20 (Daniel J. Bernstein, 2008; RFC 8439) is a stream cipher: it turns a 256-bit key, a 12-byte nonce and a block counter into a stream of random-looking bytes, and XORs it with the text. 20 rounds of add, rotate and XOR. Poly1305 adds a 16-byte tag, so a wrong key or changed data is detected. It is fast without special hardware, so phones and TLS 1.3 use it. Java: java/chacha20/ChaCha20.java",
    format: "nonce (12 bytes) + ciphertext + tag (16 bytes)",
    warning: "Never reuse a nonce with the same key: two messages would share a keystream, and XORing them cancels it out. This page makes a new one every time. " + KEY_WARNING,
    ivNote: "A new random 12-byte nonce is used each time, so encrypting the same text twice gives different output. Both still decrypt.",
    encrypt: async (k, iv, d) => aeadEncrypt(k, iv, d),
    decrypt: async (k, iv, d) => aeadDecrypt(k, iv, d),
    okMsg: "✓ Decrypted. The Poly1305 tag checks out, so the data is unchanged.",
    failMsg: "✗ Decryption failed: wrong key, or the data was changed",
    source: "RFC 8439, plain ChaCha20",
    vecEnc: async (k, iv, d) => chacha20(k, iv.slice(4), new DataView(iv.buffer, iv.byteOffset).getUint32(0, true), d),
    vecDec: async (k, iv, d) => chacha20(k, iv.slice(4), new DataView(iv.buffer, iv.byteOffset).getUint32(0, true), d),
    vectors: [ // name, key, counter + nonce, plaintext, ciphertext (hex)
      ["RFC 8439 2.4.2 \"sunscreen\"", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "01000000000000000000004a00000000",
        "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
        "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d"],
      ["RFC 8439 A.2 #1 (all zeros)", "0".repeat(64), "0".repeat(32), "0".repeat(128),
        "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586"],
    ],
  },
};

/** The method with the chosen AES mode applied (other methods ignore mode). */
export const symConfig = (m: SymMethod, mode?: AesMode): SymMethod =>
  m.modes && mode ? { ...m, mode, ...m.modes[mode] } : m;

/** Hex key -> bytes, or null if it is not exactly keyBytes bytes. */
export function parseKey(hex: string, keyBytes: number) {
  const k = hex.trim().toLowerCase();
  return new RegExp(`^[0-9a-f]{${keyBytes * 2}}$`).test(k) ? fromHex(k) : null;
}
export const keyMessage = (ok: boolean, keyBytes: number) =>
  ok ? `✓ Valid ${keyBytes * 8}-bit key` : `Key must be exactly ${keyBytes * 2} hex chars (0-9, a-f). Click Generate key.`;
export const newKey = (keyBytes: number) => toHex(random(keyBytes));

/** Base64( IV + ciphertext [+ tag] ), with a fresh IV every time. */
export async function encryptText(m: SymConfig, key: Uint8Array, text: string) {
  const iv = random(m.ivBytes);
  return toB64(cat(iv, await m.encrypt(key, iv, enc(text))));
}

/** Decrypts Base64 input; returns the result line and the text. */
export async function decryptText(m: SymMethod, key: Uint8Array, b64: string): Promise<{ ok: boolean; text: string; plain: string }> {
  let all: Uint8Array | null;
  try { all = fromB64(b64); } catch { all = null; }
  const min = m.ivBytes + m.minData;
  if (!all || all.length < min || (all.length - m.ivBytes) % m.block)
    return { ok: false, text: `✗ Not valid ${m.name} data (Base64 of ${m.format}, at least ${min} bytes)`, plain: "" };
  try {
    const pt = await m.decrypt(key, all.slice(0, m.ivBytes), all.slice(m.ivBytes));
    return { ok: true, text: m.okMsg, plain: dec(pt) };
  } catch {
    return { ok: false, text: m.failMsg, plain: "" };
  }
}

/** One test vector: encrypt must give the expected ciphertext and decrypt must give the plaintext back. */
export async function runVector(m: SymConfig, [, k, iv, pt, expected]: Vector) {
  const e = toHex(await m.vecEnc(fromHex(k), fromHex(iv), fromHex(pt)));
  const d = toHex(await m.vecDec(fromHex(k), fromHex(iv), fromHex(expected)));
  return e === expected && d === pt;
}
export const vectorName = ([name, , , pt]: Vector) =>
  `${/^\d+$/.test(name) ? "Test case " + name : name} (${pt.length / 2} bytes, encrypt + decrypt)`;
