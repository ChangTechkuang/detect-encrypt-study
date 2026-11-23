// HASHING, not encryption: no key and no way back. Any input -> fixed-size output; verify = hash again
// and compare. MD5 and SHA-256 both pad the input (bit 1, zeros, length), then chain a state through
// each 64-byte block (Merkle-Damgard): MD5 = 4 words x 64 steps, SHA-256 = 8 words x 64 rounds.
// MD5 collisions can be made in seconds (broken); SHA-256 has none known.
// SHA-1 = MD5's successor: 5 words x 80 steps, a 160-bit hash. Broken since 2017 (SHAttered collision).
// SHA-512 = the same design as SHA-256 with 64-bit words, 128-byte blocks and 80 rounds: a 512-bit hash.
// To add a method: add one entry here. hash() returns a Promise of lowercase hex.
import SparkMD5 from "spark-md5";
import { enc, toHex } from "../bytes";

export type HashMethod = {
  id: "md5" | "sha1" | "sha256" | "sha512";
  name: string;
  bits: number;
  about: string;
  warning: string;
  hash: (s: string) => Promise<string>;
  source: string;
  vectors: [input: string, expected: string][];
};

export const METHODS: HashMethod[] = [
  {
    id: "md5", name: "MD5", bits: 128,
    about: "MD5 (Message-Digest Algorithm 5) produces a 128-bit hash. Defined in RFC 1321.",
    warning: "MD5 is broken for security: collisions can be made on purpose. Use it only for checksums. Never for passwords.",
    hash: async (s) => SparkMD5.hash(s), // UTF-8 aware
    source: "RFC 1321, appendix A.5",
    vectors: [
      ["", "d41d8cd98f00b204e9800998ecf8427e"],
      ["a", "0cc175b9c0f1b6a831c399e269772661"],
      ["abc", "900150983cd24fb0d6963f7d28e17f72"],
      ["message digest", "f96b697d7cb7938d525a2f31aaf161d0"],
      ["abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b"],
      ["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "d174ab98d277d9f5a5611c2c9f419d9f"],
      ["1234567890".repeat(8), "57edf4a22be3c955ac49da2e2107b67a"],
    ],
  },
  {
    id: "sha1", name: "SHA-1", bits: 160,
    about: "SHA-1 (Secure Hash Algorithm 1) produces a 160-bit hash. Defined in NIST FIPS 180-4. Designed by the NSA in 1995 as MD5's successor.",
    warning: "SHA-1 is broken for security: Google made two different PDFs with the same SHA-1 in 2017 (SHAttered). Browsers stopped trusting SHA-1 certificates. Use SHA-256 instead. Git still uses it to name objects, with extra collision checks.",
    hash: async (s) => toHex(await crypto.subtle.digest("SHA-1", enc(s))),
    source: "NIST FIPS 180-2 examples",
    vectors: [
      ["", "da39a3ee5e6b4b0d3255bfef95601890afd80709"],
      ["abc", "a9993e364706816aba3e25717850c26c9cd0d89d"],
      ["abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "84983e441c3bd26ebaae4aa1f95129e5e54670f1"],
      ["a".repeat(1_000_000), "34aa973cd4c4daa4f61eeb2bdbad27316534016f"],
    ],
  },
  {
    id: "sha256", name: "SHA-256", bits: 256,
    about: "SHA-256 (SHA-2 family) produces a 256-bit hash. Defined in NIST FIPS 180-4. Still secure for integrity checks.",
    warning: "SHA-256 is secure for fingerprints and integrity, but too fast for passwords on its own. Use bcrypt, Argon2 or PBKDF2 for passwords.",
    hash: async (s) => toHex(await crypto.subtle.digest("SHA-256", enc(s))),
    source: "NIST FIPS 180-2 examples",
    vectors: [
      ["", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
      ["abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"],
      ["abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"],
      ["a".repeat(1_000_000), "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"],
    ],
  },
  {
    id: "sha512", name: "SHA-512", bits: 512,
    about: "SHA-512 (SHA-2 family) produces a 512-bit hash. Same design as SHA-256, but with 64-bit words, 128-byte blocks and 80 rounds. Defined in NIST FIPS 180-4.",
    warning: "SHA-512 is secure for fingerprints and integrity (and often faster than SHA-256 on 64-bit computers), but too fast for passwords on its own. Use bcrypt, Argon2 or PBKDF2 for passwords.",
    hash: async (s) => toHex(await crypto.subtle.digest("SHA-512", enc(s))),
    source: "NIST FIPS 180-2 examples",
    vectors: [
      ["", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"],
      ["abc", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"],
      ["abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"],
      ["a".repeat(1_000_000), "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"],
    ],
  },
];

export const byId = (id: HashMethod["id"]) => METHODS.find((m) => m.id === id)!;

export type VerifyResult = { ok: boolean; text: string } | null;

const invalid = (s: string) => ({ ok: false, text: `✗ Not a valid hash (${s.length} characters). Expected ` +
  METHODS.map((m) => `${m.bits / 4} hex chars (${m.name})`).join(" or ") });

/** Hash only, no text: which method its length and characters fit. Can't prove which text it came from. */
export function hashFormat(storedRaw: string): VerifyResult {
  const stored = storedRaw.trim().toLowerCase();
  const m = METHODS.find((x) => stored.length === x.bits / 4);
  if (!/^[0-9a-f]+$/.test(stored) || !m) return invalid(stored);
  return { ok: true, text: `✓ Valid ${m.name} format: ${stored.length} hex characters = ${m.bits} bits. To check which text it belongs to, type the text and press Verify again.` };
}

/** Detect method(s) by hash length (MD5 = 32 hex, SHA-1 = 40 hex, SHA-256 = 64 hex, SHA-512 = 128 hex), hash the input again and compare. */
export async function verifyHash(input: string, storedRaw: string): Promise<VerifyResult> {
  const stored = storedRaw.trim().toLowerCase();
  if (!stored) return null;
  const candidates = METHODS.filter((m) => stored.length === m.bits / 4);
  if (!/^[0-9a-f]+$/.test(stored) || !candidates.length) return invalid(stored);
  let found: HashMethod | null = null;
  for (const m of candidates) if ((await m.hash(input)) === stored) { found = m; break; }
  const names = candidates.map((m) => m.name).join(" / ");
  return found
    ? { ok: true, text: `✓ Match (${found.name}): input is the original` }
    : { ok: false, text: `✗ No match (${names}): input was changed, even one character or space differs` };
}
