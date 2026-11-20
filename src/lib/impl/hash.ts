// HASHING, not encryption: no key and no way back. Any input -> fixed-size output; verify = hash again
// and compare. MD5 and SHA-256 both pad the input (bit 1, zeros, length), then chain a state through
// each 64-byte block (Merkle-Damgard): MD5 = 4 words x 64 steps, SHA-256 = 8 words x 64 rounds.
// MD5 collisions can be made in seconds (broken); SHA-256 has none known.
// To add a method: add one entry here. hash() returns a Promise of lowercase hex.
import SparkMD5 from "spark-md5";
import { enc, toHex } from "../bytes";

export type HashMethod = {
  id: "md5" | "sha256";
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
];

export const byId = (id: HashMethod["id"]) => METHODS.find((m) => m.id === id)!;

export type VerifyResult = { ok: boolean; text: string } | null;

/** Detect method(s) by hash length (MD5 = 32 hex, SHA-256 = 64 hex), hash the input again and compare. */
export async function verifyHash(input: string, storedRaw: string): Promise<VerifyResult> {
  const stored = storedRaw.trim().toLowerCase();
  if (!stored) return null;
  const candidates = METHODS.filter((m) => stored.length === m.bits / 4);
  if (!/^[0-9a-f]+$/.test(stored) || !candidates.length)
    return { ok: false, text: "Not a valid hash. Expected " + METHODS.map((m) => `${m.bits / 4} hex chars (${m.name})`).join(" or ") };
  let found: HashMethod | null = null;
  for (const m of candidates) if ((await m.hash(input)) === stored) { found = m; break; }
  const names = candidates.map((m) => m.name).join(" / ");
  return found
    ? { ok: true, text: `✓ Match (${found.name}): input is the original` }
    : { ok: false, text: `✗ No match (${names}): input was changed, even one character or space differs` };
}
