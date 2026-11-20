// HASHING for passwords: no way back; verify = read cost + salt from the stored hash, hash again, compare.
// Fixes two problems of SHA-256(password): a random salt per password (no rainbow tables, equal passwords
// look different), and a cost factor: 2^cost rounds of Blowfish's expensive key setup (salt + password
// mixed in again and again), so each guess is slow. Each +1 cost doubles the work.
import bcrypt from "bcryptjs";

export const COSTS = Array.from({ length: 11 }, (_, i) => i + 4); // 4..14
export const DEFAULT_COST = 10;

/** New random salt every call. */
export const bcryptHash = (password: string, cost: number) => bcrypt.hash(password, cost);

export const BCRYPT_RE = /^\$2[abxy]?\$\d{2}\$[./A-Za-z0-9]{53}$/;

export async function bcryptVerify(password: string, storedRaw: string) {
  const stored = storedRaw.trim();
  if (!BCRYPT_RE.test(stored)) return { ok: false, text: "✗ Not a valid bcrypt hash (60 chars, starts with $2a$, $2b$ or $2y$)" };
  const ok = await bcrypt.compare(password, stored);
  return { ok, text: ok ? "✓ Match: password is correct" : "✗ No match: wrong password" };
}

// OpenBSD bcrypt / jBCrypt test suite: password, salt, expected (cost 6 so it runs fast)
export const BCRYPT_VECTORS: [password: string, salt: string, expected: string][] = [
  ["", "$2a$06$DCq7YPn5Rq63x1Lad4cll.", "$2a$06$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s."],
  ["a", "$2a$06$m0CrhHm10qJ3lXRY.5zDGO", "$2a$06$m0CrhHm10qJ3lXRY.5zDGO3rS2KdeeWLuGmsfGlMfOxih58VYVfxe"],
  ["abc", "$2a$06$If6bvum7DFjUnE9p2uDeDu", "$2a$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i"],
  ["abcdefghijklmnopqrstuvwxyz", "$2a$06$.rCVZVOThsIa97pEDOxvGu", "$2a$06$.rCVZVOThsIa97pEDOxvGuRRgzG64bvtJ0938xuqzv18d3ZpQhstC"],
  ["~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$2a$06$fPIsBO8qRqkjj273rfaOI.", "$2a$06$fPIsBO8qRqkjj273rfaOI.HtSV9jLDpTbZn782DC6/t7qT67P6FfO"],
];

/** Hash with the fixed salt, verify, and reject an altered password. */
export const checkVector = async ([pw, salt, expected]: [string, string, string]) =>
  (await bcrypt.hash(pw, salt)) === expected && (await bcrypt.compare(pw, expected)) && !(await bcrypt.compare(pw + "x", expected));
