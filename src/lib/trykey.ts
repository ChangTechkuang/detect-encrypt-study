// "Try with key": decrypt with every symmetric method that fits the key size and see which one works.
// Reuses the Playground's tested decrypt code. Runs in the browser: the key never leaves the page.
import { fromHex, toB64 } from "@/lib/bytes";
import { SYM_METHODS, decryptText, symConfig, type AesMode, type SymMethod } from "@/lib/impl/symmetric";

export type Attempt = { name: string; methodId: SymMethod["id"]; verdict: "certain" | "likely" | "no"; text: string };

// Readable text: letters, digits, punctuation, symbols, spaces; no "�" from invalid UTF-8
const looksLikeText = (s: string) => s.length > 0 && !s.includes("�") && /^[\p{L}\p{N}\p{P}\p{S}\p{M}\s]*$/u.test(s);

/** Returns the attempts (best first), or an error message for a bad key. Data may be Base64 or hex. */
export async function tryWithKey(data: string, keyHex: string): Promise<Attempt[] | string> {
  const k = keyHex.replace(/\s+/g, "").toLowerCase();
  if (!/^([0-9a-f]{2})+$/.test(k)) return "The key must be hex: pairs of 0-9 and a-f.";
  const key = fromHex(k);
  const d = data.replace(/\s+/g, "");
  const b64 = /^([0-9a-f]{2})+$/i.test(d) ? toB64(fromHex(d.toLowerCase())) : d; // accept hex ciphertext too

  const tries: [string, SymMethod][] = [];
  if (key.length === 8) tries.push(["DES-CBC", SYM_METHODS.des]);
  if (key.length === 24) tries.push(["3DES-CBC", SYM_METHODS.tripledes]);
  if ([16, 24, 32].includes(key.length))
    for (const mode of ["GCM", "CBC", "CTR", "ECB"] as AesMode[]) tries.push([`AES-${key.length * 8}-${mode}`, symConfig(SYM_METHODS.aes, mode)]);
  if (key.length === 16) tries.push(["SEED-CBC", SYM_METHODS.seed]);
  if (key.length === 32) tries.push(["ChaCha20-Poly1305", SYM_METHODS.chacha20]);
  if ([16, 24, 32].includes(key.length)) tries.push([`ARIA-${key.length * 8}-CBC`, SYM_METHODS.aria]);
  if (!tries.length) return `A ${key.length}-byte key fits no method here. Key sizes: DES 8, AES 16/24/32, SEED 16, ARIA 16/24/32, 3DES 24, ChaCha20 32 bytes.`;

  const out: Attempt[] = [];
  for (const [name, m] of tries) {
    const r = await decryptText(m, key, b64);
    const readable = r.ok && looksLikeText(r.plain);
    out.push({
      name, methodId: m.id,
      // Only a tag (GCM, Poly1305) proves the key; CBC padding can pass by luck and CTR never fails, so those are "likely" at best
      verdict: !readable ? "no" : name.endsWith("-GCM") || name.endsWith("-Poly1305") ? "certain" : "likely",
      text: readable ? r.plain : r.ok ? "Decrypted to unreadable bytes: wrong key or wrong method." : r.text.replace(/^✗\s*/, ""),
    });
  }
  const rank = { certain: 0, likely: 1, no: 2 };
  return out.sort((a, b) => rank[a.verdict] - rank[b.verdict]);
}
