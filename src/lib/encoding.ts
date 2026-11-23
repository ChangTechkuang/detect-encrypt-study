// Encodings: reversible ways to WRITE data. No key, no secret: anyone can decode them.
import { enc, fromB64, fromHex, toB64, toHex } from "@/lib/bytes";

export type EncodingId = "hex" | "base64" | "base64url" | "url" | "html";

const htmlNamed: Record<string, string> = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " " };

export const ENCODINGS: { id: EncodingId; name: string; looks: string; use: string; encode: (s: string) => string; decode: (s: string) => string }[] = [
  {
    id: "hex", name: "Hex", looks: "Only 0–9 and a–f, 2 characters per byte",
    use: "Showing raw bytes and hashes",
    encode: (s) => toHex(enc(s)),
    decode: (s) => {
      const h = s.replace(/\s+/g, "").toLowerCase();
      if (!/^([0-9a-f]{2})*$/.test(h)) throw new Error("Hex needs pairs of 0-9 / a-f characters");
      return text(fromHex(h));
    },
  },
  {
    id: "base64", name: "Base64", looks: "A–Z a–z 0–9 + /, often ends with =",
    use: "Email attachments, JSON, this project's ciphertext",
    encode: (s) => toB64(enc(s)),
    decode: (s) => {
      const b = s.replace(/\s+/g, "");
      if (!/^[A-Za-z0-9+/]*={0,2}$/.test(b) || b.length % 4 === 1) throw new Error("Not valid Base64");
      return text(fromB64(b));
    },
  },
  {
    id: "base64url", name: "Base64URL", looks: "Like Base64 but - and _ instead of + and /, usually no =",
    use: "JWT tokens, values inside URLs",
    encode: (s) => toB64(enc(s)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""),
    decode: (s) => {
      const b = s.replace(/\s+/g, "");
      if (!/^[A-Za-z0-9_-]*={0,2}$/.test(b) || b.length % 4 === 1) throw new Error("Not valid Base64URL");
      return text(fromB64(b.replace(/-/g, "+").replace(/_/g, "/")));
    },
  },
  {
    id: "url", name: "URL encoding", looks: "% followed by 2 hex characters, e.g. %20 = space",
    use: "Web addresses and form data",
    encode: (s) => encodeURIComponent(s),
    decode: (s) => {
      try { return decodeURIComponent(s.replace(/\+/g, " ")); } catch { throw new Error("Broken % sequence"); }
    },
  },
  {
    id: "html", name: "HTML entities", looks: "&name; or &#number;, e.g. &lt; = <",
    use: "Showing special characters safely in web pages",
    encode: (s) => [...s].map((c) => {
      const named = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
      return named ?? (c.codePointAt(0)! > 126 ? `&#${c.codePointAt(0)};` : c);
    }).join(""),
    decode: (s) => s.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (m, e: string) =>
      e[0] === "#" ? String.fromCodePoint(parseInt(e[1].toLowerCase() === "x" ? e.slice(2) : e.slice(1), e[1].toLowerCase() === "x" ? 16 : 10))
        : htmlNamed[e.toLowerCase()] ?? m),
  },
];

/** Bytes → text, or an error if the bytes are not valid UTF-8 text (e.g. ciphertext). */
function text(b: Uint8Array) {
  try { return new TextDecoder("utf-8", { fatal: true }).decode(b); }
  catch { throw new Error(`Decoded to ${b.length} bytes that are not text (maybe encrypted or binary): ${toHex(b)}`); }
}

/** Best guess of which encoding a string uses. shortcut: simple pattern rules; ambiguous inputs (e.g. "cafe") pick the first match. */
export function guessEncoding(s: string): EncodingId | null {
  const t = s.trim();
  if (!t) return null;
  if (/%[0-9a-f]{2}/i.test(t)) return "url";
  if (/&(#x?[0-9a-f]+|[a-z]+);/i.test(t)) return "html";
  if (/^([0-9a-f]{2})+$/i.test(t.replace(/\s+/g, ""))) return "hex"; // hex is often written "48 65 6c"
  // A long run of hex characters with an odd count is hex with a character missing, not Base64 (same rule as classify.ts)
  if (/^[0-9a-f]{31,}$/i.test(t.replace(/\s+/g, ""))) return null;
  const n = t.replace(/[\r\n]+/g, ""); // Base64 may be split over lines, but never has spaces between words
  if (/[-_]/.test(n) && /^[A-Za-z0-9_-]+={0,2}$/.test(n)) return "base64url";
  if (/^[A-Za-z0-9+/]+={0,2}$/.test(n) && n.length % 4 !== 1) return "base64";
  return null;
}

export const byId = (id: EncodingId) => ENCODINGS.find((e) => e.id === id)!;
