// Byte helpers shared by every Implement panel.

export const enc = (s: string) => new TextEncoder().encode(s);
export const dec = (b: Uint8Array) => new TextDecoder().decode(b);

export const toHex = (b: ArrayBuffer | Uint8Array) =>
  [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
export const fromHex = (h: string) => Uint8Array.from(h.match(/../g) || [], (x) => parseInt(x, 16));

/** Binary string <-> bytes (for btoa/atob and node-forge). */
export const bin = (b: Uint8Array) => { let s = ""; for (const x of b) s += String.fromCharCode(x); return s; };
export const unbin = (s: string) => Uint8Array.from(s, (c) => c.charCodeAt(0));

export const toB64 = (b: Uint8Array) => btoa(bin(b));
/** Throws on invalid Base64. Whitespace is ignored. */
export const fromB64 = (s: string) => unbin(atob(s.replace(/\s+/g, "")));

export const cat = (...parts: ArrayLike<number>[]) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
};

export const random = (n: number) => crypto.getRandomValues(new Uint8Array(n));

/** PKCS#7 padding (PKCS#5 for 8-byte blocks). */
export const pad = (d: Uint8Array, n: number) => {
  const p = n - (d.length % n), out = new Uint8Array(d.length + p);
  out.set(d);
  out.fill(p, d.length);
  return out;
};
/** Throws "bad padding" (usually a wrong key or changed last block). */
export const unpad = (d: Uint8Array, n: number) => {
  const p = d[d.length - 1];
  if (!p || p > n || d.subarray(d.length - p).some((x) => x !== p)) throw new Error("bad padding");
  return d.subarray(0, d.length - p);
};
