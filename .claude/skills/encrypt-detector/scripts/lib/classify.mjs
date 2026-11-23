// GENERATED from src/lib/classify.ts by scripts/build-skill.mjs (npm run skill:build). Do not edit: edit the .ts and rebuild.
// Rule-based classifier: hash vs symmetric vs asymmetric, from STRUCTURE only. No AI, instant, same answer every time.
// Self-contained (no imports) so the browser, the API route and eval/evaluate.mts all run this exact file.
//
// What ciphertext alone can and can't tell:
// - Good hashes and good ciphertexts are BOTH random-looking bytes. Statistics (entropy, byte counts) can only
//   separate them from text, never from each other. So the rules use length, encoding and structure.
// - Some lengths are shared: 32 bytes = SHA-256 or AES/SEED-CBC of up to 15 bytes; 64 bytes = SHA-512 or a
//   3-block CBC / 36-byte GCM message. There, only the convention "hashes are written in hex" tips the balance,
//   with low confidence, or the answer is UNKNOWN.
// - AES vs SEED, AES-GCM vs ChaCha20-Poly1305, and AES key sizes are NOT visible in ciphertext: algorithm = UNKNOWN.
/** Below this, the answer is reported as UNKNOWN instead of a guess. */
export const MIN_CONFIDENCE = 0.6;
const result = (c) => {
    const r = { algorithm: "UNKNOWN", algorithmConfidence: 0, candidates: [], shortlist: [], representation: "structured", bytes: 0, ...c };
    if (r.categoryConfidence < MIN_CONFIDENCE)
        r.category = "UNKNOWN";
    if (r.algorithmConfidence < MIN_CONFIDENCE || r.category === "UNKNOWN")
        r.algorithm = "UNKNOWN";
    return r;
};
// ---- decoding
const fromHex = (h) => Uint8Array.from(h.match(/../g) ?? [], (x) => parseInt(x, 16));
function fromBase64(s) {
    const std = s.replace(/-/g, "+").replace(/_/g, "/");
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(std) || std.replace(/=+$/, "").length % 4 === 1)
        return null;
    try {
        return Uint8Array.from(atob(std.padEnd(Math.ceil(std.length / 4) * 4, "=")), (c) => c.charCodeAt(0));
    }
    catch {
        return null;
    }
}
const hasOid = (b, oidHex) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("").includes(oidHex);
const RSA_OID = "2a864886f70d010101", EC_OID = "2a8648ce3d0201";
// ---- P-256 point check: y² = x³ - 3x + b (mod p). A random 65-byte string passes with chance ~2^-257.
const B = BigInt; // the project targets ES2017, which has no 123n literals
const P256 = { p: B("0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff"), b: B("0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b") };
const toInt = (b) => b.reduce((a, v) => (a << B(8)) | B(v), B(0));
function isP256Point(b) {
    if (b.length < 65 || b[0] !== 4)
        return false;
    const { p } = P256, x = toInt(b.slice(1, 33)), y = toInt(b.slice(33, 65));
    if (x >= p || y >= p)
        return false;
    return (y * y) % p === (((x * x % p) * x - B(3) * x + P256.b) % p + p) % p;
}
/** DER SEQUENCE whose length field matches the data exactly (keys and certificates are DER). */
function isDerSequence(b) {
    if (b.length < 4 || b[0] !== 0x30)
        return false;
    let len = b[1], head = 2;
    if (len & 0x80) {
        const n = len & 0x7f;
        if (n < 1 || n > 3)
            return false;
        len = 0;
        for (let i = 0; i < n; i++)
            len = len * 256 + b[2 + i];
        head = 2 + n;
    }
    return head + len === b.length;
}
/**
 * Hashes and ciphertexts are random bytes. Returns why this ISN'T random, or "" if it could be.
 * Both tests are near-impossible by chance (< 1 in 10^6 for the sizes used here), so hand-typed or made-up values get caught.
 */
function notRandom(b, hex) {
    // A repeated 4-byte run: random data repeats one with chance ~ n²/2^33 (tiny below a few hundred bytes)
    const seen = new Map();
    let repeats = 0;
    for (let i = 0; i + 4 <= b.length; i++) {
        const k = b.slice(i, i + 4).join(","), at = seen.get(k);
        if (at !== undefined && i - at >= 4)
            repeats++;
        else if (at === undefined)
            seen.set(k, i);
    }
    if (b.length <= 1024 && repeats >= 2)
        return `The same byte runs repeat ${repeats} times. Random data almost never repeats like that.`;
    // Hex written as letter-digit, letter-digit…: random hex mixes letters and digits in every position
    if (hex && hex.length >= 32) {
        const letters = (start) => { let l = 0, c = 0; for (let i = start; i < hex.length; i += 2, c++)
            if (hex[i] > "9")
                l++; return l / c; };
        const gap = Math.abs(letters(0) - letters(1));
        // Measured on 2,000,000 random values per size: 0.8 below 64 chars, 0.6 from 64 up -> false alarms <= ~1 in 2,000,000
        if (gap >= (hex.length < 64 ? 0.8 : 0.6))
            return `In almost every pair, ${letters(0) > letters(1) ? "a letter (a-f) comes first and a digit second" : "a digit comes first and a letter (a-f) second"}. Random hex doesn't follow a pattern like that.`;
    }
    return "";
}
/** "128 hex chars is SHA-512, this is 120": a value a few characters off a hash size. */
function nearMiss(hexLen) {
    const sizes = [[32, "MD5"], [40, "SHA-1"], [64, "SHA-256"], [96, "SHA-384"], [128, "SHA-512"]];
    if (sizes.some(([len]) => len === hexLen))
        return []; // exactly a hash size: not a near miss
    const near = sizes.find(([len]) => Math.abs(len - hexLen) <= 8);
    return near ? [`${hexLen} hex characters: ${near[1]} is always exactly ${near[0]}, so this can't be a complete ${near[1]}.`] : [];
}
/** ECDSA signature in DER: SEQUENCE { INTEGER r, INTEGER s }, each about the curve size. Returns the curve, or "". */
function ecdsaCurve(b) {
    if (!isDerSequence(b))
        return "";
    let i = b[1] & 0x80 ? 2 + (b[1] & 0x7f) : 2;
    const ints = [];
    while (i < b.length) {
        if (b[i] !== 0x02 || i + 2 > b.length)
            return ""; // only INTEGERs allowed
        ints.push(b[i + 1]);
        i += 2 + b[i + 1];
    }
    if (i !== b.length || ints.length !== 2)
        return "";
    const m = Math.max(...ints);
    return m >= 30 && m <= 33 ? "P-256" : m >= 46 && m <= 49 ? "P-384" : m >= 64 && m <= 67 ? "P-521" : "";
}
/** SEED and ARIA are Korean national standards: say so whenever they are on the shortlist. */
const KOREAN = "SEED and ARIA are Korean national standards (KISA; ARIA is KS X 1213), used by Korean banks, card companies and shopping sites next to AES.";
const printableRatio = (b) => b.filter((x) => (x >= 32 && x < 127) || x === 9 || x === 10 || x === 13).length / b.length;
// ---- length tables
// Hash digests (bytes): [algorithm, confidence if written in hex, confidence if Base64, other possibilities,
// keyed variants with exactly the same output (HMAC with a secret key, PBKDF2 with a password): only the key tells them apart]
const HASH_SIZES = {
    16: ["MD5", 0.85, 0.65, "MD4/NTLM (same size), one AES/SEED/ARIA block without IV (ECB), a 128-bit key or random ID", ["HMAC-MD5"]],
    20: ["SHA-1", 0.9, 0.8, "RIPEMD-160 (same size), AES-CTR of a 4-byte text", ["HMAC-SHA1"]],
    // 32 and 64 are shared with short ciphertexts. Hex leans "likely hash" (real-world habit: hashes are written in hex,
    // ciphertext in Base64); Base64 stays UNKNOWN. On eval/data, which puts hex ciphertexts on these sizes on purpose,
    // the hex guess is right only about half the time: see eval/report-test.md.
    32: ["SHA-256", 0.65, 0.45, "SHA3-256 / BLAKE2s (same size); AES/SEED/ARIA-CBC of a 0–15 byte text (IV 16 + 1 block); a 256-bit key", ["HMAC-SHA-256", "PBKDF2-SHA256"]],
    48: ["SHA-384", 0.65, 0.45, "SHA3-384 (same size); AES/SEED/ARIA-CBC of a 16–31 byte text (IV 16 + 2 blocks); AES-GCM / ChaCha20-Poly1305 of a 20-byte text", ["HMAC-SHA-384"]],
    64: ["SHA-512", 0.65, 0.45, "SHA3-512 / BLAKE2b (same size); AES/SEED/ARIA-CBC of a 32–47 byte text; AES-GCM / ChaCha20-Poly1305 of a 36-byte text", ["HMAC-SHA-512", "PBKDF2-SHA512"]],
};
// RSA output = exactly the key size in bytes
// RSA-1024 (128 bytes): retired, and 128 bytes is also a common CBC size (calibrated on eval/data/kr-dev.json) -> below MIN_CONFIDENCE
const RSA_SIZES = { 128: ["RSA-1024", 0.5], 256: ["RSA-2048", 0.8], 384: ["RSA-3072", 0.8], 512: ["RSA-4096", 0.8] };
export function classify(input) {
    const t = input.trim();
    if (!t)
        return result({ category: "UNKNOWN", categoryConfidence: 0, evidence: ["Empty input."] });
    // 1. Formats that label themselves: certain
    if (/^\$2[abxy]?\$\d\d\$[./A-Za-z0-9]{53}$/.test(t))
        return result({ category: "hashing", categoryConfidence: 0.99, algorithm: "bcrypt", algorithmConfidence: 0.99, evidence: ["Starts with $2a$/$2b$/$2y$ + cost + 53 characters: the bcrypt format."] });
    if (/^\$argon2(id|i|d)\$/.test(t))
        return result({ category: "hashing", categoryConfidence: 0.99, algorithm: "Argon2", algorithmConfidence: 0.99, evidence: ["Starts with $argon2: the Argon2 password-hash format."] });
    const crypt = t.match(/^\$(1|5|6)\$/);
    if (crypt) {
        const name = { 1: "MD5-crypt", 5: "SHA-256-crypt", 6: "SHA-512-crypt" }[crypt[1]];
        return result({ category: "hashing", categoryConfidence: 0.97, algorithm: name, algorithmConfidence: 0.95, evidence: [`Starts with $${crypt[1]}$: the Unix ${name} password format.`] });
    }
    // PBKDF2 stored as text: Django "pbkdf2_sha256$600000$salt$hash", passlib "$pbkdf2-sha256$29000$salt$hash"
    const pbkdf2 = t.match(/^\$?pbkdf2(?:[-_](sha1|sha256|sha384|sha512))?\$(\d+)\$[^$\s]+\$[^$\s]+$/i);
    if (pbkdf2) {
        const h = (pbkdf2[1] ?? "sha1").toUpperCase().replace("SHA", "SHA-");
        return result({ category: "hashing", categoryConfidence: 0.98, algorithm: `PBKDF2-HMAC-${h} (${Number(pbkdf2[2]).toLocaleString("en-US")} rounds)`, algorithmConfidence: 0.97,
            evidence: ["Starts with pbkdf2 + hash name + rounds + salt + hash: the stored PBKDF2 password format (Django / passlib).",
                "PBKDF2 runs HMAC thousands of times with a salt, so passwords are slow to guess. One-way: it can only be checked, not decrypted."] });
    }
    const pem = t.match(/-----BEGIN ([A-Z0-9 ]+)-----/);
    if (pem) {
        const body = fromBase64(t.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "")) ?? new Uint8Array(0);
        const kind = /RSA/.test(pem[1]) || hasOid(body, RSA_OID) ? "RSA" : /EC/.test(pem[1]) || hasOid(body, EC_OID) ? "EC" : "";
        return result({ category: "asymmetric", categoryConfidence: 0.99, algorithm: kind ? `${kind} ${pem[1].toLowerCase()} (PEM)` : `PEM ${pem[1].toLowerCase()}`,
            algorithmConfidence: kind ? 0.95 : 0.6, evidence: [`PEM header "${pem[1]}": keys and certificates belong to asymmetric cryptography.`] });
    }
    // 2. Decode: hex first (hex characters are also valid Base64), then Base64 / Base64URL
    const compact = t.replace(/\s+/g, "").replace(/^0x/i, "");
    // Only hex characters but an odd count: hex with one character lost or added (e.g. cut off when copying), not Base64
    if (/^[0-9a-fA-F]+$/.test(compact) && compact.length % 2 === 1 && compact.length >= 31)
        return result({ category: "UNKNOWN", categoryConfidence: 0.2, representation: "hex", candidates: ["a hash or ciphertext with one character missing or extra"],
            evidence: [`${compact.length} hex characters: an odd number. Hex always comes in pairs (2 characters = 1 byte), so one character is missing or extra. Was it cut off when copying?`,
                ...nearMiss(compact.length)] });
    let bytes = null, representation = "text";
    if (/^[0-9a-fA-F]+$/.test(compact) && compact.length % 2 === 0) {
        bytes = fromHex(compact.toLowerCase());
        representation = "hex";
    }
    else if ((bytes = fromBase64(compact)))
        representation = "base64";
    if (!bytes || !bytes.length)
        return result({ category: "UNKNOWN", categoryConfidence: 0, representation: "text", evidence: ["Not hex and not Base64: this looks like plain text, not a hash or ciphertext."] });
    const n = bytes.length, base = { representation, bytes: n };
    const sizeNote = `${representation === "hex" ? "Hex" : "Base64"}: ${n} bytes (${n * 8} bits).`;
    // 3. Text hidden in an encoding: hashes and ciphertexts are random bytes, so mostly-printable bytes are neither
    if (n >= 4 && printableRatio(bytes) > 0.9)
        return result({ ...base, category: "encoding", categoryConfidence: 0.9, algorithm: representation === "hex" ? "Hex-encoded text" : "Base64-encoded text", algorithmConfidence: 0.9,
            evidence: [sizeNote, "Decodes to readable text. Hashes and ciphertexts decode to random bytes, so this is only encoded, not hashed or encrypted."] });
    // 4. Structure that only asymmetric crypto has
    const curve = ecdsaCurve(bytes);
    if (curve)
        return result({ ...base, category: "asymmetric", categoryConfidence: 0.95, algorithm: `ECDSA signature (${curve})`, algorithmConfidence: 0.9,
            candidates: ["a DSA signature (same layout, rare today)"],
            evidence: [sizeNote, `A DER SEQUENCE of exactly two INTEGERs (r, s) the size of a ${curve} number: the layout of an ECDSA signature.`,
                "A signature proves who signed with the private key; anyone can check it with the public key. It is not encryption."] });
    if (n === 65 && isP256Point(bytes))
        return result({ ...base, category: "asymmetric", categoryConfidence: 0.97, algorithm: "ECC public key (P-256)", algorithmConfidence: 0.95,
            evidence: [sizeNote, "04 + x + y, and the point lies on the P-256 curve: a raw (uncompressed) ECC public key. Random bytes almost never are."] });
    if (isDerSequence(bytes)) {
        const kind = hasOid(bytes, RSA_OID) ? "RSA" : hasOid(bytes, EC_OID) ? "EC" : "";
        return result({ ...base, category: "asymmetric", categoryConfidence: 0.9, algorithm: kind ? `${kind} key or certificate (DER)` : "DER structure (key or certificate)", algorithmConfidence: kind ? 0.85 : 0.6,
            evidence: [sizeNote, "A DER SEQUENCE whose length field matches the data exactly: the binary format of keys and certificates."] });
    }
    if (n >= 65 + 12 + 16 && isP256Point(bytes))
        return result({ ...base, category: "asymmetric", categoryConfidence: 0.97, algorithm: "ECIES (P-256)", algorithmConfidence: 0.85,
            candidates: ["any hybrid scheme that sends an ephemeral P-256 public key first"],
            evidence: [sizeNote, "The first 65 bytes are a valid P-256 curve point (04 + x + y). Random bytes almost never are: this is an ephemeral public key, the start of ECIES."] });
    // 5. Not random at all: a made-up or hand-typed value, not the output of any algorithm
    const miss = representation === "hex" ? nearMiss(compact.length) : [];
    const patterned = notRandom(bytes, representation === "hex" ? compact.toLowerCase() : null);
    if (patterned)
        return result({ ...base, category: "UNKNOWN", categoryConfidence: 0.1, candidates: ["a value typed by hand or made up to look like hex", "test or placeholder data"],
            evidence: [sizeNote, patterned, ...miss, "Real hashes and ciphertexts always look random, so this is probably not the output of any algorithm."] });
    // 6. Exact sizes: hash digests and RSA blocks
    const hash = HASH_SIZES[n];
    if (hash) {
        const [name, hexConf, b64Conf, others, keyed] = hash, conf = representation === "hex" ? hexConf : b64Conf;
        const shared = n === 32 || n === 48 || n === 64; // also a short CBC/GCM ciphertext size
        return result({ ...base, category: "hashing", categoryConfidence: conf, algorithm: [name, ...keyed.filter((k) => k.startsWith("HMAC"))].join(" / "), algorithmConfidence: conf - 0.05,
            candidates: [others], shortlist: [name, ...keyed, ...(shared ? ["AES-CBC", "SEED-CBC", "ARIA-CBC", "AES-GCM"] : [])],
            evidence: [sizeNote, `${n} bytes is exactly the ${name} output size.`,
                representation === "hex" ? "Written in hex, the usual way to write a hash." : "Written in Base64: hashes are usually hex, ciphertexts usually Base64, so this could be either.",
                `${keyed.join(" and ")} give exactly the same size: a plain hash and a keyed one (HMAC with a secret key, PBKDF2 with a password) look the same. Only the key tells them apart.`,
                ...(shared ? [conf < MIN_CONFIDENCE ? "Too close to call: UNKNOWN rather than a guess." : "Likely, not certain: a short AES/SEED/ARIA-CBC message written in hex has the same length. Only the key can prove it (Try with a key)."] : [])] });
    }
    const rsa = RSA_SIZES[n];
    if (rsa)
        return result({ ...base, category: "asymmetric", categoryConfidence: rsa[1], algorithm: rsa[0], algorithmConfidence: rsa[1] - 0.05,
            candidates: [`${rsa[0]} ciphertext with RSA-OAEP or PKCS#1 v1.5 padding`, `${rsa[0]} signature (PKCS#1 v1.5 or PSS)`, "a long symmetric ciphertext that happens to be this size"],
            evidence: [sizeNote, `Exactly ${n * 8} bits: RSA output is always exactly the key size (${rsa[0]}).`,
                "The padding (RSA-OAEP, the modern choice, or the older PKCS#1 v1.5) is hidden inside: only the private key shows which, and whether it is a ciphertext or a signature."] });
    // 7. Everything else long enough: symmetric ciphertext. IV/nonce + data never lands on exactly one hash size by design.
    if (n >= 28) {
        const block16 = n % 16 === 0;
        return result({ ...base, category: "symmetric", categoryConfidence: 0.85, algorithm: "UNKNOWN", algorithmConfidence: 0,
            shortlist: block16 ? ["AES-CBC", "SEED-CBC", "ARIA-CBC", "AES-GCM", "ARIA-GCM", "ChaCha20-Poly1305"] : ["AES-GCM", "ARIA-GCM", "ChaCha20-Poly1305", "AES-CTR"],
            candidates: block16
                ? ["AES-CBC (128/192/256)", "SEED-CBC (128)", "ARIA-CBC (128/192/256)", "AES-GCM / ARIA-GCM / ChaCha20-Poly1305 (if the text length fits)"]
                : ["AES-GCM (128/192/256)", "ARIA-GCM (128/192/256)", "ChaCha20-Poly1305", "AES-CTR / other stream mode"],
            evidence: [sizeNote, "Not a hash size and not an RSA size: hashes and RSA have fixed sizes, ciphertext grows with the message.",
                block16 ? "A multiple of 16 bytes: IV + whole 16-byte blocks (CBC-style: AES, SEED or ARIA, all 16-byte block ciphers)." : "Not a multiple of 16: no block padding, so a stream or AEAD mode (12-byte nonce + text + 16-byte tag).",
                "AES, SEED and ARIA, GCM and ChaCha20, and the key sizes look identical in ciphertext: the algorithm needs the key (Try with a key).", KOREAN, ...miss] });
    }
    // 8. Short (17-27 bytes): too short for GCM/ChaCha (28+), but DES/3DES-CBC (8-byte IV + blocks) and AES-CTR (16-byte IV + text) fit
    const short = [], names = [];
    if (n >= 16 && (n - 8) % 8 === 0) {
        names.push("DES-CBC", "3DES-CBC");
        short.push(`DES/3DES-CBC: 8-byte IV + ${(n - 8) / 8} block(s) of 8 bytes (text of ${(n - 8) - 8}–${(n - 8) - 1} bytes)`);
    }
    if (n > 16) {
        names.push("AES-CTR");
        short.push(`AES-CTR: 16-byte IV + text of ${n - 16} bytes`);
    }
    if (short.length) {
        if (n === 24)
            short.push("a 192-bit key (AES-192 or 3DES): also symmetric");
        return result({ ...base, category: "symmetric", categoryConfidence: 0.65, candidates: short, shortlist: names,
            evidence: [sizeNote, "Not a hash size and not an RSA size, but too short for AES-GCM or ChaCha20 (at least 28 bytes).",
                "Fits a short symmetric ciphertext: DES/3DES-CBC or AES-CTR. Which one, and the text inside, needs the key (Try with a key).", ...miss] });
    }
    return result({ ...base, category: "UNKNOWN", categoryConfidence: 0.3, candidates: ["a short key, ID or token", "one DES/3DES block (8 bytes) without IV"],
        evidence: [sizeNote, "Too short for any ciphertext format here and not a known hash size."] });
}
