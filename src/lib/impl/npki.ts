// ---------- 공동인증서 (Korean NPKI certificate). Same formats as java/gongdong/Gongdong.java ----------
// Is it symmetric or asymmetric? ASYMMETRIC. Each function below is marked:
//   [ASYMMETRIC] issue, signBytes, verifyBytes, keyMatches: RSA key pairs. The private key signs,
//                the public key (inside signCert.der) verifies. The bank only ever gets your PUBLIC
//                key, so it can check your signatures but never make one: that is what the certificate is for.
//   [SYMMETRIC]  keyIv, lockKey, unlockKey: SEED with ONE key made from your password. It only protects
//                signPri.key on your own disk; the password and SEED key never leave your PC.
//   Flow: password --SEED decrypt (symmetric)--> RSA private key --RSA sign (asymmetric)--> signature
//         signature + signCert.der --RSA verify with the public key (asymmetric)--> valid / invalid
import { cat, enc, dec, toHex, fromHex, fromB64, pad, unpad } from "../bytes";
import { seed } from "../seed";

type Bytes = Uint8Array<ArrayBuffer>;
export type DerEl = { tag: number; raw: Bytes; body: Bytes; kids?: DerEl[] };

// DER (the binary ASN.1 encoding of certificates and keys): tag, length, body.
export const der = {
  tlv(tag: number, body: Uint8Array): Bytes {
    const n = body.length, len = n < 128 ? [n] : n < 256 ? [0x81, n] : n < 65536 ? [0x82, n >> 8, n & 255] : [0x83, n >> 16, n >> 8 & 255, n & 255];
    return cat([tag], len, body);
  },
  seq: (...items: Uint8Array[]) => der.tlv(0x30, cat(...items)),
  set: (...items: Uint8Array[]) => der.tlv(0x31, cat(...items)),
  ctx: (n: number, ...items: Uint8Array[]) => der.tlv(0xa0 + n, cat(...items)), // [n] EXPLICIT
  int(v: number | Uint8Array) { // number or unsigned big-endian bytes
    let b = typeof v === "number" ? Uint8Array.from(v.toString(16).padStart(2, "0").replace(/^(.)((..)*)$/, "0$1$2").match(/../g)!.map((h) => parseInt(h, 16))) : v;
    let i = 0; while (i < b.length - 1 && b[i] === 0 && b[i + 1] < 128) i++;
    b = b.subarray(i);
    return der.tlv(0x02, b[0] >= 128 ? cat([0], b) : b);
  },
  oid(s: string) {
    const [a, b, ...rest] = s.split(".").map(Number), out = [40 * a + b];
    for (let v of rest) { const t = [v & 127]; while ((v >>= 7)) t.unshift(128 | v & 127); out.push(...t); }
    return der.tlv(0x06, Uint8Array.from(out));
  },
  nul: () => Uint8Array.from([5, 0]),
  bool: () => Uint8Array.from([1, 1, 255]),
  octet: (b: Uint8Array) => der.tlv(0x04, b),
  bits: (b: ArrayLike<number>, unused = 0) => der.tlv(0x03, cat([unused], b)),
  utf8: (s: string) => der.tlv(0x0c, enc(s)),
  printable: (s: string) => der.tlv(0x13, enc(s)),
  time: (d: Date) => der.tlv(0x17, enc(d.toISOString().replace(/^..(..)-(..)-(..)T(..):(..):(..).*/, "$1$2$3$4$5$6Z"))), // UTCTime
  // Parse one element: { tag, raw (whole TLV), body, kids (if constructed) }
  parse(b: Bytes, at = 0): DerEl {
    const tag = b[at];
    let n = b[at + 1], o = at + 2;
    if (n >= 128) { const k = n & 127; if (k < 1 || k > 3) throw new Error("bad DER"); n = 0; for (let i = 0; i < k; i++) n = n * 256 + b[o++]; }
    if (o + n > b.length) throw new Error("bad DER");
    const el: DerEl = { tag, raw: b.subarray(at, o + n), body: b.subarray(o, o + n) };
    if (tag & 0x20) { el.kids = []; for (let p = 0; p < n;) { const k = der.parse(el.body, p); el.kids.push(k); p += k.raw.length; } }
    return el;
  },
  oidOf(el: DerEl) {
    const b = el.body, out = [Math.floor(b[0] / 40), b[0] % 40];
    for (let i = 1, v = 0; i < b.length; i++) { v = v * 128 + (b[i] & 127); if (b[i] < 128) { out.push(v); v = 0; } }
    return out.join(".");
  },
};

export const OID = {
  rsa: "1.2.840.113549.1.1.1", sha256rsa: "1.2.840.113549.1.1.11",
  cn: "2.5.4.3", ou: "2.5.4.11", o: "2.5.4.10", c: "2.5.4.6",
  keyUsage: "2.5.29.15", basic: "2.5.29.19",
  seedSha1: "1.2.410.200004.1.15", // KISA: pbeWithSHA1AndSEED-CBC, used by signPri.key
};
const NAME_KEYS: Record<string, string> = { [OID.cn]: "cn", [OID.ou]: "ou", [OID.o]: "o", [OID.c]: "c" };
const SIG_ALG = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }; // sha256WithRSAEncryption, as NPKI uses
const sha1 = async (b: Bytes) => new Uint8Array(await crypto.subtle.digest("SHA-1", b));

type NameKey = "cn" | "ou" | "o" | "c";
export type CertSet = { caCert: Bytes; signCert: Bytes; signPri: Bytes };

export const npki = {
  // Name in DER order (c first). Korean certificates print it reversed: cn=..., ou=..., o=..., c=kr
  name: (parts: [NameKey, string][]) => der.seq(...parts.map(([k, v]) => der.set(der.seq(der.oid(OID[k]), k === "c" ? der.printable(v) : der.utf8(v))))),
  nameText: (el: DerEl) => el.kids!.map((s) => s.kids![0]).reverse()
    .map((a) => `${NAME_KEYS[der.oidOf(a.kids![0])] || der.oidOf(a.kids![0])}=${dec(a.kids![1].body)}`).join(", "),

  // [ASYMMETRIC] RSA-2048 key pair: public half goes in the certificate, private half gets locked by SEED
  async newKeyPair() {
    const kp = await crypto.subtle.generateKey({ ...SIG_ALG, modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) }, true, ["sign", "verify"]);
    return { spki: new Uint8Array(await crypto.subtle.exportKey("spki", kp.publicKey)), pkcs8: new Uint8Array(await crypto.subtle.exportKey("pkcs8", kp.privateKey)) };
  },
  // [ASYMMETRIC] sign needs the PRIVATE key; verify needs only the PUBLIC key (no password, no secret)
  signBytes: async (pkcs8: Bytes, data: Bytes) => new Uint8Array(await crypto.subtle.sign(SIG_ALG, await crypto.subtle.importKey("pkcs8", pkcs8, SIG_ALG, false, ["sign"]), data)),
  verifyBytes: async (spki: Bytes, sig: Bytes, data: Bytes) => crypto.subtle.verify(SIG_ALG, await crypto.subtle.importKey("spki", spki, SIG_ALG, false, ["verify"]), sig, data),

  // [ASYMMETRIC] X.509 v3 certificate, signed by the CA's PRIVATE key with SHA-256 + RSA.
  // Anyone checks it with the CA's PUBLIC key (caCert.der).
  async issue({ issuer, subject, spki, caPkcs8, isCA, days }: { issuer: Bytes; subject: Bytes; spki: Bytes; caPkcs8: Bytes; isCA: boolean; days: number }) {
    const now = new Date(Math.floor(Date.now() / 1000) * 1000), serial = crypto.getRandomValues(new Uint8Array(8));
    serial[0] &= 0x7f;
    const alg = der.seq(der.oid(OID.sha256rsa), der.nul());
    const exts = isCA
      ? [der.seq(der.oid(OID.basic), der.bool(), der.octet(der.seq(der.bool()))),                         // CA: yes
         der.seq(der.oid(OID.keyUsage), der.bool(), der.octet(der.bits([0x06], 1)))]                       // keyCertSign, cRLSign
      : [der.seq(der.oid(OID.keyUsage), der.bool(), der.octet(der.bits([0xc0], 6)))];                      // digitalSignature, nonRepudiation
    const tbs = der.seq(
      der.ctx(0, der.int(2)), der.int(serial), alg, issuer,
      der.seq(der.time(now), der.time(new Date(+now + days * 864e5))),
      subject, spki, der.ctx(3, der.seq(...exts)));
    return der.seq(tbs, alg, der.bits(await npki.signBytes(caPkcs8, tbs)));
  },
  parseCert(b: Bytes) {
    const [tbs, , sig] = der.parse(b).kids!, t = tbs.kids!, td = (s: DerEl) => dec(s.body);
    const time = (s: DerEl) => { const v = td(s); return new Date(`${s.tag === 0x17 ? (+v.slice(0, 2) < 50 ? "20" : "19") : ""}${v.replace(/^(\d{2,4}?)(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)Z$/, "$1-$2-$3T$4:$5:$6Z")}`); };
    return {
      tbs: tbs.raw, sig: sig.body.subarray(1), serial: toHex(t[1].body), sigAlg: der.oidOf(t[2].kids![0]),
      issuer: npki.nameText(t[3]), subject: npki.nameText(t[5]),
      notBefore: time(t[4].kids![0]), notAfter: time(t[4].kids![1]), spki: t[6].raw,
    };
  },

  // [SYMMETRIC] signPri.key: PKCS #8 EncryptedPrivateKeyInfo, SEED-CBC with a key from PBKDF1-SHA1(password, salt, 2048).
  // The SAME SEED key locks and unlocks. It is never stored: it is rebuilt from password + salt each time,
  // slowly on purpose (2048 x SHA-1) so guessing passwords takes longer.
  async keyIv(password: string, salt: Uint8Array, iter: number) {
    let dk = await sha1(cat(enc(password), salt));
    for (let i = 1; i < iter; i++) dk = await sha1(dk);
    return { key: dk.subarray(0, 16), iv: (await sha1(dk.subarray(16, 20))).subarray(0, 16) }; // IV = SHA-1(last 4 bytes of DK)
  },
  async lockKey(pkcs8: Bytes, password: string, iter = 2048) {
    const salt = crypto.getRandomValues(new Uint8Array(8)), { key, iv } = await npki.keyIv(password, salt, iter);
    return der.seq(der.seq(der.oid(OID.seedSha1), der.seq(der.octet(salt), der.int(iter))), der.octet(seed(true, key, iv, pad(pkcs8, 16))));
  },
  keyInfo(b: Bytes) {
    const [alg, data] = der.parse(b).kids!, [salt, iter] = alg.kids![1].kids!;
    return { oid: der.oidOf(alg.kids![0]), salt: salt.body, iter: parseInt(toHex(iter.body), 16), data: data.body };
  },
  // [SYMMETRIC] same password -> same SEED key -> RSA private key back.
  // Wrong password -> wrong SEED key -> garbage -> bad padding (or not a valid key): throws.
  async unlockKey(b: Bytes, password: string) {
    const k = npki.keyInfo(b);
    if (k.oid !== OID.seedSha1) throw new Error("not SEED-CBC with SHA-1 (" + k.oid + ")");
    const { key, iv } = await npki.keyIv(password, k.salt, k.iter);
    const pkcs8 = unpad(seed(false, key, iv, k.data), 16) as Bytes; // subarray of a fresh buffer
    await crypto.subtle.importKey("pkcs8", pkcs8, SIG_ALG, false, ["sign"]); // garbage that passed the padding check fails here
    return pkcs8;
  },
  // [ASYMMETRIC] Does this private key belong to this certificate? Both halves of a pair share the modulus n.
  async keyMatches(pkcs8: Bytes, spki: Bytes) {
    const n = async (fmt: "pkcs8" | "spki", b: Bytes) => (await crypto.subtle.exportKey("jwk", await crypto.subtle.importKey(fmt, b, SIG_ALG, true, [fmt === "spki" ? "verify" : "sign"]))).n;
    return await n("pkcs8", pkcs8) === await n("spki", spki);
  },

  // A test CA + a user certificate set, like the files in NPKI/<CA>/USER/<user>/
  async issueSet(holder: string, password: string): Promise<CertSet> {
    const ca = await npki.newKeyPair(), user = await npki.newKeyPair();
    const caName = npki.name([["c", "KR"], ["o", "TestCA"], ["cn", "Test Root CA (learning only)"]]);
    const id = Array.from(crypto.getRandomValues(new Uint8Array(10)), (b) => b % 10).join("");
    const caCert = await npki.issue({ issuer: caName, subject: caName, spki: ca.spki, caPkcs8: ca.pkcs8, isCA: true, days: 3650 });
    const signCert = await npki.issue({
      issuer: caName, subject: npki.name([["c", "KR"], ["o", "TestCA"], ["ou", "personal"], ["cn", `${holder}()${id}`]]),
      spki: user.spki, caPkcs8: ca.pkcs8, isCA: false, days: 365,
    });
    return { caCert, signCert, signPri: await npki.lockKey(user.pkcs8, password) };
  },
  // Everything a program checks before trusting a certificate set
  async open({ caCert, signCert, signPri }: CertSet, password: string, now = new Date()) {
    const ca = npki.parseCert(caCert), cert = npki.parseCert(signCert);
    const pkcs8 = await npki.unlockKey(signPri, password); // SYMMETRIC: password unlocks the file
    return { // the rest is ASYMMETRIC: key pair match, CA signature check
      cert, pkcs8,
      keyMatches: await npki.keyMatches(pkcs8, cert.spki),
      signedByCA: cert.issuer === ca.subject && await npki.verifyBytes(ca.spki, cert.sig, cert.tbs),
      inDate: cert.notBefore <= now && now <= cert.notAfter,
    };
  },
};

// Fixed test sets (password test1234!) + a signature of GD_MSG. Same values in java/gongdong/Gongdong.java.
export const GD_PW = "test1234!", GD_MSG = "I agree to the contract";
export const GD_JAVA = {
  ca: "MIIDLzCCAhegAwIBAgIIYuekDupGIwUwDQYJKoZIhvcNAQELBQAwRTELMAkGA1UEBhMCS1IxDzANBgNVBAoMBlRlc3RDQTElMCMGA1UEAwwcVGVzdCBSb290IENBIChsZWFybmluZyBvbmx5KTAeFw0yNjExMjAwNTA1NDlaFw0zNjExMTcwNTA1NDlaMEUxCzAJBgNVBAYTAktSMQ8wDQYDVQQKDAZUZXN0Q0ExJTAjBgNVBAMMHFRlc3QgUm9vdCBDQSAobGVhcm5pbmcgb25seSkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDLi3UPEwAbx+w/NJUKCmZXrz7FZTOrSQheWvTTy/TJsDOyYJceYTY7lRaEaACQpmCx7K1HUlFs6GBiMwwJJYZUxXIslgTWw4zsf9foQgJc2OfrqUMJO0ap6i8+SXvpsCWPkGfTsRd2JA0CaPByNsxfGP/KH7kpvSxU2pV3mDe1poyr2NAD+eZ4conSozkXTAd9PJ2gZs2XBONWjM0ZQ9EsEKYxW2jSiRUMsPTR1dfmnhIGME1G6zKB/frCR7noRYJwQC1s5yFZhRcbIDLqKZSPWCWeHVKMMVtm9NUrDbXNafMFxpG8AKP+fBfmDACaDYlVFxdwALvPji0FT8HzpMA7AgMBAAGjIzAhMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMA0GCSqGSIb3DQEBCwUAA4IBAQCb1Xt8/WdTk3ekruZ125NtXu1Uwge1ShLaaqyioK5PdPsJhhlGGVXSddoWnbVcet2aIPgCYby4u4ZABKl4OApM2nul2VdEYpLWR4Q30bhTn+IhQlDwlsdyQxshSgqrhNMyFomPq3j4IqF0KA09Hf1fWlrQdqI+DYFNYV3LFBjjrC4LUMqgQzd41+m3SvPukya2mTgiN20+QF7hx23Kv2Nzz0Cjb6Q6nkKrwcJ/t1WaZOs7d6W+e57NByyebmbGeTJpK6E/Biws1AlhNihyQ373AfUMw54IVZG3joEZIqs7mnnWwnC9aYA5mAL2EtHoj2uLVoNLY66LD3Id351bPfiG",
  cert: "MIIDKjCCAhKgAwIBAgIIBupjsqDDIJEwDQYJKoZIhvcNAQELBQAwRTELMAkGA1UEBhMCS1IxDzANBgNVBAoMBlRlc3RDQTElMCMGA1UEAwwcVGVzdCBSb290IENBIChsZWFybmluZyBvbmx5KTAeFw0yNjExMjAwNTA1NDlaFw0yNzExMjAwNTA1NDlaMFExCzAJBgNVBAYTAktSMQ8wDQYDVQQKDAZUZXN0Q0ExETAPBgNVBAsMCHBlcnNvbmFsMR4wHAYDVQQDDBXtmY3quLjrj5koKTY3OTk2MDk5MjkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDLnQEGK2/MyWeG4OXe2u8y4Sola4h1HJLhYu7jlEx80uEZuE37+MQnWN8ef35GPTQg+1qOkb6H49Jkzi/wKfkeLCzFD2wqpAaSCHQ1skcQduqgPeUN4I3VhIyXUXYBjSKfZVkQYWtBzA0YW16QF2MSGTT/3zvmoLOvkzT4zFdG9iUWVeLOgqDWJTkAJFL7lcdGbIkP8cDz0NiqEOQIAdMVjKBOdyghC7ZaYyJ/jxG1nh7PMQqUPObj2SmSWASa4JDx9OyHnbOLp8xF20zBbDjPXx0+6HlZVDrpdi+g/Hzk4EHTE2DVwHML0H+aTpojq9IV41JLz+dLxW0NKKxFbLMpAgMBAAGjEjAQMA4GA1UdDwEB/wQEAwIGwDANBgkqhkiG9w0BAQsFAAOCAQEALVo8MCXv8fa7fmLBBpi225w1zdm4dUNsUzpjOXyxu0peVhIwaK1rn1MJBvWiL9Sh6ZYruIsrSb5CzoOrJnJmQiGyciogSZvxw4TnT55rMO0P76YWtpJ718fSo85Tai8YEGZA2TNOaAmDkeFl8NeEDe7OV6G96q6W2cDFGSnfqvniW4BerWYTmhyamGZ8g6OMOkZ/cvEo97CHTl2mgmbv+jUWiI9Uw9Ye8KKxTGcdVd2CjUYJGL42tpcp1jdYTE1My1cz4dLEQnky/InD37oemVcNHtPBq4RfyaMs2xt8XVcKsOiIfeaPNKjFOnJZi6qdKJDb9SJfuPIWbFhH6DeATQ==",
  key: "MIIE8DAaBggqgxqMmkQBDzAOBAgCVwRZm2VKKAICCAAEggTQcAwNPA3W+pemoyNx4OG4rUcWqFpfAyOZUo524wWYn1tF0mvAqe/bDPvBqFepFv2YCcrJCozANdhtswWGu8xjlYo/nDkYRncJhY72OwR3Z10g+d49ZFz2cEXwjmikYB2SoJ338njSQ9f8WIJOXFE7vc6XGy6i4Q04TfmOWa/fyjqTe5UQXfDvLh+effD3lTBNjJrqnT8zHVNBhoiR/URJnu3oX6kDC5FOqsnsVKXdEQpyhQ3Ja6XWwOgMHP5WLGXZm9Y5HQy+JsiETS/avRad7uIJ9pon/9KAeLBbLLEWovYkDO2g958hN1XXGyvV3hvos2oYLEN5OhKos7bFK7V4Slafyv9KtZxO5VJjcoDHG7xZmoMvVNqlRJhizySfsAzESvKgXMe1g+l+EtDOy5OVMrvVKohXofxTLQftTuYTGS3Q95lN+TGQlEqZTCa5C0jvrNMPjJhfrwQh8J4vITL6iknhEOIPwCbsHvmZbvkgyLfiR3pG0D5akEn7LFbQzXbtzzUSsvWM/upfl02McX9BORGe1y+eCS4CGrHye506IJy6ptpF8aNXt/vN0P/gVVdyS6KB63/6G/zClzqe7N1CH6iqr/xv+MspgFYIlmt3dcCkSaTvKEEiNDgrPLCoW0VYPKPHDOfuRBbmQBPZ/RKT6w3wl9u7Mkup1BSZFUVh+bA/LPPTWVdsPcAO39z1ZswtLF5h8rq9rKOrv77iMosjCmAUwGLImfk9jgCtopnBJh4X4evbK0K+Md5LGXVT2yP4fFJ/MUHsUNUb2c/CwXUUBFxNeSd4Gg5MnbG+bC4UFV9E8zLQzE3n635HdKHTc+viuDxPHo17M2aZpz4J5aGTFzRXltN2N1xIJO083pN0CI72PyNs8BDPvvyS1J7OeW9Q6grIcWvS53IVqmg5/0lYLG00LFwTualbk1/pBlh44rtUWGvdrB2DUsoRmvNMv9ik5/aaE0j3EvWBJdYlzRtzoZeNpaA+lj98M+A5VOR2KQvTfm9oBxeeno9ykHsLA5XNZ3ncytkQIzkEwd8VwEOKqdMDIgbNopv3X62J0vGtyVkp8MRRWiZFPK6P0mX4ccOxIndUxfbfaQULWsea/sGCoCbiXDcICjkfWtmnq2Gnoh6TqaxFEq5iCRNGSUv6YsBBjsDIH27uC+IRq9cEeo91bDzqkMgOTqV6xR45HCsDCPDm2DxB0KrQS/AlFi0Y5gA9gnxWWJHKRRWZ6agREmh2tQIj0HjjhxB+HCvLpF2I57RwXwC9BvYCDZ5hJss/x9bKBUkcjpEeZtDX5XAqFDKlPUwDfDIT3w9YSQaM30kmVkzWzeWOsQHUjbh/be0uWoEPqQVnJMdh+XwcWvI0a0V3xwSqVfIAisuw1g/vK0xl+1dV9tn5pIs6+UKdP89LmtXt+jMK5+I3jlN79pv9l4VD/2myORhaWhdq2V/g/bf5phEYwmPbI3OMj9O+4ZXiFsRkTIcGLKeFIyQzgftgtpD53kstAuKFbVYzmvyBT6JsccUy7PDtqhkufW/oL4pXKAZU+fbem0qghUZLSBvQOjYSiUmv8OC9unLBebRIBPbaB+bxTgjv3hLHdAPGCP6/xHtkOiwrzir9cJEYoxSwNRRVYHCneGAjVbqst2krzhWwG7o=",
  sig: "iUaQvmo50KbPyFQAAvRbic7aydp2uJ8xV0qQk0I2a4y309S/rTIqeyNtEgHyz516RAlCi9TrvoqG1vaIMuNSo/so1ZerdpzV8+ZJCTkRxJFHx/N1CxH/8W7vrGwa+XejWDOrkrySQRz2hF5AfSZyaItORRknTNl5XZOpgCe8KKcQCuGefRkKs4hdLtHaETUs7XmrYmaHed9b+npvfVB9PkaxRpgNmSKM9/z9tZjdxtmoW4L9lbDeKZJfONoDD3dx0dxCn/L/fWF/Ofc+j6Mf2p0Yvl+PlKaL1mRgyvQQw2JF/Zi7eoHvxHOW4gNEzrEqhiE4pps34sL/tduSuphhEQ==",
}; // made by Gongdong.java
export const GD_PAGE = {
  ca: "MIIDLzCCAhegAwIBAgIINQgSZqvUg7AwDQYJKoZIhvcNAQELBQAwRTELMAkGA1UEBhMCS1IxDzANBgNVBAoMBlRlc3RDQTElMCMGA1UEAwwcVGVzdCBSb290IENBIChsZWFybmluZyBvbmx5KTAeFw0yNjExMjAwNTA1NDdaFw0zNjExMTcwNTA1NDdaMEUxCzAJBgNVBAYTAktSMQ8wDQYDVQQKDAZUZXN0Q0ExJTAjBgNVBAMMHFRlc3QgUm9vdCBDQSAobGVhcm5pbmcgb25seSkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDeqifs3Lz7Kis0s1YppjM4RHjPguMWMzLT9oiEz+UDRAiAaeZ0Yv9Ao3VyggkKjDyIIiBJYVtxPPDZeDTSQi1NDpE6pAEG0urawMYnWSpcHcA14bx3ltpspekKzdMtGSzmHCvVpd59G0vSIBiqTC4bHztrqGkBXL0dlIFvHVR/ESGLm+o/UrqIq4U+6UZf7r8SnULrroWUM+e2Ir22/wiR060YbdechyKegVeInjuvuEsUJytY1Vqn5CH/qHI0BjhCXOMha1dwBm8bZUpnPknVjqu2vmHqqGAaXdfaR0YFOQdIUMEjbga4gaAsZc9K1IX2naSdRmcXORoJA5F54hBnAgMBAAGjIzAhMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMA0GCSqGSIb3DQEBCwUAA4IBAQCWI7DG8xtK3JOWcJBx8yx4tEp6uEppjgiNQk4KF5uyMkxvgxEtwksucc8f3mJvOLgI71Opq190+g/MODhP2xwQrhrjLw8ZZ7KniN5+fIFV61vN5SNnBxHE0Di5uoptvJWUCI23CuMyOVsqUqC2gJDlE5FCw2zc2r25NE3kE/0QxsZirAQPaE7V98vCl1hnwwVfD31eQURXX+YL40kV7CSdxTxbC1whAQY4opTjuisNSDdqK2rI1orzeq30i3l6pdfbC54t+ZqbfIvyUgfJ3mRMXp75I0hd/a0qtA52nNvsavuG8BbSq0G/TyZ8NZ8IB6q4W/day2ZuTGe8nyG//fGc",
  cert: "MIIDKjCCAhKgAwIBAgIIRmG7dqp4OfMwDQYJKoZIhvcNAQELBQAwRTELMAkGA1UEBhMCS1IxDzANBgNVBAoMBlRlc3RDQTElMCMGA1UEAwwcVGVzdCBSb290IENBIChsZWFybmluZyBvbmx5KTAeFw0yNjExMjAwNTA1NDdaFw0yNzExMjAwNTA1NDdaMFExCzAJBgNVBAYTAktSMQ8wDQYDVQQKDAZUZXN0Q0ExETAPBgNVBAsMCHBlcnNvbmFsMR4wHAYDVQQDDBXtmY3quLjrj5koKTk1NjgzODIzNzkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC+emZ6aR4qv99EfXi7rCZc8j3j8BrRBemCmHP8GKE505PglvYDQoB7yp977uCh5Hcq6j7bBbDdGO17OQNwq2p9epEbnpK5+RuVGyA70qoTOf75oaOv/OEUPRxmT/K73TwmjrKtRWqlsNChbrykTY7Avv37ofVIIcQ729ZgvB7Kfmz5gAMA1zAQD8xbpRS+3ENQ8gcyeI7kAbKLgD+IoUSZqou8wLhrvmu7qgGx4x++c8BG31icVkpCUWKkTqrd5O3ImANgFrXKvx+kdeiJhu0n5PWskY8RwMe11do3of7xHKIPJh4VmhB1r0BWHSZttv0+R6qIIRax7Y5hW8n0sB61AgMBAAGjEjAQMA4GA1UdDwEB/wQEAwIGwDANBgkqhkiG9w0BAQsFAAOCAQEAI73Y3pOnS75EctxYUu/GZ/6Hjovp7n2gRk59iasPfLQe+y/bXFoZjYfFY1ZHfW2sZ6UAQSJzrjFBFR/n9sW9iEAAZcN7mCMYLBeMsebLWcQvtpBq5P8WjxAxGzeQmgJPrIR1ix/Athjn6zD1lxJe1POeW+Gl/BiilWztH6ZgmzLEfmqeee49f6QHYl+E9+YqrYfvyPNs8oc/fL2qooVPDrtVxEI8Sw0ijUeRxRoAOW7b1K2zCbi0I2nma/q0fLwyKEr5SpkiDZpNlsI3iCfZB6/IyyLbUSnfZC8WUivEjIGTBrf6kBHGyyjwiFHKbAFfbZKjR9htnVKhZR4/6BNkkw==",
  key: "MIIE8DAaBggqgxqMmkQBDzAOBAg/l9j0b51YNgICCAAEggTQkJuEUMXlg8Db7TPnCwp+zkA3mTVIjd3swzx9DydoMwzZlYtOIfRbRSSarXee5Zl8XDncmGbH3okfIzoOtaJybFlxJfmdbr5Ys29bjG+eHPLk80Rqs78uynLBIPLFGac3mxS9ln7m5BU8A4IKS7OsA8NrSCbsNC6kI9tn5ABf4xCeZP/zZ0h5u5NuNWyWH73dGLE1zhDejdTKrbooFFyoIUo+wzjKj7oUdvwkBu8j8RnfHg6TXQ6Q5i1T4okyFB6OFCKgvWOUocEP1BnpO5HVZOm5n6zwuIkzlTI/mALN2RoJQApFcbxsIJzvDSCEXYyFSzC9NI5sYcqUgQ8i+3d8J5SVGqA0Ol+5YDsjJKMC+KPEEoMyqyvzg1E5s4wmBkJ4aVrtW9zuLHcE8Y6qRx7uQ9b3CNy1nOd5FE3cTisvFM5nuxpVOEXDpPe9dFUoNad2Y5UXfrbI/4Qew/A/DywjwtTzBwDUad1Vw585P7E8/UDuG0xyRiY0JnxqQDbIl3eAsCxgINZTCgm8+S7K1Ul3EtQH2e1S0kgvLjacn0svDT0gzIrgK2kSirGQL8rv5fb1vmQrA3In+VMA4mBwMJBr5clUZI6tDE6AEKVI+l9lJkuq2eIaYoiafS6BVjbAGa6IDiQeSDzxI1OxWKSXKdQvnu2Ref3yRRempd6yFiJNVbCfL9wHyifQJqvwG0bxJVioiiA4srEcArOA04R7ylJdciDagqAib/7TuVmMC8zlNo/pMLPsTMcC6KdSnLhFvl8ZetsEUQQKJJOIHNt/t2Ylh9cZy9+w5scbiWEUFarCZu92c7Lg2wxG+vUNsiwZ+BBzmxGkFkFgMyhW/S75QgcF4HSIZYQKeCSsSAalVYYsLpm6Pc7epmeQTdh5IT7AA1CfaVqQsRX6PbBrORjx2MTgvKzzK/lelsGISn49h4ABHkbYw3AxjuUTdZlSkxBb7tvDETvbv8UR6mLmetECu68dQGj7V9SEzHYX1p+t+UYGJyH4LH3VQ7U18LLQq8srO1r4R5y9VChDXAHVcKnRwdI/zA3vPyYly9qGsKcm8SE8vqHJI2acB4AWTtvNDyJ8n0/jaCbDnmSICXJtV/YYKF0stUrX+C5bWzG7N+QiOIZS7oBHM+y7X3jqTmqI24yLVePvWoQwIvuHW8tLREvvmIgAn+Wotkcmk+B83Drkmh0plQfJDsSMXyMSTaEjqmDMUDbZRuRRKXwZN34iU9dypp7vk10ypcZA9FwoJAYfgQDRXLVCAU2y/8JG9c2vzPeiLLIGMfp9kvRfNuJNb2W0ed/pkKUruFHUqv+u/HYhUxTia6bziSj9FG5Oc5M3ylVQABp0s/ctBI9m6YwB6xrYikQAt+PGvs6QkRN98wA2ioihlc4eXP0zMVZ/lm01HNznKf8Kh7JJPWR5mPsMn+/fcopURFEJTdcp8uCXc9au/CB0g3d7qWPhMv04j7E0/nQ/Y/M0pwNaUi6x0KMgBfjTFUr74nahhSv3XpFw1wIy4L8wvY9t+bO/4sO/zNzSfjd2dj+aZXwjfFweohMBqiDYFaHIXY4jxFrTw0m9aTPUhsfQusAJQ2iEjORrIiKx2rdCp00bG3AdpAjry+Ki0eMOcF/uUetc2MvbuWaE5JLtUOHTImY=",
  sig: "o7LVikS8LIC8VK9K7ST01sRwzHDIhX8z5mWkmf9vfqcGK9CK4BnFfwZsT/Lj2G9l3gTxu25Y8GlpAnlFIss83UvCPaMKxxl4U6xVj+IYf5ZnUATrfU7YizEJSSmoHsFxHEiJwfVkNltdTQH7GBC0ru+n3bTzTNaRAWSHsNt3rk25wC//y0/C/gM8RSp+qGCzxvHh/l3D0PAM/3htsqae/G53I7OBZAfjSfZ1yuAGiCMoWunWI+GX7lBn3NGDqfaSR/a9TGfBQsrmZ/knb+J+LcLJwP25QeyikbVUIXjvHb6tldby9PML1+yrl0xLcnmchN5U1Lv651oRZbYFOfCYLw==",
}; // made by this page's code
export type Fixture = typeof GD_JAVA;
export const gdSet = (f: Fixture): CertSet => ({ caCert: fromB64(f.ca), signCert: fromB64(f.cert), signPri: fromB64(f.key) });

/** The 12 self-checks, as [name, run] pairs. A check that throws counts as a fail. */
export function gdChecks(): [string, () => Promise<boolean>][] {
  const msg = enc(GD_MSG);
  const opens = async (f: Fixture) => { const o = await npki.open(gdSet(f), GD_PW); return o.keyMatches && o.signedByCA; };
  const sigOk = async (f: Fixture) => npki.verifyBytes(npki.parseCert(fromB64(f.cert)).spki, fromB64(f.sig), msg);
  let fresh: CertSet, other: CertSet; // issued once, shared by the checks below
  return [
    ["SEED known answer (RFC 4269 B.3)", async () =>
      toHex(seed(true, fromHex("4706480851e61be85d74bfb3fd956185"), null, fromHex("83a2f8a288641fb9a4e9a5cc2f131c7d"))) === "ee54d13ebcae706d226bc3142cd40d4a"],
    ["Set made by Java opens: key matches certificate, signed by CA", () => opens(GD_JAVA)],
    ["Signature made by Java verifies", () => sigOk(GD_JAVA)],
    ["Set made by this page opens (Java checks the same set)", () => opens(GD_PAGE)],
    ["Signature made by this page verifies", () => sigOk(GD_PAGE)],
    ["Issue a new set → opens, key matches, signed by CA, in date", async () => {
      fresh = await npki.issueSet("홍길동", "my password 1!");
      const o = await npki.open(fresh, "my password 1!");
      return o.keyMatches && o.signedByCA && o.inDate && o.cert.subject.startsWith("cn=홍길동()");
    }],
    ["Sign with the private key, verify with the certificate", async () => {
      const o = await npki.open(fresh, "my password 1!"), sig = await npki.signBytes(o.pkcs8, msg);
      return npki.verifyBytes(o.cert.spki, sig, msg);
    }],
    ["Changed message is rejected", async () =>
      !(await npki.verifyBytes(npki.parseCert(fromB64(GD_JAVA.cert)).spki, fromB64(GD_JAVA.sig), enc(GD_MSG + "!")))],
    ["Wrong password is rejected", async () => {
      try { await npki.open(fresh, "my password 2!"); return false; } catch { return true; }
    }],
    ["Certificate with a changed name is rejected by the CA check", async () => {
      const forged = Uint8Array.from(fresh.signCert), at = toHex(forged).indexOf(toHex(enc("personal"))) / 2;
      forged[at] = "P".charCodeAt(0);
      return !(await npki.open({ ...fresh, signCert: forged }, "my password 1!")).signedByCA;
    }],
    ["Certificate from a different CA is rejected", async () => {
      other = await npki.issueSet("홍길동", "my password 1!");
      return !(await npki.open({ ...fresh, caCert: other.caCert }, "my password 1!")).signedByCA;
    }],
    ["Someone else's private key does not match the certificate", async () =>
      !(await npki.open({ ...fresh, signPri: other.signPri }, "my password 1!")).keyMatches],
  ];
}
