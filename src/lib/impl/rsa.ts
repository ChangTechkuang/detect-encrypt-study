// RSA-OAEP (encryption) + RSA-PSS (signatures). Web Crypto, same parameters and PEM format as java/rsa/Rsa.java.
// ASYMMETRIC: two DIFFERENT keys. Compare SEED/AES (symmetric), where one shared key does both jobs.
// The math Web Crypto does inside (see java/rsa/Rsa.java for the full version):
//   key pair:  n = p * q (two huge secret primes), e = 65537, d = e^-1 mod (p-1)(q-1)
//              public key = (n, e), private key = (n, d)
//   encrypt:   c = m^e mod n  (public)      decrypt: m = c^d mod n  (private)
//   sign:      s = h^d mod n  (private)     verify:  s^e mod n == h (public), h = padded SHA-256 of the message
//   security:  finding d from (n, e) needs p and q, i.e. factoring n: impossible for 2048 bits today.
// OAEP / PSS add random padding first, so raw "textbook" RSA (same m -> same c, forgeable) is never used.
import { fromB64, toB64, toHex } from "../bytes";

export const RSA_ALG = { name: "RSA-OAEP", hash: "SHA-256" };
export const pemOf = (type: string, der: ArrayBuffer) =>
  `-----BEGIN ${type}-----\n${toB64(new Uint8Array(der)).match(/.{1,64}/g)!.join("\n")}\n-----END ${type}-----`;
export const derOf = (pem: string) => fromB64(pem.replace(/-----[A-Z ]+-----/g, ""));
export const rsaPublic = (pem: string) => crypto.subtle.importKey("spki", derOf(pem), RSA_ALG, false, ["encrypt"]);
export const rsaPrivate = (pem: string) => crypto.subtle.importKey("pkcs8", derOf(pem), RSA_ALG, false, ["decrypt"]);
export const rsaBits = (key: CryptoKey) => (key.algorithm as RsaHashedKeyAlgorithm).modulusLength;
export const rsaMax = (key: CryptoKey) => rsaBits(key) / 8 - 66; // OAEP-SHA256: k - 2*hLen - 2
// [ASYMMETRIC] PUBLIC key encrypts (random OAEP padding -> different output each time); PRIVATE key decrypts
export const rsaEncrypt = async (key: CryptoKey, bytes: Uint8Array<ArrayBuffer>) =>
  new Uint8Array(await crypto.subtle.encrypt({ name: "RSA-OAEP" }, key, bytes));
export const rsaDecrypt = async (key: CryptoKey, bytes: Uint8Array<ArrayBuffer>) =>
  new Uint8Array(await crypto.subtle.decrypt({ name: "RSA-OAEP" }, key, bytes));

// RSA-PSS: same PEM keys, imported for signing. SHA-256 + 32-byte salt, same as java/rsa/Rsa.java.
export const PSS_ALG = { name: "RSA-PSS", hash: "SHA-256" };
export const PSS_PARAMS = { name: "RSA-PSS", saltLength: 32 };
export const pssPrivate = (pem: string) => crypto.subtle.importKey("pkcs8", derOf(pem), PSS_ALG, false, ["sign"]);
export const pssPublic = (pem: string) => crypto.subtle.importKey("spki", derOf(pem), PSS_ALG, false, ["verify"]);
// [ASYMMETRIC] PRIVATE key signs (encryption run backwards); anyone's PUBLIC key verifies
export const rsaSign = async (key: CryptoKey, bytes: Uint8Array<ArrayBuffer>) =>
  new Uint8Array(await crypto.subtle.sign(PSS_PARAMS, key, bytes));
export const rsaVerify = (key: CryptoKey, sig: Uint8Array<ArrayBuffer>, bytes: Uint8Array<ArrayBuffer>) =>
  crypto.subtle.verify(PSS_PARAMS, key, sig, bytes);

export async function rsaGenerate(bits: number) {
  const kp = await crypto.subtle.generateKey(
    { ...RSA_ALG, modulusLength: bits, publicExponent: new Uint8Array([1, 0, 1]) }, true, ["encrypt", "decrypt"]);
  return {
    pub: pemOf("PUBLIC KEY", await crypto.subtle.exportKey("spki", kp.publicKey)),
    priv: pemOf("PRIVATE KEY", await crypto.subtle.exportKey("pkcs8", kp.privateKey)),
  };
}

// Fixed 2048-bit TEST key pair + ciphertext and signature of "Hello, RSA!" made by java/rsa/Rsa.java (same values there).
// Never use this key for anything real: its private half is published here.
export const RSA_TEST_PUB = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2Qg5klYLyVHpik5/PorQ
P/6hBLwdHk0wWNkEEEp1U+8sqmIMc/QTuM8fbJlFYg8WALaYksMVSyMvb3OUxi5X
XWqcSe5ddBuwHWLe4bz+S+Ev/YbYqD4bZIQmpdnozxjSz8C16bC7HQpdv+s+rf5n
5R8EcfsCp8ONA5F6K0SRJiUgDt4fF7H6I1dc4VSdAi0nMWtQAuTLIGBswKhoSUCU
0qlLDArLakMikW4u/ko3jF2RMhw/ulV1KWKHKEVfQMQunHhz446V9banZo+t/yq0
b6j9ZQrG4XChR7R9wDK5bxsuV0e4MI8HXkvcoMcGavbgBAQW/j2rGqo3lSK5teAq
mwIDAQAB
-----END PUBLIC KEY-----`;
export const RSA_TEST_PRIV = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDZCDmSVgvJUemK
Tn8+itA//qEEvB0eTTBY2QQQSnVT7yyqYgxz9BO4zx9smUViDxYAtpiSwxVLIy9v
c5TGLlddapxJ7l10G7AdYt7hvP5L4S/9htioPhtkhCal2ejPGNLPwLXpsLsdCl2/
6z6t/mflHwRx+wKnw40DkXorRJEmJSAO3h8XsfojV1zhVJ0CLScxa1AC5MsgYGzA
qGhJQJTSqUsMCstqQyKRbi7+SjeMXZEyHD+6VXUpYocoRV9AxC6ceHPjjpX1tqdm
j63/KrRvqP1lCsbhcKFHtH3AMrlvGy5XR7gwjwdeS9ygxwZq9uAEBBb+PasaqjeV
Irm14CqbAgMBAAECggEAJXozHt72+BPKBVUayf0Eixh4S64ERThFEgKfngSNkCns
B5wY1GkggrhZj9JD1fQO856UaDuB0NDJnzBRT4uvEHWZeXbM8oDZf6mUHV0aeJXx
SJFhlmPrLQdY+SjQ9/osZS28/BbFqPUiTULdNwSIgltB1EDpK3ksP6J+ezxC6FgN
a8i51b8BMSAyDQVmj4cYvMDIpVogEFhWnUHoQ/4LEr4SeNELs86y/pbAQrZZSLKi
rr6I6XDjcPV9l5He9o23NnvGnsKiL4FaThhUc2Ne7VyJsPFCTOHV17WmZOH87o1N
+okVXSesnQ4rdqVELOR1+hvRhO+jL0RK4r58CtPeaQKBgQDmFYqdUCqsEgNmnw1B
fWQz1dSUKxAqzrbaFsglzDXSM4Tm03gL6sv5SNZ9mna/bWaWsh9jL9AHo4vqA0av
BBGDfut/XoJHshVtN4RHYp0KuMUdtBz45E03MDIxZXLyjKnGlY19uTLEzDcl7v1e
xlVLYEzrY2ch1HZY2K0x9KGxTQKBgQDxelRaQAiKCFa3uuIAw/kDjsSZi/zzJVbN
3xdOl8XbDpd7QGNp29cCnjfaEwiD4fsWP0O9h0p7B+jhBzztzSlu3yPVcv2r1+t5
IJ7mIa5Xya1yZiVD9AqsZ187zn3GA0KuZ72Ihn4shXxrH1i2i+/8xeCqVRJjYvFi
TFG58YTXhwKBgQC8q9tv5qYnVdoeE7z+AAHkE6tvGOT4BWyh596WSB+2T/LiiXQ+
aXp738OrWbeYf/CJEGV2o2V2biE0cx1KNQ7bgn9AgdJZUmoJlmXNV8spWJyjH+hG
HIhJAieWo/cfeENcCZTuDKjaAhAS9igkyIR2++/3chrG/f9SGdPkTBMvXQKBgQC5
nZaJaP8nWxGNWRGwFPOsUGm+vWRKYkE/LmTz/KYRpD28d9ny3RGA6a1063x4I5Sl
nSus2/ncaFAR6UZkZHecydj5kdJ77RULno+Fxg4FXPj+HpY2jbhGnY8OocL8GjV/
ai6+auNBxbnFferrJtXqLxBq3cmsq7lwHcoUbBn4sQKBgC8CNHd+kZ4vT6yDkn99
+MjUEQK/YKVzullm/BdVCstp4K9hq9ZJWtqJwlPs4Kz+2W+CUAbv9VLgmzpq6hBc
pyJ+OdKy1DtxsltlGBsquYGfCohZbW656B21yp1JP0p+PlWtRI361nLjMZ5XYWYP
A+sqnCeTVoNdy5NYq8KSWyeo
-----END PRIVATE KEY-----`;
export const RSA_TEST_CT = 'kxGIljmm+tygYH00JeM5gSK41T3NyNbcB4U+U93+dINzvmN5+OCbiTWnEf6SZ3+rB6UAUXFkhQATbsWrTIwAFwc58uVGF71ZMsIXZma5Ik4cK1Wr6r4H9ku9AFP/3R0TQnezxrPOOsdkAU6Meecpa29coTgDsxS7R2wb2L0djird3d0Mz8vNv01rFxASS+oyzBsaK8KHadKWLUbMX+RRgVTnlgU80nFqc9HMLBrfZvW82VOw14ovjC74VRuXgkO85SmtbMrZBl7IIikNVieh3B04ZlFdOf6TGhjZje5fVxmKJl0ftzY1a83LUB3FBmAr4Y8sN0+fVw9CyYfVL9ygDw==';
export const RSA_TEST_SIG = 'QsjAQzYAuaz2nfNT280CTmCEVvCrC4KyTVxE+Hhr/wNXnZjeRoEaXX7jF7ywWxQdB9L1XNNxBqW5XTUA+yiWIQN+AzezpsgC2U+2vods645+l/CaTYA5AR1QKTMT1kL8eFC5Mlg3DIs0qBXg5nngzbazMbNVFKo3l74SYaSaCIA2uj1v5FCu/KDLst9eyB7dyf4QPeiCrBOTd/btY+mha7QNi3lKyHWdbnZMoaNqaXt2DPZOoHbksd5huAat5IwzPNR9J4n6LugtzTFdENkSBk145hhLoI/3GEuFbUlUW2oDm7TfYKQ9RzjXAmSSQvgMODTAgbeZPr/McgFDtxxXvA==';

const encode = (s: string) => new TextEncoder().encode(s);

/** The 12 self-checks, as [name, run] pairs (run resolves true on pass; a throw counts as fail). */
export function rsaChecks(): [string, () => Promise<boolean>][] {
  const fails = async (fn: () => Promise<unknown>) => { try { await fn(); return false; } catch { return true; } };
  const text = encode("Hello, RSA! café ✓");
  return [
    ["Known answer: fixed test key decrypts the ciphertext made by Java", async () =>
      new TextDecoder().decode(await rsaDecrypt(await rsaPrivate(RSA_TEST_PRIV), fromB64(RSA_TEST_CT))) === "Hello, RSA!"],
    ["Round trip: encrypt with public key, decrypt with private key", async () => {
      const ct = await rsaEncrypt(await rsaPublic(RSA_TEST_PUB), text);
      return toHex(await rsaDecrypt(await rsaPrivate(RSA_TEST_PRIV), ct)) === toHex(text);
    }],
    ["Same text twice → different output (OAEP is randomized)", async () => {
      const pub = await rsaPublic(RSA_TEST_PUB);
      return toB64(await rsaEncrypt(pub, text)) !== toB64(await rsaEncrypt(pub, text));
    }],
    ["Wrong private key is rejected", async () => {
      const ct = await rsaEncrypt(await rsaPublic(RSA_TEST_PUB), text);
      const other = await rsaGenerate(2048);
      return fails(async () => rsaDecrypt(await rsaPrivate(other.priv), ct));
    }],
    ["Changed ciphertext is rejected", async () => {
      const ct = fromB64(RSA_TEST_CT);
      ct[10] ^= 1;
      return fails(async () => rsaDecrypt(await rsaPrivate(RSA_TEST_PRIV), ct));
    }],
    ["2048-bit key: 190-byte message works, 191 bytes is rejected", async () => {
      const pub = await rsaPublic(RSA_TEST_PUB), priv = await rsaPrivate(RSA_TEST_PRIV);
      const ok = (await rsaDecrypt(priv, await rsaEncrypt(pub, new Uint8Array(190).fill(97)))).length === 190;
      return ok && fails(() => rsaEncrypt(pub, new Uint8Array(191)));
    }],
    ["PEM export/import round trip", async () => {
      const { pub, priv } = await rsaGenerate(2048);
      const k = await crypto.subtle.importKey("spki", derOf(pub), RSA_ALG, true, ["encrypt"]);
      const k2 = await crypto.subtle.importKey("pkcs8", derOf(priv), RSA_ALG, true, ["decrypt"]);
      return pemOf("PUBLIC KEY", await crypto.subtle.exportKey("spki", k)) === pub
        && pemOf("PRIVATE KEY", await crypto.subtle.exportKey("pkcs8", k2)) === priv;
    }],
    ["Known answer: fixed test public key verifies the signature made by Java", async () =>
      rsaVerify(await pssPublic(RSA_TEST_PUB), fromB64(RSA_TEST_SIG), encode("Hello, RSA!"))],
    ["Sign with private key, verify with public key; signing twice gives different valid signatures", async () => {
      const priv = await pssPrivate(RSA_TEST_PRIV), pub = await pssPublic(RSA_TEST_PUB);
      const s1 = await rsaSign(priv, text), s2 = await rsaSign(priv, text);
      return toB64(s1) !== toB64(s2) && await rsaVerify(pub, s1, text) && await rsaVerify(pub, s2, text);
    }],
    ["Changed message is rejected", async () =>
      !(await rsaVerify(await pssPublic(RSA_TEST_PUB), fromB64(RSA_TEST_SIG), encode("Hello, RSA?")))],
    ["Changed signature is rejected", async () => {
      const sig = fromB64(RSA_TEST_SIG);
      sig[10] ^= 1;
      return !(await rsaVerify(await pssPublic(RSA_TEST_PUB), sig, encode("Hello, RSA!")));
    }],
    ["Wrong public key is rejected", async () => {
      const other = await rsaGenerate(2048);
      return !(await rsaVerify(await pssPublic(other.pub), fromB64(RSA_TEST_SIG), encode("Hello, RSA!")));
    }],
  ];
}
