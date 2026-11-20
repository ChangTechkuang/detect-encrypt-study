import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

/**
 * RSA demo for learning. Asymmetric: a key pair, used two opposite ways.
 *   Encryption, RSA-OAEP (SHA-256): public key encrypts, only the private key decrypts.
 *   Signature,  RSA-PSS  (SHA-256): only the private key signs, anyone with the public key verifies.
 *
 * Why ASYMMETRIC? Two DIFFERENT keys. Compare SEED/AES (symmetric): one shared key does both jobs,
 * so both sides must already share a secret. With RSA you publish the public key to everyone and
 * nothing secret ever has to be sent.
 *
 * How it works (the math Java does inside Cipher / Signature):
 *   Key pair:  pick two huge random primes p, q (1024 bits each for RSA-2048)
 *              n = p * q          (the "modulus", 2048 bits, in BOTH keys)
 *              e = 65537          (public exponent)
 *              d = e^-1 mod (p-1)(q-1)   (private exponent: needs p and q to compute)
 *              public key = (n, e)       private key = (n, d)  [+ p, q to make it faster]
 *   Encrypt:   c = m^e mod n      (anyone, with the public key)
 *   Decrypt:   m = c^d mod n      (only the owner of d)
 *   Sign:      s = h^d mod n      (h = padded SHA-256 of the message; only the owner of d)
 *   Verify:    s^e mod n == h ?   (anyone, with the public key)
 *   Security:  getting d from (n, e) means factoring n into p * q, which nobody can do for 2048 bits.
 *
 * Never use this raw "textbook" math: the same m always gives the same c, and it can be forged.
 * OAEP and PSS add random padding around m / h first. That is what the parameter specs below set up.
 *
 * RSA can only encrypt a small message: (key bytes - 66) bytes, e.g. 190 bytes for a 2048-bit key.
 * Real systems use it to encrypt a random AES key, and AES encrypts the data ("hybrid encryption").
 * Signing has no size limit: the message is hashed with SHA-256 first.
 *
 * Keys are PEM: public = SPKI "PUBLIC KEY", private = PKCS#8 "PRIVATE KEY" (same as the Implement page (src/lib/impl)).
 * Ciphertext and signature: Base64, always key-size bytes (256 bytes for 2048-bit).
 *
 * Run:  java Rsa.java                                  (self-checks)
 *       java Rsa.java genkey [2048|3072|4096]          (writes public.pem + private.pem here)
 *       java Rsa.java encrypt public.pem "text"
 *       java Rsa.java decrypt private.pem <base64>
 *       java Rsa.java sign    private.pem "text"
 *       java Rsa.java verify  public.pem  "text" <signature-base64>
 */
public class Rsa {
    // Java's "OAEPWithSHA-256AndMGF1Padding" uses SHA-1 inside MGF1. Spell out SHA-256 for both,
    // which is what Web Crypto (and the Implement page (src/lib/impl)) uses, so the two can decrypt each other's output.
    private static final OAEPParameterSpec OAEP_SHA256 =
            new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);

    /** Makes p, q, n, e, d (see the header). Slow for 4096 bits: finding big primes takes many tries. */
    public static KeyPair generateKeyPair(int bits) throws GeneralSecurityException {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(bits);
        return g.generateKeyPair();
    }

    /**
     * [ASYMMETRIC] PUBLIC key encrypts: OAEP pads the text with random bytes, then c = m^e mod n.
     * The random padding is why the same text gives different output every time.
     */
    public static String encrypt(String plaintext, PublicKey key) throws GeneralSecurityException {
        Cipher c = Cipher.getInstance("RSA/ECB/OAEPPadding"); // "ECB" is just Java's name: RSA has no blocks/modes
        c.init(Cipher.ENCRYPT_MODE, key, OAEP_SHA256);
        return Base64.getEncoder().encodeToString(c.doFinal(plaintext.getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * [ASYMMETRIC] PRIVATE key decrypts: m = c^d mod n, then OAEP checks and removes its padding.
     * Throws BadPaddingException if the private key is wrong or the ciphertext was changed.
     */
    public static String decrypt(String encrypted, PrivateKey key) throws GeneralSecurityException {
        Cipher c = Cipher.getInstance("RSA/ECB/OAEPPadding");
        c.init(Cipher.DECRYPT_MODE, key, OAEP_SHA256);
        return new String(c.doFinal(Base64.getDecoder().decode(encrypted.trim())), StandardCharsets.UTF_8);
    }

    // RSA-PSS with SHA-256, MGF1-SHA-256 and a 32-byte salt: the same as Web Crypto { name: 'RSA-PSS', saltLength: 32 }
    private static final PSSParameterSpec PSS_SHA256 =
            new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, PSSParameterSpec.TRAILER_FIELD_BC);

    /**
     * [ASYMMETRIC] PRIVATE key signs: h = PSS(SHA-256(message), random salt), then s = h^d mod n.
     * Encryption run backwards: the private key "locks", and anyone's public key "unlocks" to check.
     * PSS uses a random salt, so signing twice gives different signatures.
     */
    public static String sign(String message, PrivateKey key) throws GeneralSecurityException {
        Signature s = Signature.getInstance("RSASSA-PSS");
        s.setParameter(PSS_SHA256);
        s.initSign(key);
        s.update(message.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(s.sign());
    }

    /**
     * [ASYMMETRIC] PUBLIC key verifies: computes s^e mod n and checks it is the PSS padding of SHA-256(message).
     * True only if the signature was made by the matching private key over exactly this message.
     */
    public static boolean verify(String message, String signature, PublicKey key) throws GeneralSecurityException {
        Signature s = Signature.getInstance("RSASSA-PSS");
        s.setParameter(PSS_SHA256);
        s.initVerify(key);
        s.update(message.getBytes(StandardCharsets.UTF_8));
        try {
            return s.verify(Base64.getDecoder().decode(signature.trim()));
        } catch (SignatureException | IllegalArgumentException e) { // malformed signature or Base64
            return false;
        }
    }

    public static String toPem(PublicKey k) { return pem("PUBLIC KEY", k.getEncoded()); }
    public static String toPem(PrivateKey k) { return pem("PRIVATE KEY", k.getEncoded()); }

    private static String pem(String type, byte[] der) {
        String b64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(der);
        return "-----BEGIN " + type + "-----\n" + b64 + "\n-----END " + type + "-----\n";
    }

    private static byte[] der(String pem) {
        return Base64.getMimeDecoder().decode(pem.replaceAll("-----[A-Z ]+-----", ""));
    }

    public static PublicKey publicFromPem(String pem) throws GeneralSecurityException {
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(der(pem)));
    }

    public static PrivateKey privateFromPem(String pem) throws GeneralSecurityException {
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der(pem)));
    }

    // Fixed 2048-bit TEST key pair, plus a ciphertext and a signature of "Hello, RSA!" made with it.
    // The same values are in the Implement page (src/lib/impl), so both sides prove they use each other's format.
    // Never use this key for anything real: its private half is published here.
    static final String TEST_PUBLIC_PEM = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2Qg5klYLyVHpik5/PorQ
P/6hBLwdHk0wWNkEEEp1U+8sqmIMc/QTuM8fbJlFYg8WALaYksMVSyMvb3OUxi5X
XWqcSe5ddBuwHWLe4bz+S+Ev/YbYqD4bZIQmpdnozxjSz8C16bC7HQpdv+s+rf5n
5R8EcfsCp8ONA5F6K0SRJiUgDt4fF7H6I1dc4VSdAi0nMWtQAuTLIGBswKhoSUCU
0qlLDArLakMikW4u/ko3jF2RMhw/ulV1KWKHKEVfQMQunHhz446V9banZo+t/yq0
b6j9ZQrG4XChR7R9wDK5bxsuV0e4MI8HXkvcoMcGavbgBAQW/j2rGqo3lSK5teAq
mwIDAQAB
-----END PUBLIC KEY-----""";
    static final String TEST_PRIVATE_PEM = """
-----BEGIN PRIVATE KEY-----
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
-----END PRIVATE KEY-----""";
    static final String TEST_CIPHERTEXT = "kxGIljmm+tygYH00JeM5gSK41T3NyNbcB4U+U93+dINzvmN5+OCbiTWnEf6SZ3+rB6UAUXFkhQATbsWrTIwAFwc58uVGF71ZMsIXZma5Ik4cK1Wr6r4H9ku9AFP/3R0TQnezxrPOOsdkAU6Meecpa29coTgDsxS7R2wb2L0djird3d0Mz8vNv01rFxASS+oyzBsaK8KHadKWLUbMX+RRgVTnlgU80nFqc9HMLBrfZvW82VOw14ovjC74VRuXgkO85SmtbMrZBl7IIikNVieh3B04ZlFdOf6TGhjZje5fVxmKJl0ftzY1a83LUB3FBmAr4Y8sN0+fVw9CyYfVL9ygDw==";

    static final String TEST_SIGNATURE = "QsjAQzYAuaz2nfNT280CTmCEVvCrC4KyTVxE+Hhr/wNXnZjeRoEaXX7jF7ywWxQdB9L1XNNxBqW5XTUA+yiWIQN+AzezpsgC2U+2vods645+l/CaTYA5AR1QKTMT1kL8eFC5Mlg3DIs0qBXg5nngzbazMbNVFKo3l74SYaSaCIA2uj1v5FCu/KDLst9eyB7dyf4QPeiCrBOTd/btY+mha7QNi3lKyHWdbnZMoaNqaXt2DPZOoHbksd5huAat5IwzPNR9J4n6LugtzTFdENkSBk145hhLoI/3GEuFbUlUW2oDm7TfYKQ9RzjXAmSSQvgMODTAgbeZPr/McgFDtxxXvA==";

    public static void main(String[] args) throws Exception {
        if (args.length >= 1 && args[0].equals("genkey")) {
            KeyPair kp = generateKeyPair(args.length > 1 ? Integer.parseInt(args[1]) : 2048);
            Files.writeString(Path.of("public.pem"), toPem(kp.getPublic()));
            Files.writeString(Path.of("private.pem"), toPem(kp.getPrivate()));
            System.out.println("Wrote public.pem and private.pem. Keep private.pem secret.");
            return;
        }
        if (args.length >= 3) {
            String pem = Files.readString(Path.of(args[1]));
            System.out.println(switch (args[0]) {
                case "encrypt" -> encrypt(args[2], publicFromPem(pem));
                case "decrypt" -> decrypt(args[2], privateFromPem(pem));
                case "sign" -> sign(args[2], privateFromPem(pem));
                case "verify" -> verify(args[2], args[3], publicFromPem(pem)) ? "VALID" : "INVALID";
                default -> throw new IllegalArgumentException("Unknown command: " + args[0]);
            });
            return;
        }

        PublicKey testPub = publicFromPem(TEST_PUBLIC_PEM);
        PrivateKey testPriv = privateFromPem(TEST_PRIVATE_PEM);
        check(decrypt(TEST_CIPHERTEXT, testPriv).equals("Hello, RSA!"), "known answer: fixed test key decrypts fixed ciphertext");
        check(publicFromPem(toPem(testPub)).equals(testPub) && privateFromPem(toPem(testPriv)).equals(testPriv), "PEM export/import round trip");

        for (int bits : new int[] {2048, 3072, 4096}) {
            KeyPair kp = generateKeyPair(bits);
            String text = "Hello, RSA-" + bits + "! café ✓";
            String enc = encrypt(text, kp.getPublic());
            check(decrypt(enc, kp.getPrivate()).equals(text), "RSA-" + bits + " round trip (" + Base64.getDecoder().decode(enc).length + "-byte ciphertext)");

            int max = bits / 8 - 66; // OAEP-SHA256 limit: k - 2*hLen - 2
            check(decrypt(encrypt("a".repeat(max), kp.getPublic()), kp.getPrivate()).length() == max, "RSA-" + bits + " max message = " + max + " bytes");
            check(throwsType(IllegalBlockSizeException.class, () -> encrypt("a".repeat(max + 1), kp.getPublic())), "RSA-" + bits + " message of " + (max + 1) + " bytes is rejected");
        }

        String enc = encrypt("Hello, RSA!", testPub);
        check(!encrypt("Hello, RSA!", testPub).equals(enc), "same text twice -> different output (OAEP is randomized)");
        check(throwsType(BadPaddingException.class, () -> decrypt(enc, generateKeyPair(2048).getPrivate())), "wrong private key is rejected");
        byte[] tampered = Base64.getDecoder().decode(enc);
        tampered[10] ^= 1;
        check(throwsType(BadPaddingException.class, () -> decrypt(Base64.getEncoder().encodeToString(tampered), testPriv)), "changed ciphertext is rejected");

        // Signatures (RSA-PSS)
        check(verify("Hello, RSA!", TEST_SIGNATURE, testPub), "known answer: fixed signature verifies with the test public key");
        String msg = "Version 1.2 release approved";
        String sig = sign(msg, testPriv);
        check(verify(msg, sig, testPub), "sign with private key, verify with public key");
        String sig2 = sign(msg, testPriv);
        check(!sig2.equals(sig) && verify(msg, sig2, testPub), "signing twice -> different signatures (PSS random salt), both valid");
        check(!verify("Version 1.3 release approved", sig, testPub), "changed message is rejected");
        byte[] badSig = Base64.getDecoder().decode(sig);
        badSig[10] ^= 1;
        check(!verify(msg, Base64.getEncoder().encodeToString(badSig), testPub), "changed signature is rejected");
        check(!verify(msg, sig, generateKeyPair(2048).getPublic()), "wrong public key is rejected");
        check(!verify(msg, "not base64!", testPub), "malformed signature -> false, no crash");
        String big = "x".repeat(100_000);
        check(verify(big, sign(big, testPriv), testPub), "100,000-byte message signs fine (it is hashed first)");
        System.out.println("All checks passed.");
    }

    private interface Action { void run() throws Exception; }

    private static boolean throwsType(Class<? extends Exception> type, Action a) {
        try { a.run(); return false; } catch (Exception e) { return type.isInstance(e); }
    }

    private static void check(boolean ok, String name) {
        if (!ok) throw new AssertionError("FAILED: " + name);
        System.out.println("  ok  " + name);
    }
}
