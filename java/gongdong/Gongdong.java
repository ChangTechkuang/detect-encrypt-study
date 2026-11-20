import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;

/**
 * 공동인증서 (Korean joint certificate, formerly 공인인증서; NPKI) demo for learning.
 *
 * A certificate set is three files, like NPKI/<CA>/USER/<user>/ on a Korean PC:
 *   caCert.der   the CA's certificate (real ones are built into the software)
 *   signCert.der X.509 v3 certificate: your name + public key, signed by the CA (RSA-2048, SHA-256)
 *   signPri.key  your private key (PKCS #8), encrypted with your certificate password:
 *                PBKDF1-SHA1(password, 8-byte salt, 2048 rounds) -> 20 bytes DK
 *                SEED key = DK[0..16], IV = SHA-1(DK[16..20])[0..16], SEED-CBC + PKCS#7
 *                OID 1.2.410.200004.1.15 (KISA pbeWithSHA1AndSEED-CBC)
 * Signing = RSA PKCS #1 v1.5 with SHA-256 using the unlocked private key.
 *
 * Is it symmetric or asymmetric? ASYMMETRIC. Each part of this file is one or the other:
 *
 *   [ASYMMETRIC] issue(), sign(), verify(), open()'s CA check: RSA key pairs
 *       private key signs, public key verifies. The bank / 홈택스 only ever gets your PUBLIC key
 *       (inside signCert.der), so it can check your signatures but can never make one. That is the
 *       whole point of the certificate, and why 공동인증서 is asymmetric.
 *
 *   [SYMMETRIC]  keyIv(), lockKey(), unlockKey(): SEED with a password-derived key
 *       ONE key both locks and unlocks signPri.key. It only protects the private key file on your
 *       own disk (a stolen file is useless without the password). The password and the SEED key
 *       never leave your PC, and nobody else ever needs them.
 *
 *   Flow:  password --(symmetric: SEED decrypt)--> RSA private key --(asymmetric: RSA sign)--> signature
 *          signature + signCert.der --(asymmetric: RSA verify with the public key)--> valid / invalid
 *
 * Everything here is made-up test data from a made-up "TestCA". Not a real certificate.
 * Same formats as the Implement page (src/lib/impl). Run: java Gongdong.java
 */
public class Gongdong {
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final HexFormat HEX = HexFormat.of();
    private static final String OID_SHA256_RSA = "1.2.840.113549.1.1.11", OID_SEED_SHA1 = "1.2.410.200004.1.15";

    public record CertSet(byte[] caCert, byte[] signCert, byte[] signPri) {}
    public record Opened(X509Certificate cert, PrivateKey key, boolean keyMatches, boolean signedByCA) {}

    // ---------- [ASYMMETRIC] Issue: the CA signs your public key ----------
    // Two RSA key pairs: the CA's and yours. The CA's PRIVATE key signs your certificate;
    // anyone checks it later with the CA's PUBLIC key (in caCert.der). Your private key is then
    // handed to the symmetric part (lockKey) to be stored safely.

    public static CertSet issueSet(String holder, String password) throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        KeyPair ca = g.generateKeyPair(), user = g.generateKeyPair();
        byte[] caName = Der.name(new String[][]{{"c", "KR"}, {"o", "TestCA"}, {"cn", "Test Root CA (learning only)"}});
        StringBuilder id = new StringBuilder();
        for (int i = 0; i < 10; i++) id.append(RANDOM.nextInt(10));
        byte[] userName = Der.name(new String[][]{{"c", "KR"}, {"o", "TestCA"}, {"ou", "personal"}, {"cn", holder + "()" + id}});
        byte[] caCert = issue(caName, caName, ca.getPublic(), ca.getPrivate(), true, 3650);
        byte[] signCert = issue(caName, userName, user.getPublic(), ca.getPrivate(), false, 365);
        return new CertSet(caCert, signCert, lockKey(user.getPrivate().getEncoded(), password));
    }

    /** X.509 v3 certificate, signed by the CA's private key with SHA-256 + RSA. */
    static byte[] issue(byte[] issuer, byte[] subject, PublicKey pub, PrivateKey caKey, boolean isCA, int days) throws GeneralSecurityException {
        byte[] serial = new byte[8];
        RANDOM.nextBytes(serial);
        serial[0] &= 0x7f;
        byte[] alg = Der.seq(Der.oid(OID_SHA256_RSA), Der.NULL);
        byte[] exts = isCA
            ? Der.seq(Der.seq(Der.oid("2.5.29.19"), Der.TRUE, Der.octet(Der.seq(Der.TRUE))),                       // basicConstraints: CA
                      Der.seq(Der.oid("2.5.29.15"), Der.TRUE, Der.octet(Der.bits(new byte[]{0x06}, 1))))           // keyCertSign, cRLSign
            : Der.seq(Der.seq(Der.oid("2.5.29.15"), Der.TRUE, Der.octet(Der.bits(new byte[]{(byte) 0xc0}, 6)))); // digitalSignature, nonRepudiation
        ZonedDateTime now = ZonedDateTime.now(ZoneOffset.UTC).withNano(0);
        byte[] tbs = Der.seq(
            Der.tlv(0xa0, Der.integer(new byte[]{2})), Der.integer(serial), alg, issuer,
            Der.seq(Der.time(now), Der.time(now.plusDays(days))),
            subject, pub.getEncoded(), Der.tlv(0xa3, exts));
        return Der.seq(tbs, alg, Der.bits(sign(caKey, tbs), 0));
    }

    // ---------- [SYMMETRIC] signPri.key: SEED-CBC with a key from PBKDF1-SHA1 ----------
    // The same SEED key encrypts (lockKey) and decrypts (unlockKey): that is what symmetric means.
    // The key is not stored anywhere: it is rebuilt from the password + salt every time.
    // Slow on purpose (2048 x SHA-1) so guessing passwords takes longer.

    /** password + salt -> SHA-1 x iter -> DK (20 bytes) -> SEED key (16 bytes) and IV (16 bytes). */
    static byte[][] keyIv(String password, byte[] salt, int iter) throws GeneralSecurityException {
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        sha1.update(password.getBytes(StandardCharsets.UTF_8));
        byte[] dk = sha1.digest(salt);
        for (int i = 1; i < iter; i++) dk = sha1.digest(dk);
        byte[] iv = Arrays.copyOf(sha1.digest(Arrays.copyOfRange(dk, 16, 20)), 16); // IV = SHA-1(last 4 bytes of DK)
        return new byte[][]{Arrays.copyOf(dk, 16), iv};
    }

    /** SYMMETRIC encrypt: RSA private key (PKCS #8 bytes) -> signPri.key. Salt and rounds are stored in the file, in clear. */
    static byte[] lockKey(byte[] pkcs8, String password) throws GeneralSecurityException {
        byte[] salt = new byte[8];
        RANDOM.nextBytes(salt);
        int iter = 2048;
        byte[][] ki = keyIv(password, salt, iter);
        int pad = 16 - pkcs8.length % 16;
        byte[] padded = Arrays.copyOf(pkcs8, pkcs8.length + pad);
        Arrays.fill(padded, pkcs8.length, padded.length, (byte) pad);
        return Der.seq(Der.seq(Der.oid(OID_SEED_SHA1), Der.seq(Der.octet(salt), Der.integer(BigIntBytes(iter)))),
                Der.octet(Seed.cbc(true, ki[0], ki[1], padded)));
    }

    /**
     * SYMMETRIC decrypt: signPri.key + the SAME password -> the same SEED key -> RSA private key.
     * A wrong password gives a wrong SEED key, so the output is garbage: caught by the padding check
     * (or, rarely, because the garbage is not a valid key). Throws in both cases.
     */
    static PrivateKey unlockKey(byte[] signPri, String password) throws GeneralSecurityException {
        Der.El root = Der.parse(signPri, 0), alg = root.kids.get(0);
        String oid = Der.oidOf(alg.kids.get(0));
        if (!oid.equals(OID_SEED_SHA1)) throw new GeneralSecurityException("not SEED-CBC with SHA-1 (" + oid + ")");
        byte[] salt = alg.kids.get(1).kids.get(0).body;
        int iter = new java.math.BigInteger(1, alg.kids.get(1).kids.get(1).body).intValueExact();
        byte[][] ki = keyIv(password, salt, iter);
        byte[] pt = Seed.cbc(false, ki[0], ki[1], root.kids.get(1).body);
        int pad = pt[pt.length - 1] & 0xff;
        if (pad < 1 || pad > 16) throw new GeneralSecurityException("wrong password (bad padding)");
        for (int i = pt.length - pad; i < pt.length; i++) if ((pt[i] & 0xff) != pad) throw new GeneralSecurityException("wrong password (bad padding)");
        try {
            return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Arrays.copyOf(pt, pt.length - pad)));
        } catch (Exception e) {
            throw new GeneralSecurityException("wrong password (not a key)"); // garbage that passed the padding check
        }
    }

    // ---------- Open (symmetric unlock + asymmetric checks), sign, verify (asymmetric) ----------

    static X509Certificate cert(byte[] der) throws GeneralSecurityException {
        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(der));
    }

    /** What a program checks before trusting a certificate set. Validity dates: cert.checkValidity(). */
    public static Opened open(CertSet set, String password) throws GeneralSecurityException {
        X509Certificate ca = cert(set.caCert()), c = cert(set.signCert());
        PrivateKey key = unlockKey(set.signPri(), password);                 // SYMMETRIC: password unlocks the file
        // ASYMMETRIC pair check: a private key and its public key share the same modulus n
        boolean matches = ((RSAPrivateCrtKey) key).getModulus().equals(((RSAPublicKey) c.getPublicKey()).getModulus());
        boolean byCA;
        try {
            c.verify(ca.getPublicKey());                                     // ASYMMETRIC: CA's public key checks the CA's signature
            byCA = c.getIssuerX500Principal().equals(ca.getSubjectX500Principal());
        } catch (GeneralSecurityException e) {
            byCA = false;
        }
        return new Opened(c, key, matches, byCA);
    }

    /** ASYMMETRIC: only the holder of the PRIVATE key can make this. SHA-256 hash of data, then RSA. */
    static byte[] sign(PrivateKey key, byte[] data) throws GeneralSecurityException {
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initSign(key);
        s.update(data);
        return s.sign();
    }

    /** ASYMMETRIC: anyone can check with the PUBLIC key from the certificate. No password, no secret needed. */
    static boolean verify(X509Certificate cert, byte[] data, byte[] sig) throws GeneralSecurityException {
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initVerify(cert.getPublicKey());
        s.update(data);
        return s.verify(sig);
    }

    // ---------- Fixed test sets (password test1234!) and a signature of FIXTURE_MSG ----------
    static final String FIXTURE_PW = "test1234!", FIXTURE_MSG = "I agree to the contract";
    // Made by the Implement page's code (same values there): proves Java opens what the page makes
    static final String PAGE_CA = "MIIDLzCCAhegAwIBAgIINQgSZqvUg7AwDQYJKoZIhvcNAQELBQAwRTELMAkGA1UEBhMCS1IxDzANBgNVBAoMBlRlc3RDQTElMCMG"
        + "A1UEAwwcVGVzdCBSb290IENBIChsZWFybmluZyBvbmx5KTAeFw0yNjExMjAwNTA1NDdaFw0zNjExMTcwNTA1NDdaMEUxCzAJBgNV"
        + "BAYTAktSMQ8wDQYDVQQKDAZUZXN0Q0ExJTAjBgNVBAMMHFRlc3QgUm9vdCBDQSAobGVhcm5pbmcgb25seSkwggEiMA0GCSqGSIb3"
        + "DQEBAQUAA4IBDwAwggEKAoIBAQDeqifs3Lz7Kis0s1YppjM4RHjPguMWMzLT9oiEz+UDRAiAaeZ0Yv9Ao3VyggkKjDyIIiBJYVtx"
        + "PPDZeDTSQi1NDpE6pAEG0urawMYnWSpcHcA14bx3ltpspekKzdMtGSzmHCvVpd59G0vSIBiqTC4bHztrqGkBXL0dlIFvHVR/ESGL"
        + "m+o/UrqIq4U+6UZf7r8SnULrroWUM+e2Ir22/wiR060YbdechyKegVeInjuvuEsUJytY1Vqn5CH/qHI0BjhCXOMha1dwBm8bZUpn"
        + "PknVjqu2vmHqqGAaXdfaR0YFOQdIUMEjbga4gaAsZc9K1IX2naSdRmcXORoJA5F54hBnAgMBAAGjIzAhMA8GA1UdEwEB/wQFMAMB"
        + "Af8wDgYDVR0PAQH/BAQDAgEGMA0GCSqGSIb3DQEBCwUAA4IBAQCWI7DG8xtK3JOWcJBx8yx4tEp6uEppjgiNQk4KF5uyMkxvgxEt"
        + "wksucc8f3mJvOLgI71Opq190+g/MODhP2xwQrhrjLw8ZZ7KniN5+fIFV61vN5SNnBxHE0Di5uoptvJWUCI23CuMyOVsqUqC2gJDl"
        + "E5FCw2zc2r25NE3kE/0QxsZirAQPaE7V98vCl1hnwwVfD31eQURXX+YL40kV7CSdxTxbC1whAQY4opTjuisNSDdqK2rI1orzeq30"
        + "i3l6pdfbC54t+ZqbfIvyUgfJ3mRMXp75I0hd/a0qtA52nNvsavuG8BbSq0G/TyZ8NZ8IB6q4W/day2ZuTGe8nyG//fGc", PAGE_CERT = "MIIDKjCCAhKgAwIBAgIIRmG7dqp4OfMwDQYJKoZIhvcNAQELBQAwRTELMAkGA1UEBhMCS1IxDzANBgNVBAoMBlRlc3RDQTElMCMG"
        + "A1UEAwwcVGVzdCBSb290IENBIChsZWFybmluZyBvbmx5KTAeFw0yNjExMjAwNTA1NDdaFw0yNzExMjAwNTA1NDdaMFExCzAJBgNV"
        + "BAYTAktSMQ8wDQYDVQQKDAZUZXN0Q0ExETAPBgNVBAsMCHBlcnNvbmFsMR4wHAYDVQQDDBXtmY3quLjrj5koKTk1NjgzODIzNzkw"
        + "ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC+emZ6aR4qv99EfXi7rCZc8j3j8BrRBemCmHP8GKE505PglvYDQoB7yp97"
        + "7uCh5Hcq6j7bBbDdGO17OQNwq2p9epEbnpK5+RuVGyA70qoTOf75oaOv/OEUPRxmT/K73TwmjrKtRWqlsNChbrykTY7Avv37ofVI"
        + "IcQ729ZgvB7Kfmz5gAMA1zAQD8xbpRS+3ENQ8gcyeI7kAbKLgD+IoUSZqou8wLhrvmu7qgGx4x++c8BG31icVkpCUWKkTqrd5O3I"
        + "mANgFrXKvx+kdeiJhu0n5PWskY8RwMe11do3of7xHKIPJh4VmhB1r0BWHSZttv0+R6qIIRax7Y5hW8n0sB61AgMBAAGjEjAQMA4G"
        + "A1UdDwEB/wQEAwIGwDANBgkqhkiG9w0BAQsFAAOCAQEAI73Y3pOnS75EctxYUu/GZ/6Hjovp7n2gRk59iasPfLQe+y/bXFoZjYfF"
        + "Y1ZHfW2sZ6UAQSJzrjFBFR/n9sW9iEAAZcN7mCMYLBeMsebLWcQvtpBq5P8WjxAxGzeQmgJPrIR1ix/Athjn6zD1lxJe1POeW+Gl"
        + "/BiilWztH6ZgmzLEfmqeee49f6QHYl+E9+YqrYfvyPNs8oc/fL2qooVPDrtVxEI8Sw0ijUeRxRoAOW7b1K2zCbi0I2nma/q0fLwy"
        + "KEr5SpkiDZpNlsI3iCfZB6/IyyLbUSnfZC8WUivEjIGTBrf6kBHGyyjwiFHKbAFfbZKjR9htnVKhZR4/6BNkkw==", PAGE_KEY = "MIIE8DAaBggqgxqMmkQBDzAOBAg/l9j0b51YNgICCAAEggTQkJuEUMXlg8Db7TPnCwp+zkA3mTVIjd3swzx9DydoMwzZlYtOIfRb"
        + "RSSarXee5Zl8XDncmGbH3okfIzoOtaJybFlxJfmdbr5Ys29bjG+eHPLk80Rqs78uynLBIPLFGac3mxS9ln7m5BU8A4IKS7OsA8Nr"
        + "SCbsNC6kI9tn5ABf4xCeZP/zZ0h5u5NuNWyWH73dGLE1zhDejdTKrbooFFyoIUo+wzjKj7oUdvwkBu8j8RnfHg6TXQ6Q5i1T4oky"
        + "FB6OFCKgvWOUocEP1BnpO5HVZOm5n6zwuIkzlTI/mALN2RoJQApFcbxsIJzvDSCEXYyFSzC9NI5sYcqUgQ8i+3d8J5SVGqA0Ol+5"
        + "YDsjJKMC+KPEEoMyqyvzg1E5s4wmBkJ4aVrtW9zuLHcE8Y6qRx7uQ9b3CNy1nOd5FE3cTisvFM5nuxpVOEXDpPe9dFUoNad2Y5UX"
        + "frbI/4Qew/A/DywjwtTzBwDUad1Vw585P7E8/UDuG0xyRiY0JnxqQDbIl3eAsCxgINZTCgm8+S7K1Ul3EtQH2e1S0kgvLjacn0sv"
        + "DT0gzIrgK2kSirGQL8rv5fb1vmQrA3In+VMA4mBwMJBr5clUZI6tDE6AEKVI+l9lJkuq2eIaYoiafS6BVjbAGa6IDiQeSDzxI1Ox"
        + "WKSXKdQvnu2Ref3yRRempd6yFiJNVbCfL9wHyifQJqvwG0bxJVioiiA4srEcArOA04R7ylJdciDagqAib/7TuVmMC8zlNo/pMLPs"
        + "TMcC6KdSnLhFvl8ZetsEUQQKJJOIHNt/t2Ylh9cZy9+w5scbiWEUFarCZu92c7Lg2wxG+vUNsiwZ+BBzmxGkFkFgMyhW/S75QgcF"
        + "4HSIZYQKeCSsSAalVYYsLpm6Pc7epmeQTdh5IT7AA1CfaVqQsRX6PbBrORjx2MTgvKzzK/lelsGISn49h4ABHkbYw3AxjuUTdZlS"
        + "kxBb7tvDETvbv8UR6mLmetECu68dQGj7V9SEzHYX1p+t+UYGJyH4LH3VQ7U18LLQq8srO1r4R5y9VChDXAHVcKnRwdI/zA3vPyYl"
        + "y9qGsKcm8SE8vqHJI2acB4AWTtvNDyJ8n0/jaCbDnmSICXJtV/YYKF0stUrX+C5bWzG7N+QiOIZS7oBHM+y7X3jqTmqI24yLVePv"
        + "WoQwIvuHW8tLREvvmIgAn+Wotkcmk+B83Drkmh0plQfJDsSMXyMSTaEjqmDMUDbZRuRRKXwZN34iU9dypp7vk10ypcZA9FwoJAYf"
        + "gQDRXLVCAU2y/8JG9c2vzPeiLLIGMfp9kvRfNuJNb2W0ed/pkKUruFHUqv+u/HYhUxTia6bziSj9FG5Oc5M3ylVQABp0s/ctBI9m"
        + "6YwB6xrYikQAt+PGvs6QkRN98wA2ioihlc4eXP0zMVZ/lm01HNznKf8Kh7JJPWR5mPsMn+/fcopURFEJTdcp8uCXc9au/CB0g3d7"
        + "qWPhMv04j7E0/nQ/Y/M0pwNaUi6x0KMgBfjTFUr74nahhSv3XpFw1wIy4L8wvY9t+bO/4sO/zNzSfjd2dj+aZXwjfFweohMBqiDY"
        + "FaHIXY4jxFrTw0m9aTPUhsfQusAJQ2iEjORrIiKx2rdCp00bG3AdpAjry+Ki0eMOcF/uUetc2MvbuWaE5JLtUOHTImY=", PAGE_SIG = "o7LVikS8LIC8VK9K7ST01sRwzHDIhX8z5mWkmf9vfqcGK9CK4BnFfwZsT/Lj2G9l3gTxu25Y8GlpAnlFIss83UvCPaMKxxl4U6xV"
        + "j+IYf5ZnUATrfU7YizEJSSmoHsFxHEiJwfVkNltdTQH7GBC0ru+n3bTzTNaRAWSHsNt3rk25wC//y0/C/gM8RSp+qGCzxvHh/l3D"
        + "0PAM/3htsqae/G53I7OBZAfjSfZ1yuAGiCMoWunWI+GX7lBn3NGDqfaSR/a9TGfBQsrmZ/knb+J+LcLJwP25QeyikbVUIXjvHb6t"
        + "ldby9PML1+yrl0xLcnmchN5U1Lv651oRZbYFOfCYLw==";
    // Made by this file (same values in the Implement page (src/lib/impl)): proves the page opens what Java makes
    static final String JAVA_CA = "MIIDLzCCAhegAwIBAgIIYuekDupGIwUwDQYJKoZIhvcNAQELBQAwRTELMAkGA1UEBhMCS1IxDzANBgNVBAoMBlRlc3RDQTElMCMG"
        + "A1UEAwwcVGVzdCBSb290IENBIChsZWFybmluZyBvbmx5KTAeFw0yNjExMjAwNTA1NDlaFw0zNjExMTcwNTA1NDlaMEUxCzAJBgNV"
        + "BAYTAktSMQ8wDQYDVQQKDAZUZXN0Q0ExJTAjBgNVBAMMHFRlc3QgUm9vdCBDQSAobGVhcm5pbmcgb25seSkwggEiMA0GCSqGSIb3"
        + "DQEBAQUAA4IBDwAwggEKAoIBAQDLi3UPEwAbx+w/NJUKCmZXrz7FZTOrSQheWvTTy/TJsDOyYJceYTY7lRaEaACQpmCx7K1HUlFs"
        + "6GBiMwwJJYZUxXIslgTWw4zsf9foQgJc2OfrqUMJO0ap6i8+SXvpsCWPkGfTsRd2JA0CaPByNsxfGP/KH7kpvSxU2pV3mDe1poyr"
        + "2NAD+eZ4conSozkXTAd9PJ2gZs2XBONWjM0ZQ9EsEKYxW2jSiRUMsPTR1dfmnhIGME1G6zKB/frCR7noRYJwQC1s5yFZhRcbIDLq"
        + "KZSPWCWeHVKMMVtm9NUrDbXNafMFxpG8AKP+fBfmDACaDYlVFxdwALvPji0FT8HzpMA7AgMBAAGjIzAhMA8GA1UdEwEB/wQFMAMB"
        + "Af8wDgYDVR0PAQH/BAQDAgEGMA0GCSqGSIb3DQEBCwUAA4IBAQCb1Xt8/WdTk3ekruZ125NtXu1Uwge1ShLaaqyioK5PdPsJhhlG"
        + "GVXSddoWnbVcet2aIPgCYby4u4ZABKl4OApM2nul2VdEYpLWR4Q30bhTn+IhQlDwlsdyQxshSgqrhNMyFomPq3j4IqF0KA09Hf1f"
        + "WlrQdqI+DYFNYV3LFBjjrC4LUMqgQzd41+m3SvPukya2mTgiN20+QF7hx23Kv2Nzz0Cjb6Q6nkKrwcJ/t1WaZOs7d6W+e57NByye"
        + "bmbGeTJpK6E/Biws1AlhNihyQ373AfUMw54IVZG3joEZIqs7mnnWwnC9aYA5mAL2EtHoj2uLVoNLY66LD3Id351bPfiG", JAVA_CERT = "MIIDKjCCAhKgAwIBAgIIBupjsqDDIJEwDQYJKoZIhvcNAQELBQAwRTELMAkGA1UEBhMCS1IxDzANBgNVBAoMBlRlc3RDQTElMCMG"
        + "A1UEAwwcVGVzdCBSb290IENBIChsZWFybmluZyBvbmx5KTAeFw0yNjExMjAwNTA1NDlaFw0yNzExMjAwNTA1NDlaMFExCzAJBgNV"
        + "BAYTAktSMQ8wDQYDVQQKDAZUZXN0Q0ExETAPBgNVBAsMCHBlcnNvbmFsMR4wHAYDVQQDDBXtmY3quLjrj5koKTY3OTk2MDk5Mjkw"
        + "ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDLnQEGK2/MyWeG4OXe2u8y4Sola4h1HJLhYu7jlEx80uEZuE37+MQnWN8e"
        + "f35GPTQg+1qOkb6H49Jkzi/wKfkeLCzFD2wqpAaSCHQ1skcQduqgPeUN4I3VhIyXUXYBjSKfZVkQYWtBzA0YW16QF2MSGTT/3zvm"
        + "oLOvkzT4zFdG9iUWVeLOgqDWJTkAJFL7lcdGbIkP8cDz0NiqEOQIAdMVjKBOdyghC7ZaYyJ/jxG1nh7PMQqUPObj2SmSWASa4JDx"
        + "9OyHnbOLp8xF20zBbDjPXx0+6HlZVDrpdi+g/Hzk4EHTE2DVwHML0H+aTpojq9IV41JLz+dLxW0NKKxFbLMpAgMBAAGjEjAQMA4G"
        + "A1UdDwEB/wQEAwIGwDANBgkqhkiG9w0BAQsFAAOCAQEALVo8MCXv8fa7fmLBBpi225w1zdm4dUNsUzpjOXyxu0peVhIwaK1rn1MJ"
        + "BvWiL9Sh6ZYruIsrSb5CzoOrJnJmQiGyciogSZvxw4TnT55rMO0P76YWtpJ718fSo85Tai8YEGZA2TNOaAmDkeFl8NeEDe7OV6G9"
        + "6q6W2cDFGSnfqvniW4BerWYTmhyamGZ8g6OMOkZ/cvEo97CHTl2mgmbv+jUWiI9Uw9Ye8KKxTGcdVd2CjUYJGL42tpcp1jdYTE1M"
        + "y1cz4dLEQnky/InD37oemVcNHtPBq4RfyaMs2xt8XVcKsOiIfeaPNKjFOnJZi6qdKJDb9SJfuPIWbFhH6DeATQ==", JAVA_KEY = "MIIE8DAaBggqgxqMmkQBDzAOBAgCVwRZm2VKKAICCAAEggTQcAwNPA3W+pemoyNx4OG4rUcWqFpfAyOZUo524wWYn1tF0mvAqe/b"
        + "DPvBqFepFv2YCcrJCozANdhtswWGu8xjlYo/nDkYRncJhY72OwR3Z10g+d49ZFz2cEXwjmikYB2SoJ338njSQ9f8WIJOXFE7vc6X"
        + "Gy6i4Q04TfmOWa/fyjqTe5UQXfDvLh+effD3lTBNjJrqnT8zHVNBhoiR/URJnu3oX6kDC5FOqsnsVKXdEQpyhQ3Ja6XWwOgMHP5W"
        + "LGXZm9Y5HQy+JsiETS/avRad7uIJ9pon/9KAeLBbLLEWovYkDO2g958hN1XXGyvV3hvos2oYLEN5OhKos7bFK7V4Slafyv9KtZxO"
        + "5VJjcoDHG7xZmoMvVNqlRJhizySfsAzESvKgXMe1g+l+EtDOy5OVMrvVKohXofxTLQftTuYTGS3Q95lN+TGQlEqZTCa5C0jvrNMP"
        + "jJhfrwQh8J4vITL6iknhEOIPwCbsHvmZbvkgyLfiR3pG0D5akEn7LFbQzXbtzzUSsvWM/upfl02McX9BORGe1y+eCS4CGrHye506"
        + "IJy6ptpF8aNXt/vN0P/gVVdyS6KB63/6G/zClzqe7N1CH6iqr/xv+MspgFYIlmt3dcCkSaTvKEEiNDgrPLCoW0VYPKPHDOfuRBbm"
        + "QBPZ/RKT6w3wl9u7Mkup1BSZFUVh+bA/LPPTWVdsPcAO39z1ZswtLF5h8rq9rKOrv77iMosjCmAUwGLImfk9jgCtopnBJh4X4evb"
        + "K0K+Md5LGXVT2yP4fFJ/MUHsUNUb2c/CwXUUBFxNeSd4Gg5MnbG+bC4UFV9E8zLQzE3n635HdKHTc+viuDxPHo17M2aZpz4J5aGT"
        + "FzRXltN2N1xIJO083pN0CI72PyNs8BDPvvyS1J7OeW9Q6grIcWvS53IVqmg5/0lYLG00LFwTualbk1/pBlh44rtUWGvdrB2DUsoR"
        + "mvNMv9ik5/aaE0j3EvWBJdYlzRtzoZeNpaA+lj98M+A5VOR2KQvTfm9oBxeeno9ykHsLA5XNZ3ncytkQIzkEwd8VwEOKqdMDIgbN"
        + "opv3X62J0vGtyVkp8MRRWiZFPK6P0mX4ccOxIndUxfbfaQULWsea/sGCoCbiXDcICjkfWtmnq2Gnoh6TqaxFEq5iCRNGSUv6YsBB"
        + "jsDIH27uC+IRq9cEeo91bDzqkMgOTqV6xR45HCsDCPDm2DxB0KrQS/AlFi0Y5gA9gnxWWJHKRRWZ6agREmh2tQIj0HjjhxB+HCvL"
        + "pF2I57RwXwC9BvYCDZ5hJss/x9bKBUkcjpEeZtDX5XAqFDKlPUwDfDIT3w9YSQaM30kmVkzWzeWOsQHUjbh/be0uWoEPqQVnJMdh"
        + "+XwcWvI0a0V3xwSqVfIAisuw1g/vK0xl+1dV9tn5pIs6+UKdP89LmtXt+jMK5+I3jlN79pv9l4VD/2myORhaWhdq2V/g/bf5phEY"
        + "wmPbI3OMj9O+4ZXiFsRkTIcGLKeFIyQzgftgtpD53kstAuKFbVYzmvyBT6JsccUy7PDtqhkufW/oL4pXKAZU+fbem0qghUZLSBvQ"
        + "OjYSiUmv8OC9unLBebRIBPbaB+bxTgjv3hLHdAPGCP6/xHtkOiwrzir9cJEYoxSwNRRVYHCneGAjVbqst2krzhWwG7o=", JAVA_SIG = "iUaQvmo50KbPyFQAAvRbic7aydp2uJ8xV0qQk0I2a4y309S/rTIqeyNtEgHyz516RAlCi9TrvoqG1vaIMuNSo/so1ZerdpzV8+ZJ"
        + "CTkRxJFHx/N1CxH/8W7vrGwa+XejWDOrkrySQRz2hF5AfSZyaItORRknTNl5XZOpgCe8KKcQCuGefRkKs4hdLtHaETUs7XmrYmaH"
        + "ed9b+npvfVB9PkaxRpgNmSKM9/z9tZjdxtmoW4L9lbDeKZJfONoDD3dx0dxCn/L/fWF/Ofc+j6Mf2p0Yvl+PlKaL1mRgyvQQw2JF"
        + "/Zi7eoHvxHOW4gNEzrEqhiE4pps34sL/tduSuphhEQ==";

    public static void main(String[] args) throws Exception {
        Base64.Decoder b64 = Base64.getDecoder();
        Base64.Encoder enc = Base64.getEncoder();
        if (args.length > 0) {
            switch (args[0]) {
                case "issue" -> { // issue <name> <password> <dir>
                    CertSet s = issueSet(args[1], args[2]);
                    Path dir = Files.createDirectories(Path.of(args[3]));
                    Files.write(dir.resolve("caCert.der"), s.caCert());
                    Files.write(dir.resolve("signCert.der"), s.signCert());
                    Files.write(dir.resolve("signPri.key"), s.signPri());
                    System.out.println("Wrote caCert.der, signCert.der, signPri.key to " + dir);
                }
                case "open" -> { // open <dir> <password>
                    Opened o = open(read(args[1]), args[2]);
                    System.out.println("Subject : " + o.cert().getSubjectX500Principal());
                    System.out.println("Issuer  : " + o.cert().getIssuerX500Principal());
                    System.out.println("Valid   : " + o.cert().getNotBefore() + " -> " + o.cert().getNotAfter());
                    System.out.println("Key matches certificate: " + o.keyMatches() + ", signed by CA: " + o.signedByCA());
                }
                case "sign" -> // sign <dir> <password> <message>
                    System.out.println(enc.encodeToString(sign(open(read(args[1]), args[2]).key(), args[3].getBytes(StandardCharsets.UTF_8))));
                case "verify" -> // verify <dir> <message> <signatureBase64>
                    System.out.println(verify(cert(Files.readAllBytes(Path.of(args[1], "signCert.der"))),
                            args[2].getBytes(StandardCharsets.UTF_8), b64.decode(args[3])) ? "VALID" : "INVALID");
                case "fixture" -> { // prints a new Java-made set for the JAVA_* constants
                    CertSet s = issueSet("홍길동", FIXTURE_PW);
                    System.out.println(enc.encodeToString(s.caCert()) + "\n" + enc.encodeToString(s.signCert()) + "\n" + enc.encodeToString(s.signPri())
                            + "\n" + enc.encodeToString(sign(unlockKey(s.signPri(), FIXTURE_PW), FIXTURE_MSG.getBytes(StandardCharsets.UTF_8))));
                }
                default -> System.out.println("Usage: java Gongdong.java [issue <name> <password> <dir> | open <dir> <password> | sign <dir> <password> <msg> | verify <dir> <msg> <sig>]");
            }
            return;
        }

        check(HEX.formatHex(Seed.ecb(HEX.parseHex("4706480851e61be85d74bfb3fd956185"), HEX.parseHex("83a2f8a288641fb9a4e9a5cc2f131c7d")))
                .equals("ee54d13ebcae706d226bc3142cd40d4a"), "SEED known answer (RFC 4269 B.3)");

        byte[] msg = FIXTURE_MSG.getBytes(StandardCharsets.UTF_8);
        for (String[] f : new String[][]{{"the page", PAGE_CA, PAGE_CERT, PAGE_KEY, PAGE_SIG}, {"Java", JAVA_CA, JAVA_CERT, JAVA_KEY, JAVA_SIG}}) {
            CertSet s = new CertSet(b64.decode(f[1]), b64.decode(f[2]), b64.decode(f[3]));
            Opened o = open(s, FIXTURE_PW);
            check(o.keyMatches() && o.signedByCA(), "set made by " + f[0] + " opens: key matches certificate, signed by CA");
            check(verify(o.cert(), msg, b64.decode(f[4])), "signature made by " + f[0] + " verifies");
        }

        CertSet s = issueSet("홍길동", "my password 1!");
        Opened o = open(s, "my password 1!");
        check(o.keyMatches() && o.signedByCA(), "issue a new set -> opens, key matches, signed by CA");
        o.cert().checkValidity();
        check(o.cert().getSubjectX500Principal().getName().startsWith("CN=홍길동()"), "subject: " + o.cert().getSubjectX500Principal());
        byte[] sig = sign(o.key(), msg);
        check(verify(o.cert(), msg, sig), "sign with the private key, verify with the certificate");
        check(!verify(o.cert(), "I agree to the contract!".getBytes(StandardCharsets.UTF_8), sig), "changed message is rejected");

        try {
            open(s, "my password 2!");
            check(false, "wrong password is rejected");
        } catch (GeneralSecurityException e) {
            check(true, "wrong password is rejected (" + e.getMessage() + ")");
        }

        byte[] forged = s.signCert().clone();
        byte[] name = "personal".getBytes(StandardCharsets.UTF_8);
        int at = indexOf(forged, name);
        forged[at] = 'P'; // change the subject, keep everything else
        check(!open(new CertSet(s.caCert(), forged, s.signPri()), "my password 1!").signedByCA(), "certificate with a changed name is rejected by the CA check");

        CertSet other = issueSet("홍길동", "my password 1!");
        check(!open(new CertSet(other.caCert(), s.signCert(), s.signPri()), "my password 1!").signedByCA(), "certificate from a different CA is rejected");
        check(!open(new CertSet(s.caCert(), s.signCert(), other.signPri()), "my password 1!").keyMatches(), "someone else's private key does not match the certificate");

        System.out.println("All checks passed.");
    }

    static CertSet read(String dir) throws Exception {
        Path d = Path.of(dir);
        return new CertSet(Files.readAllBytes(d.resolve("caCert.der")), Files.readAllBytes(d.resolve("signCert.der")), Files.readAllBytes(d.resolve("signPri.key")));
    }

    static int indexOf(byte[] a, byte[] b) {
        for (int i = 0; i <= a.length - b.length; i++) if (Arrays.equals(a, i, i + b.length, b, 0, b.length)) return i;
        throw new IllegalStateException("not found");
    }

    static byte[] BigIntBytes(int v) { return java.math.BigInteger.valueOf(v).toByteArray(); }

    private static void check(boolean ok, String name) {
        if (!ok) throw new AssertionError("FAILED: " + name);
        System.out.println("  ok  " + name);
    }

    // ---------- DER: the binary encoding of certificates and keys (tag, length, body) ----------
    static final class Der {
        static final byte[] NULL = {5, 0}, TRUE = {1, 1, (byte) 0xff};
        record El(int tag, byte[] raw, byte[] body, List<El> kids) {}

        static byte[] tlv(int tag, byte[]... parts) {
            ByteArrayOutputStream body = new ByteArrayOutputStream();
            for (byte[] p : parts) body.writeBytes(p);
            int n = body.size();
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            out.write(tag);
            if (n < 128) out.write(n);
            else if (n < 256) { out.write(0x81); out.write(n); }
            else if (n < 65536) { out.write(0x82); out.write(n >> 8); out.write(n); }
            else { out.write(0x83); out.write(n >> 16); out.write(n >> 8); out.write(n); }
            out.writeBytes(body.toByteArray());
            return out.toByteArray();
        }
        static byte[] seq(byte[]... items) { return tlv(0x30, items); }
        static byte[] octet(byte[] b) { return tlv(0x04, b); }
        static byte[] bits(byte[] b, int unused) { return tlv(0x03, new byte[]{(byte) unused}, b); }
        static byte[] integer(byte[] unsigned) { return tlv(0x02, new java.math.BigInteger(1, unsigned).toByteArray()); }
        static byte[] time(ZonedDateTime t) { return tlv(0x17, t.format(DateTimeFormatter.ofPattern("yyMMddHHmmss'Z'")).getBytes(StandardCharsets.US_ASCII)); }
        static byte[] oid(String s) {
            String[] p = s.split("\\.");
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            out.write(40 * Integer.parseInt(p[0]) + Integer.parseInt(p[1]));
            for (int i = 2; i < p.length; i++) {
                long v = Long.parseLong(p[i]);
                byte[] t = new byte[10];
                int k = t.length;
                t[--k] = (byte) (v & 127);
                while ((v >>= 7) > 0) t[--k] = (byte) (128 | v & 127);
                out.write(t, k, t.length - k);
            }
            return tlv(0x06, out.toByteArray());
        }
        /** Name in DER order (c first): SEQUENCE of SET of SEQUENCE { type, value }. */
        static byte[] name(String[][] parts) {
            List<byte[]> rdns = new ArrayList<>();
            for (String[] p : parts) {
                String oid = switch (p[0]) { case "cn" -> "2.5.4.3"; case "ou" -> "2.5.4.11"; case "o" -> "2.5.4.10"; default -> "2.5.4.6"; };
                byte[] v = p[1].getBytes(StandardCharsets.UTF_8);
                rdns.add(tlv(0x31, seq(oid(oid), tlv(p[0].equals("c") ? 0x13 : 0x0c, v)))); // country: PrintableString, rest: UTF8String
            }
            return seq(rdns.toArray(byte[][]::new));
        }

        static El parse(byte[] b, int at) {
            int tag = b[at] & 0xff, n = b[at + 1] & 0xff, o = at + 2;
            if (n >= 128) {
                int k = n & 127;
                if (k < 1 || k > 3) throw new IllegalArgumentException("bad DER");
                n = 0;
                for (int i = 0; i < k; i++) n = n * 256 + (b[o++] & 0xff);
            }
            if (o + n > b.length) throw new IllegalArgumentException("bad DER");
            byte[] body = Arrays.copyOfRange(b, o, o + n);
            List<El> kids = new ArrayList<>();
            if ((tag & 0x20) != 0) for (int p = 0; p < n; ) { El k = parse(body, p); kids.add(k); p += k.raw.length; }
            return new El(tag, Arrays.copyOfRange(b, at, o + n), body, kids);
        }
        static String oidOf(El e) {
            byte[] b = e.body;
            StringBuilder s = new StringBuilder((b[0] & 0xff) / 40 + "." + (b[0] & 0xff) % 40);
            long v = 0;
            for (int i = 1; i < b.length; i++) {
                v = v * 128 + (b[i] & 127);
                if ((b[i] & 0x80) == 0) { s.append('.').append(v); v = 0; }
            }
            return s.toString();
        }
    }

    // ---------- SEED block cipher (RFC 4269), same as seed/Seed.java ----------
    static final class Seed {
        private static final byte[] S1 = HEX.parseHex(
            "a985d6d3541dac255d43181e51fcca632844209de0e2c817a58f037bbb13d2ee708c3fa832ddf674ec950b575c5bbd01"
          + "241c739810ccf2d92ce772839bd186c96050a3eb0db69e4fb75ac678a612afd561c3b441527d8d081f9900190453f7e1"
          + "fd762f27b08b0eaba26e934d697c090abfeff3c58714fe64de2e4b1a06216b6602f5928a0cb37ed07a4796e52680addf"
          + "a13037ae36152238f4a7454c81e9849735cbce3c7111c78975fbdaf8945982c4ff493967c0cfd7b80f8e4223916cdba4"
          + "34f148c26f3d2d40be3ebcc1aaba4e553bdc687f9cd84a5677a0ed46b52b65fae3b9b19f5ef9e6b231ea6d5fe4f0cd88"
          + "163a58d462290733e81b0579906a2a9a");
        private static final byte[] S2 = HEX.parseHex(
            "38e82da6cfdeb3b8af6055c7446f6b5bc36233b529a0e2a7d39111061cbc364bef886ca817c416f4c245e1d63f3d8e98"
          + "284ef63ea5f90ddfd82b667a272ff17242d441c07367ac8bf7ad801fca2caa34d20beee95d9418f857ae08c513cd86b9"
          + "ff7dc131f58a6ab1d120d7022204687107db9d9961bee659dd5190dc9aa3abd0810f471ae3ec8dbf967b5ca2a163234d"
          + "c89e9c3a0c2eba6e9f5af292f34978cc15fb70757f351003646dc674d5b4ea097619fe4012e0bd05fa01f02a5ea95643"
          + "8514899bb0e5487997fc1e82218c1b5f7754b21d254f0046ed5852eb7edac9fd3095653cb6e4bb7c0e5039263284699"
          + "337e724a4cb530a87d94c838fce3b4ab7");
        private static final int[] M = {0xfc, 0xf3, 0xcf, 0x3f};
        private static final int[][] SS = new int[4][256];
        static {
            for (int b = 0; b < 4; b++)
                for (int x = 0; x < 256; x++) {
                    int v = ((b % 2 == 0) ? S1 : S2)[x] & 0xff;
                    SS[b][x] = (v & M[(b + 3) % 4]) << 24 | (v & M[(b + 2) % 4]) << 16 | (v & M[(b + 1) % 4]) << 8 | (v & M[b]);
                }
        }
        private static int g(int x) { return SS[0][x & 0xff] ^ SS[1][x >>> 8 & 0xff] ^ SS[2][x >>> 16 & 0xff] ^ SS[3][x >>> 24]; }

        private static int[] roundKeys(byte[] key) {
            ByteBuffer kb = ByteBuffer.wrap(key);
            int k0 = kb.getInt(), k1 = kb.getInt(), k2 = kb.getInt(), k3 = kb.getInt();
            int[] out = new int[32];
            for (int i = 0; i < 16; i++) {
                int kc = Integer.rotateLeft(0x9e3779b9, i);
                out[2 * i] = g(k0 + k2 - kc);
                out[2 * i + 1] = g(k1 - k3 + kc);
                if (i % 2 == 0) { int t = k0; k0 = k0 >>> 8 | k1 << 24; k1 = k1 >>> 8 | t << 24; }
                else            { int t = k2; k2 = k2 << 8 | k3 >>> 24; k3 = k3 << 8 | t >>> 24; }
            }
            return out;
        }
        private static byte[] block(int[] k, boolean encrypt, byte[] in) {
            ByteBuffer b = ByteBuffer.wrap(in);
            int l0 = b.getInt(), l1 = b.getInt(), r0 = b.getInt(), r1 = b.getInt();
            for (int i = 0; i < 16; i++) {
                int j = 2 * (encrypt ? i : 15 - i);
                int c = r0 ^ k[j], d = r1 ^ k[j + 1];
                d = g(c ^ d); c = g(c + d); d = g(d + c); c += d;
                int t0 = r0, t1 = r1;
                r0 = l0 ^ c; r1 = l1 ^ d; l0 = t0; l1 = t1;
            }
            return ByteBuffer.allocate(16).putInt(r0).putInt(r1).putInt(l0).putInt(l1).array();
        }
        static byte[] ecb(byte[] key, byte[] block) { return block(roundKeys(key), true, block); }
        static byte[] cbc(boolean encrypt, byte[] key, byte[] iv, byte[] data) {
            int[] k = roundKeys(key);
            byte[] out = new byte[data.length], prev = iv.clone();
            for (int o = 0; o < data.length; o += 16) {
                byte[] in = Arrays.copyOfRange(data, o, o + 16);
                if (encrypt) {
                    for (int i = 0; i < 16; i++) in[i] ^= prev[i];
                    prev = block(k, true, in);
                    System.arraycopy(prev, 0, out, o, 16);
                } else {
                    byte[] p = block(k, false, in);
                    for (int i = 0; i < 16; i++) p[i] ^= prev[i];
                    prev = in;
                    System.arraycopy(p, 0, out, o, 16);
                }
            }
            return out;
        }
    }
}
