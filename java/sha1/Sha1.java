import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * SHA-1 hashing demo for learning.
 * SHA-1 -> 160 bits = 40 hex chars. BROKEN: in 2017 Google/CWI made two different PDFs with the same
 * SHA-1 (SHAttered). Do not use it for signatures, certificates or anything a cheater could target.
 * Use SHA-256 instead; for passwords use bcrypt/Argon2/PBKDF2.
 *
 * HASHING, not encryption: there is NO key and NO way back. Any length of input -> always 20 bytes.
 * Same box as MD5 and SHA-256 (64-byte blocks, marker 0x80, 8-byte length at the end), then:
 *   start       5 numbers H0..H4 (H0..H3 are MD5's start values)
 *   stretch     16 words -> 80 words: w[i] = rotl1(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16])
 *   rounds      80 steps in 4 groups of 20, each group with its own mixing function and constant
 * Java ships SHA-1 because old formats still need it (Git, old certificates, HMAC-SHA1 in TOTP codes).
 */
public class Sha1 {

    /** Hash text -> 40 hex chars (160 bits). */
    public static String hash(String input) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-1")
                    .digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-1 is required on every JVM", e);
        }
    }

    /**
     * Verification = hash the input again and compare with the stored hash (a hash cannot be "decrypted").
     * isEqual takes the same time however many bytes match, so timing does not reveal the hash.
     */
    public static boolean verify(String input, String expectedHash) {
        return MessageDigest.isEqual(
                hash(input).getBytes(StandardCharsets.US_ASCII),
                expectedHash.toLowerCase().getBytes(StandardCharsets.US_ASCII));
    }

    public static void main(String[] args) {
        if (args.length > 0) {
            System.out.println("Input  : " + args[0]);
            System.out.println("SHA-1: " + hash(args[0]));
            return;
        }

        // Official test vectors from NIST (FIPS 180-2 examples)
        String[][] nist = {
            {"", "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
            {"abc", "a9993e364706816aba3e25717850c26c9cd0d89d"},
            {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "84983e441c3bd26ebaae4aa1f95129e5e54670f1"},
            {"a".repeat(1_000_000), "34aa973cd4c4daa4f61eeb2bdbad27316534016f"},
        };
        for (String[] v : nist) {
            String label = v[0].length() > 60 ? "\"a\" x 1,000,000" : "\"" + v[0] + "\"";
            check(hash(v[0]).equals(v[1]), "SHA-1(" + label + ") = " + v[1]);
            check(verify(v[0], v[1].toUpperCase()), "verify " + label);
            check(!verify(v[0] + "x", v[1]), "reject altered " + label);
        }
        System.out.println("All NIST checks passed.");
    }

    private static void check(boolean ok, String name) {
        if (!ok) throw new AssertionError("FAILED: " + name);
        System.out.println("  ok  " + name);
    }
}
