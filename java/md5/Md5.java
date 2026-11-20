import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * MD5 hashing demo for learning.
 * Note: MD5 is broken for security (collisions, fast brute force).
 * Use it for checksums/fingerprints only; for passwords use bcrypt/Argon2/PBKDF2.
 *
 * HASHING, not encryption: there is NO key and NO way back. Any length of input -> always 16 bytes.
 * Encryption (AES, RSA) can be undone with a key; a hash can only be recomputed and compared.
 * Same input -> always the same hash; change one bit -> about half the output bits change.
 *
 * How it works (RFC 1321; MessageDigest does this inside):
 *   Padding   append bit 1, then zeros, then the message length (64 bits), so the total is a multiple
 *             of 64 bytes. (The length makes "abc" and "abc\0" pad differently.)
 *   State     four 32-bit words A, B, C, D, starting from fixed constants
 *   Blocks    for each 64-byte block: 64 steps in 4 rounds of 16. Each step mixes one 32-bit word
 *             of the block into the state with a bit function (F, G, H or I), an addition of a
 *             sine-based constant, and a rotation. Then the result is ADDED to the old state.
 *   Output    A|B|C|D after the last block = 128 bits = 32 hex chars
 *   This "chain the state through the blocks" design is called Merkle-Damgard (SHA-256 uses it too).
 *
 * Why it is broken: in 2004 Wang et al. found how to make two different inputs with the same MD5
 * (a "collision") in seconds; in 2008 that gave a fake CA certificate. Finding an input for a GIVEN hash
 * is still hard, but collisions alone are enough to forge signatures. Use SHA-256 instead.
 */
public class Md5 {

    /** Hash text -> 32 hex chars (128 bits). */
    public static String hash(String input) {
        try {
            byte[] digest = MessageDigest.getInstance("MD5")
                    .digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("MD5 is required on every JVM", e);
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
            System.out.println("Input : " + args[0]);
            System.out.println("MD5   : " + hash(args[0]));
            return;
        }

        // Official test suite from RFC 1321 (the MD5 standard), appendix A.5
        String[][] rfc1321 = {
            {"", "d41d8cd98f00b204e9800998ecf8427e"},
            {"a", "0cc175b9c0f1b6a831c399e269772661"},
            {"abc", "900150983cd24fb0d6963f7d28e17f72"},
            {"message digest", "f96b697d7cb7938d525a2f31aaf161d0"},
            {"abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b"},
            {"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "d174ab98d277d9f5a5611c2c9f419d9f"},
            {"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "57edf4a22be3c955ac49da2e2107b67a"},
        };
        for (String[] v : rfc1321) {
            check(hash(v[0]).equals(v[1]), "MD5(\"" + v[0] + "\") = " + v[1]);
            check(verify(v[0], v[1].toUpperCase()), "verify \"" + v[0] + "\"");
            check(!verify(v[0] + "x", v[1]), "reject altered \"" + v[0] + "\"");
        }
        System.out.println("All RFC 1321 checks passed.");
    }

    private static void check(boolean ok, String name) {
        if (!ok) throw new AssertionError("FAILED: " + name);
        System.out.println("  ok  " + name);
    }
}
