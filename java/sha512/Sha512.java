import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * SHA-512 hashing demo for learning.
 * SHA-512 (SHA-2 family) -> 512 bits = 128 hex chars. Still secure for integrity/fingerprints.
 * For passwords, it is still too fast on its own: use bcrypt/Argon2/PBKDF2.
 *
 * HASHING, not encryption: there is NO key and NO way back. Any length of input -> always 64 bytes.
 * Same design as SHA-256 (see ../sha256/Sha256.java), just bigger:
 *   numbers     64-bit words instead of 32-bit
 *   blocks      128 bytes instead of 64, with a 16-byte length field at the end
 *   rounds      80 instead of 64
 *   start       H0..H7 from the square roots of the first 8 primes, 64 bits each
 *               (their first half is exactly the SHA-256 start value)
 * On 64-bit computers SHA-512 is often faster than SHA-256, because it works on 64-bit numbers.
 */
public class Sha512 {

    /** Hash text -> 128 hex chars (512 bits). */
    public static String hash(String input) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-512")
                    .digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-512 is required on every JVM", e);
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
            System.out.println("SHA-512: " + hash(args[0]));
            return;
        }

        // Official test vectors from NIST (FIPS 180-2 examples)
        String[][] nist = {
            {"", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"},
            {"abc", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"},
            {"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
                "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"},
            {"a".repeat(1_000_000),
                "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"},
        };
        for (String[] v : nist) {
            String label = v[0].length() > 60 ? "\"a\" x 1,000,000" : "\"" + v[0] + "\"";
            check(hash(v[0]).equals(v[1]), "SHA-512(" + label + ") = " + v[1]);
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
