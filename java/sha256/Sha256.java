import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * SHA-256 hashing demo for learning.
 * SHA-256 (SHA-2 family) -> 256 bits = 64 hex chars. Still secure for integrity/fingerprints.
 * For passwords, it is still too fast on its own: use bcrypt/Argon2/PBKDF2.
 *
 * HASHING, not encryption: there is NO key and NO way back. Any length of input -> always 32 bytes.
 * Encryption (AES, RSA) can be undone with a key; a hash can only be recomputed and compared.
 * Same input -> always the same hash; change one bit -> about half the output bits change.
 *
 * How it works (FIPS 180-4; MessageDigest does this inside):
 *   Padding   append bit 1, then zeros, then the message length (64 bits): a multiple of 64 bytes
 *   State     eight 32-bit words H0..H7, starting from the square roots of the first 8 primes
 *   Blocks    for each 64-byte block:
 *               message schedule  expand the 16 words of the block into 64 words (rotations, shifts, XOR)
 *               compression       64 rounds; each mixes one word and one constant (cube roots of the
 *                                 first 64 primes) into the 8 working words with Ch, Maj, Σ0, Σ1
 *               then ADD the result to H0..H7
 *   Output    H0..H7 after the last block = 256 bits = 64 hex chars
 *   Same Merkle-Damgard chaining as MD5, but bigger state, more rounds and stronger mixing.
 *   The constants come from primes ("nothing up my sleeve"), so nobody could have hidden a weakness in them.
 *
 * Security today: no collision has ever been found (it would take about 2^128 tries).
 * Where you meet it: TLS certificates, Bitcoin, Git, and the RSA signatures in this project
 * (rsa/, gongdong/) hash the message with SHA-256 first, then sign the 32-byte hash.
 */
public class Sha256 {

    /** Hash text -> 64 hex chars (256 bits). */
    public static String hash(String input) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is required on every JVM", e);
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
            System.out.println("SHA-256: " + hash(args[0]));
            return;
        }

        // Official test vectors from NIST (FIPS 180-2 examples)
        String[][] nist = {
            {"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
            {"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
            {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"},
            {"a".repeat(1_000_000),
                "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"},
        };
        for (String[] v : nist) {
            String label = v[0].length() > 60 ? "\"a\" x 1,000,000" : "\"" + v[0] + "\"";
            check(hash(v[0]).equals(v[1]), "SHA-256(" + label + ") = " + v[1]);
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
