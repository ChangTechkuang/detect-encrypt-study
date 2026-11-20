import org.mindrot.jbcrypt.BCrypt;

/**
 * bcrypt password hashing demo for learning. Needs lib/jbcrypt-0.4.jar (Java has no built-in bcrypt).
 *
 * Run:  java -cp lib/jbcrypt-0.4.jar Bcrypt.java            (self-checks)
 *       java -cp lib/jbcrypt-0.4.jar Bcrypt.java "password" (hash it)
 *
 * Unlike MD5/SHA-256, bcrypt is made for passwords:
 *  - random salt: same password -> different hash each time (salt is stored inside the hash)
 *  - cost factor: 2^cost rounds, deliberately slow to make brute force expensive
 *  - verify with checkpw(), which re-hashes using the salt read from the stored hash
 * Hash format: $2a$<cost>$<22-char salt><31-char hash> = 60 chars
 * Note: bcrypt only uses the first 72 bytes of the password.
 *
 * HASHING, not encryption: no way back. The server stores only the hash; at login it hashes the typed
 * password again and compares. Nobody can read the passwords out of a stolen database, only guess.
 *
 * Why not just SHA-256(password)? Two problems bcrypt fixes:
 *   Too fast   a GPU tries billions of SHA-256 guesses per second. bcrypt with cost 10 does 2^10 = 1024
 *              rounds of expensive key setup per guess, about 0.1 s: millions of times slower to attack.
 *              Raise the cost by 1 when computers get faster: each +1 doubles the work.
 *   No salt    equal passwords give equal hashes, and precomputed tables ("rainbow tables") work.
 *              bcrypt adds a random 16-byte salt to each password, so every user must be attacked alone.
 *
 * How it works (Provos & Mazieres 1999, built on the Blowfish cipher):
 *   EksBlowfishSetup  ("expensive key schedule")
 *     1. start Blowfish's tables (S-boxes and subkeys, about 4 KB) from fixed constants (digits of pi)
 *     2. mix in salt and password
 *     3. repeat 2^cost times: mix in the password, then the salt   <- this loop is the slow part
 *   Encrypt the text "OrpheanBeholderScryDoubt" 64 times with those tables
 *   Output  $2a$ + cost + salt + the result (23 bytes), in bcrypt's own Base64 = 60 chars
 * The 4 KB tables also make it costly on GPUs, which have little fast memory per core.
 *
 * Newer choice: Argon2id (Password Hashing Competition winner, 2015) also lets you set the memory used.
 * bcrypt is still fine and very widely used.
 */
public class Bcrypt {
    public static final int COST = 10;

    /** gensalt makes a new random 16-byte salt; it ends up inside the returned 60-char string. */
    public static String hash(String password) {
        return BCrypt.hashpw(password, BCrypt.gensalt(COST));
    }

    /**
     * Reads cost and salt from storedHash, hashes the typed password with them, compares the results.
     * That is why the salt does not need to be stored separately.
     */
    public static boolean verify(String password, String storedHash) {
        try {
            return BCrypt.checkpw(password, storedHash);
        } catch (IllegalArgumentException e) { // malformed stored hash
            return false;
        }
    }

    public static void main(String[] args) {
        if (args.length > 0) {
            System.out.println("Input : " + args[0]);
            System.out.println("bcrypt: " + hash(args[0]));
            return;
        }

        // Standard test vectors (OpenBSD bcrypt / jBCrypt test suite): password, salt, expected hash
        String[][] vectors = {
            {"", "$2a$06$DCq7YPn5Rq63x1Lad4cll.", "$2a$06$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s."},
            {"a", "$2a$06$m0CrhHm10qJ3lXRY.5zDGO", "$2a$06$m0CrhHm10qJ3lXRY.5zDGO3rS2KdeeWLuGmsfGlMfOxih58VYVfxe"},
            {"abc", "$2a$06$If6bvum7DFjUnE9p2uDeDu", "$2a$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i"},
            {"abcdefghijklmnopqrstuvwxyz", "$2a$06$.rCVZVOThsIa97pEDOxvGu",
                "$2a$06$.rCVZVOThsIa97pEDOxvGuRRgzG64bvtJ0938xuqzv18d3ZpQhstC"},
            {"~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$2a$06$fPIsBO8qRqkjj273rfaOI.",
                "$2a$06$fPIsBO8qRqkjj273rfaOI.HtSV9jLDpTbZn782DC6/t7qT67P6FfO"},
        };
        for (String[] v : vectors) {
            check(BCrypt.hashpw(v[0], v[1]).equals(v[2]), "hash(\"" + v[0] + "\") with fixed salt = " + v[2]);
            check(verify(v[0], v[2]), "verify \"" + v[0] + "\"");
            check(!verify(v[0] + "x", v[2]), "reject altered \"" + v[0] + "\"");
        }

        String h1 = hash("hunter2"), h2 = hash("hunter2");
        check(!h1.equals(h2), "same password twice -> different hash (random salt)");
        check(verify("hunter2", h1) && verify("hunter2", h2), "both hashes still verify");
        check(h1.length() == 60 && h1.startsWith("$2a$10$"), "format $2a$10$..., 60 chars");
        check(!verify("hunter2", "not-a-hash"), "malformed stored hash -> false, no crash");
        System.out.println("All checks passed.");
        System.out.println("Sample: " + h1);
    }

    private static void check(boolean ok, String name) {
        if (!ok) throw new AssertionError("FAILED: " + name);
        System.out.println("  ok  " + name);
    }
}
