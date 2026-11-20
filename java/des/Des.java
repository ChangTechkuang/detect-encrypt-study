import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * DES (Data Encryption Standard) demo for learning. FIPS 46-3, withdrawn in 2005.
 * BROKEN: the 56-bit key can be brute-forced in hours. Use AES-256-GCM for anything real.
 *
 * Key: 8 bytes (64 bits, of which 8 are parity bits, so 56 effective). Block: 8 bytes.
 * Mode here: CBC + PKCS#5 padding with a random 8-byte IV.
 * There is no authentication tag: changed data can decrypt to garbage without any error.
 *
 * Output format (same as the Implement page (src/lib/impl)): Base64( IV[8 bytes] + ciphertext )
 *
 * Why SYMMETRIC? ONE secret key both encrypts and decrypts, so both sides must already share it
 * (compare RSA: two different keys, one of them public).
 *
 * How the DES block cipher works (FIPS 46-3; Java's Cipher does this inside):
 *   Initial permutation  shuffle the 64 bits of the block
 *   16 Feistel rounds    split into left L and right R (32 bits each). Each round:
 *                          L, R  ->  R, L XOR F(R, round key)
 *   F function           expand R from 32 to 48 bits -> XOR the 48-bit round key
 *                        -> 8 S-boxes (6 bits in, 4 bits out: the non-linear step) -> permute the 32 bits
 *   Final permutation    undo the initial shuffle
 *   Key schedule         the 56 real key bits -> 16 round keys of 48 bits (rotate and pick bits)
 *   Decrypting runs the SAME 16 rounds with the round keys in reverse order: XOR undoes itself, so F
 *   never has to be reversed. That is the trick of a Feistel network (SEED uses it too).
 *
 * Why it is broken: the algorithm still has no practical shortcut, but 2^56 keys is too few. A machine
 * tried them all in 56 hours in 1998. 3DES (tripledes/) runs DES three times to make the key longer;
 * AES (aes/) replaced both.
 */
public class Des {
    private static final int BLOCK = 8;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final HexFormat HEX = HexFormat.of();

    public static byte[] generateKey() {
        byte[] key = new byte[BLOCK];
        RANDOM.nextBytes(key);
        return key;
    }

    /**
     * SYMMETRIC encrypt with the secret key. CBC: c[i] = DES(p[i] XOR c[i-1]), c[-1] = a random IV,
     * so equal 8-byte blocks of text do not give equal output. The IV is sent in front, it is not secret.
     */
    public static String encrypt(String plaintext, byte[] key) throws GeneralSecurityException {
        byte[] iv = new byte[BLOCK];
        RANDOM.nextBytes(iv);
        byte[] ct = des("DES/CBC/PKCS5Padding", Cipher.ENCRYPT_MODE, key, iv, plaintext.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(ByteBuffer.allocate(iv.length + ct.length).put(iv).put(ct).array());
    }

    /**
     * SYMMETRIC decrypt with the SAME secret key. CBC: p[i] = DES^-1(c[i]) XOR c[i-1].
     * Throws BadPaddingException if the padding is invalid (usually: wrong key or changed last block).
     */
    public static String decrypt(String encrypted, byte[] key) throws GeneralSecurityException {
        byte[] all = Base64.getDecoder().decode(encrypted.trim());
        if (all.length < 2 * BLOCK || all.length % BLOCK != 0) throw new IllegalArgumentException("Bad length");
        byte[] pt = des("DES/CBC/PKCS5Padding", Cipher.DECRYPT_MODE, key,
                Arrays.copyOf(all, BLOCK), Arrays.copyOfRange(all, BLOCK, all.length));
        return new String(pt, StandardCharsets.UTF_8);
    }

    private static byte[] des(String transform, int mode, byte[] key, byte[] iv, byte[] data) throws GeneralSecurityException {
        // 8 bytes = 64 bits, but the lowest bit of each byte is parity and is ignored: 56 real key bits
        if (key.length != BLOCK) throw new IllegalArgumentException("DES needs an 8-byte key (16 hex chars)");
        Cipher c = Cipher.getInstance(transform);
        if (iv == null) c.init(mode, new SecretKeySpec(key, "DES"));
        else c.init(mode, new SecretKeySpec(key, "DES"), new IvParameterSpec(iv));
        return c.doFinal(data);
    }

    public static void main(String[] args) throws Exception {
        // java Des.java encrypt <keyHex> "text"   |   java Des.java decrypt <keyHex> <base64>
        if (args.length == 3) {
            byte[] key = HEX.parseHex(args[1]);
            System.out.println(args[0].equals("decrypt") ? decrypt(args[2], key) : encrypt(args[2], key));
            return;
        }

        // Classic single-block DES test vectors (raw block cipher, ECB, no padding): key, plaintext, ciphertext
        String[][] vectors = {
            {"133457799bbcdff1", "0123456789abcdef", "85e813540f0ab405"}, // textbook worked example
            {"0123456789abcdef", "4e6f772069732074", "3fa40e8a984d4815"}, // "Now is t", FIPS 81 example
            {"0000000000000000", "0000000000000000", "8ca64de9c1b123a7"},
            {"ffffffffffffffff", "ffffffffffffffff", "7359b2163e4edc58"},
        };
        for (String[] v : vectors) {
            byte[] key = HEX.parseHex(v[0]);
            check(HEX.formatHex(des("DES/ECB/NoPadding", Cipher.ENCRYPT_MODE, key, null, HEX.parseHex(v[1]))).equals(v[2]),
                    "DES(key " + v[0] + ", " + v[1] + ") = " + v[2]);
            check(HEX.formatHex(des("DES/ECB/NoPadding", Cipher.DECRYPT_MODE, key, null, HEX.parseHex(v[2]))).equals(v[1]),
                    "decrypt back to " + v[1]);
        }

        byte[] key = generateKey();
        String text = "Hello, DES! café ✓";
        String enc = encrypt(text, key);
        check(decrypt(enc, key).equals(text), "round trip (UTF-8)");
        check(!encrypt(text, key).equals(enc), "same text twice -> different output (random IV)");

        // No integrity: flipping a bit in the IV silently changes the first block of plaintext
        byte[] tampered = Base64.getDecoder().decode(enc);
        tampered[0] ^= 1;
        String changed = decrypt(Base64.getEncoder().encodeToString(tampered), key);
        check(!changed.equals(text), "changed data is NOT detected, decrypts to: " + changed.replaceAll("\\p{Cntrl}", "?"));

        // Wrong key: usually a padding error, but about 1 in 256 times it "succeeds" with garbage
        try {
            String wrong = decrypt(enc, generateKey());
            check(!wrong.equals(text), "wrong key -> garbage (padding happened to look valid)");
        } catch (BadPaddingException e) {
            check(true, "wrong key -> padding error");
        }

        System.out.println("All checks passed.");
        System.out.println("Sample key : " + HEX.formatHex(key));
        System.out.println("Encrypted  : " + enc);
    }

    private static void check(boolean ok, String name) {
        if (!ok) throw new AssertionError("FAILED: " + name);
        System.out.println("  ok  " + name);
    }
}
