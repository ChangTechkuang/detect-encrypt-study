import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * ChaCha20-Poly1305 encryption demo for learning (RFC 8439). Java 11+ ships it.
 *
 * SYMMETRIC: one 32-byte secret key encrypts and decrypts.
 * ChaCha20 is a STREAM cipher, not a block cipher:
 *   grid     16 words: "expand 32-byte k" | key (8 words) | block counter | nonce (3 words)
 *   rounds   20 rounds of add, XOR and rotate (columns, then diagonals), then add the start grid back
 *   output   64 bytes of keystream per counter value; ciphertext = text XOR keystream (no padding)
 * Poly1305 adds a 16-byte tag computed from the ciphertext (one-time key = keystream block 0),
 * so a wrong key or changed data is rejected, like AES-GCM.
 * NEVER reuse a nonce with the same key: the keystream would repeat, and XOR of two ciphertexts leaks the texts.
 *
 * Output format = Base64( nonce (12 bytes) + ciphertext + tag (16 bytes) ), same as the website.
 */
public class ChaCha20 {
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final HexFormat HEX = HexFormat.of();

    public static byte[] generateKey() {
        byte[] key = new byte[32];
        RANDOM.nextBytes(key);
        return key;
    }

    static byte[] aead(int mode, byte[] key, byte[] nonce, byte[] aad, byte[] data) throws Exception {
        Cipher c = Cipher.getInstance("ChaCha20-Poly1305");
        c.init(mode, new SecretKeySpec(key, "ChaCha20"), new IvParameterSpec(nonce));
        if (aad.length > 0) c.updateAAD(aad);
        return c.doFinal(data); // encrypt: ciphertext + tag; decrypt: checks the tag first
    }

    /** Plain ChaCha20 (no tag), only for the RFC keystream checks. Encrypt = decrypt. */
    static byte[] raw(byte[] key, byte[] nonce, int counter, byte[] data) throws Exception {
        Cipher c = Cipher.getInstance("ChaCha20");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "ChaCha20"), new ChaCha20ParameterSpec(nonce, counter));
        return c.doFinal(data);
    }

    public static String encrypt(String plaintext, byte[] key) throws Exception {
        byte[] nonce = new byte[12];
        RANDOM.nextBytes(nonce); // fresh every message
        byte[] ct = aead(Cipher.ENCRYPT_MODE, key, nonce, new byte[0], plaintext.getBytes(StandardCharsets.UTF_8));
        byte[] out = Arrays.copyOf(nonce, 12 + ct.length);
        System.arraycopy(ct, 0, out, 12, ct.length);
        return Base64.getEncoder().encodeToString(out);
    }

    /** Throws AEADBadTagException if the key is wrong or the data was changed. */
    public static String decrypt(String encrypted, byte[] key) throws Exception {
        byte[] all = Base64.getDecoder().decode(encrypted.trim());
        if (all.length < 12 + 16) throw new IllegalArgumentException("Too short");
        byte[] pt = aead(Cipher.DECRYPT_MODE, key, Arrays.copyOf(all, 12), new byte[0], Arrays.copyOfRange(all, 12, all.length));
        return new String(pt, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) throws Exception {
        // java ChaCha20.java encrypt <keyHex> "text"   |   java ChaCha20.java decrypt <keyHex> <base64>
        if (args.length == 3) {
            byte[] key = HEX.parseHex(args[1]);
            System.out.println(args[0].equals("decrypt") ? decrypt(args[2], key) : encrypt(args[2], key));
            return;
        }

        byte[] sun = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
                .getBytes(StandardCharsets.US_ASCII);

        // RFC 8439 2.4.2: plain ChaCha20, counter 1
        byte[] k1 = HEX.parseHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        String ct242 = "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d";
        check(HEX.formatHex(raw(k1, HEX.parseHex("000000000000004a00000000"), 1, sun)).equals(ct242), "RFC 8439 2.4.2 ChaCha20 encryption");

        // RFC 8439 A.2 #1: all-zero key and nonce, counter 0
        check(HEX.formatHex(raw(new byte[32], new byte[12], 0, new byte[64])).equals(
                "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586"),
                "RFC 8439 A.2 #1 keystream");

        // RFC 8439 2.8.2: ChaCha20-Poly1305 with additional data
        byte[] k2 = HEX.parseHex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        byte[] n2 = HEX.parseHex("070000004041424344454647"), aad = HEX.parseHex("50515253c0c1c2c3c4c5c6c7");
        byte[] out = aead(Cipher.ENCRYPT_MODE, k2, n2, aad, sun);
        check(HEX.formatHex(Arrays.copyOfRange(out, out.length - 16, out.length)).equals("1ae10b594f09e26a7e902ecbd0600691"), "RFC 8439 2.8.2 tag");
        check(Arrays.equals(aead(Cipher.DECRYPT_MODE, k2, n2, aad, out), sun), "RFC 8439 2.8.2 decrypt back");

        // Same "Hello" example as the website's study page
        byte[] hello = aead(Cipher.ENCRYPT_MODE, k1, HEX.parseHex("000000000000004a00000000"), new byte[0], "Hello".getBytes(StandardCharsets.US_ASCII));
        check(HEX.formatHex(hello).equals("6a2a3d9f2f9f01c7dcde2774c609b9b001dbdc954b"), "\"Hello\" matches the page");

        // Round trip, wrong key, changed data
        byte[] key = generateKey();
        String enc = encrypt("Hello, ChaCha20! café ✓", key);
        System.out.println("  Key        : " + HEX.formatHex(key));
        System.out.println("  Encrypted  : " + enc);
        check(decrypt(enc, key).equals("Hello, ChaCha20! café ✓"), "decrypt back to the text");
        check(rejects(enc, generateKey()), "wrong key is rejected");
        byte[] bytes = Base64.getDecoder().decode(enc);
        bytes[12] ^= 1; // flip one bit of the ciphertext
        check(rejects(Base64.getEncoder().encodeToString(bytes), key), "changed data is rejected");
        System.out.println("All RFC 8439 checks passed.");
    }

    private static boolean rejects(String enc, byte[] key) {
        try { decrypt(enc, key); return false; } catch (AEADBadTagException e) { return true; } catch (Exception e) { return false; }
    }

    private static void check(boolean ok, String name) {
        if (!ok) throw new AssertionError("FAILED: " + name);
        System.out.println("  ok  " + name);
    }
}
