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
 * Triple DES (3DES / TDEA / "DESede") demo for learning. NIST SP 800-67, disallowed for encryption after 2023.
 * Runs DES three times: encrypt with K1, decrypt with K2, encrypt with K3 (EDE).
 * If K1 = K2 = K3 it is exactly single DES (that is why EDE was chosen: backward compatible).
 *
 * Key: 24 bytes (three 8-byte DES keys, 168 bits, about 112 bits of real strength). Block: 8 bytes.
 * Mode here: CBC + PKCS#5 padding with a random 8-byte IV. No authentication tag.
 *
 * Output format (same as the Implement page (src/lib/impl)): Base64( IV[8 bytes] + ciphertext )
 *
 * Why SYMMETRIC? ONE secret key (K1|K2|K3, 24 bytes) both encrypts and decrypts, so both sides must
 * already share it (compare RSA: two different keys, one of them public).
 *
 * How it works: plain DES (see des/Des.java) three times on each 8-byte block, with three keys:
 *   Encrypt:  c = E_K3( D_K2( E_K1(p) ) )     E = DES encrypt, D = DES decrypt
 *   Decrypt:  p = D_K1( E_K2( D_K3(c) ) )     the same steps undone in reverse order
 *   Why the middle step DEcrypts (EDE): if K1 = K2 = K3, then D_K2 undoes E_K1 and only E_K3 is left,
 *   so 3DES with one repeated key IS single DES. Old DES systems could talk to new 3DES ones.
 *
 * Key options:
 *   3 keys  K1, K2, K3 all different: 168 key bits (here)
 *   2 keys  K3 = K1: 112 key bits (still allowed long ago, now retired)
 *   1 key   K1 = K2 = K3: same as DES, broken (self-check 2 shows this)
 *
 * Why 168 key bits give only about 112 bits of strength: "meet in the middle". An attacker encrypts p
 * with every K1 and decrypts c with every K3 and looks for a match in the middle, so the work is about
 * 2^112, not 2^168. That is also why not 2DES: two DES steps fall to the same trick at about 2^57.
 *
 * Why it is retired now: the block is still only 8 bytes. After about 2^32 blocks (32 GB) under one key,
 * two ciphertext blocks repeat by chance and leak the XOR of their plaintexts (the Sweet32 attack, 2016).
 * It is also 3 x slower than DES. AES (aes/) replaced it: 16-byte blocks, faster, bigger keys.
 */
public class TripleDes {
    private static final int BLOCK = 8, KEY = 24;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final HexFormat HEX = HexFormat.of();

    public static byte[] generateKey() {
        byte[] key = new byte[KEY];
        RANDOM.nextBytes(key);
        return key;
    }

    /**
     * SYMMETRIC encrypt with the secret key. Each block: E_K3(D_K2(E_K1(...))), chained with CBC:
     * c[i] = 3DES(p[i] XOR c[i-1]), c[-1] = a random IV (sent in front, not secret).
     */
    public static String encrypt(String plaintext, byte[] key) throws GeneralSecurityException {
        byte[] iv = new byte[BLOCK];
        RANDOM.nextBytes(iv);
        byte[] ct = tdes("DESede/CBC/PKCS5Padding", Cipher.ENCRYPT_MODE, key, iv, plaintext.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(ByteBuffer.allocate(iv.length + ct.length).put(iv).put(ct).array());
    }

    /**
     * SYMMETRIC decrypt with the SAME secret key. Each block: D_K1(E_K2(D_K3(...))), then XOR c[i-1].
     * Throws BadPaddingException if the padding is invalid (usually: wrong key or changed last block).
     */
    public static String decrypt(String encrypted, byte[] key) throws GeneralSecurityException {
        byte[] all = Base64.getDecoder().decode(encrypted.trim());
        if (all.length < 2 * BLOCK || all.length % BLOCK != 0) throw new IllegalArgumentException("Bad length");
        byte[] pt = tdes("DESede/CBC/PKCS5Padding", Cipher.DECRYPT_MODE, key,
                Arrays.copyOf(all, BLOCK), Arrays.copyOfRange(all, BLOCK, all.length));
        return new String(pt, StandardCharsets.UTF_8);
    }

    private static byte[] tdes(String transform, int mode, byte[] key, byte[] iv, byte[] data) throws GeneralSecurityException {
        // Java's "DESede" = DES Encrypt-Decrypt-Encrypt. Bytes 0-7 = K1, 8-15 = K2, 16-23 = K3
        if (key.length != KEY) throw new IllegalArgumentException("3DES needs a 24-byte key (48 hex chars)");
        Cipher c = Cipher.getInstance(transform);
        if (iv == null) c.init(mode, new SecretKeySpec(key, "DESede"));
        else c.init(mode, new SecretKeySpec(key, "DESede"), new IvParameterSpec(iv));
        return c.doFinal(data);
    }

    public static void main(String[] args) throws Exception {
        // java TripleDes.java encrypt <keyHex> "text"   |   java TripleDes.java decrypt <keyHex> <base64>
        if (args.length == 3) {
            byte[] key = HEX.parseHex(args[1]);
            System.out.println(args[0].equals("decrypt") ? decrypt(args[2], key) : encrypt(args[2], key));
            return;
        }

        // Raw block cipher, ECB, no padding: key (K1|K2|K3), plaintext, ciphertext
        String[][] vectors = {
            // NIST SP 800-67 sample: "The qufck brown fox jump"
            {"0123456789abcdef23456789abcdef01456789abcdef0123",
             "5468652071756663 6b2062726f776e20 666f78206a756d70".replace(" ", ""),
             "a826fd8ce53b855fcce21c8112256fe668d5c05dd9b6b900"},
            // K1 = K2 = K3: same result as single DES "Now is t" (FIPS 81), because D_K2 undoes E_K1 (EDE)
            {"0123456789abcdef0123456789abcdef0123456789abcdef", "4e6f772069732074", "3fa40e8a984d4815"},
            {"0".repeat(48), "0000000000000000", "8ca64de9c1b123a7"},
        };
        for (String[] v : vectors) {
            byte[] key = HEX.parseHex(v[0]);
            check(HEX.formatHex(tdes("DESede/ECB/NoPadding", Cipher.ENCRYPT_MODE, key, null, HEX.parseHex(v[1]))).equals(v[2]),
                    "3DES(key " + v[0].substring(0, 16) + "..., " + v[1] + ") = " + v[2]);
            check(HEX.formatHex(tdes("DESede/ECB/NoPadding", Cipher.DECRYPT_MODE, key, null, HEX.parseHex(v[2]))).equals(v[1]),
                    "decrypt back to " + v[1]);
        }

        byte[] key = generateKey();
        String text = "Hello, 3DES! café ✓";
        String enc = encrypt(text, key);
        check(decrypt(enc, key).equals(text), "round trip (UTF-8)");
        check(!encrypt(text, key).equals(enc), "same text twice -> different output (random IV)");

        byte[] tampered = Base64.getDecoder().decode(enc);
        tampered[0] ^= 1;
        String changed = decrypt(Base64.getEncoder().encodeToString(tampered), key);
        check(!changed.equals(text), "changed data is NOT detected, decrypts to: " + changed.replaceAll("\\p{Cntrl}", "?"));

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
