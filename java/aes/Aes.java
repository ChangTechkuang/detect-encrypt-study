import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES demo for learning: key size 128 / 192 / 256 bits (from the key length) and mode ECB / CBC / CTR / GCM.
 *
 *   GCM  IV 12 bytes, adds a 16-byte tag: wrong key or changed data is detected. Use this one.
 *   CBC  IV 16 bytes, PKCS#5 padding. No integrity check.
 *   CTR  16-byte counter, no padding (stream). No integrity check, never fails: wrong key gives garbage.
 *   ECB  no IV, PKCS#5 padding. INSECURE: equal plaintext blocks give equal ciphertext blocks.
 *
 * Output format (same as the Implement page (src/lib/impl)): Base64( IV + ciphertext [+ tag for GCM] ). ECB has no IV.
 *
 * Why SYMMETRIC? ONE secret key both encrypts and decrypts, so both sides must already share it
 * (compare RSA: a public key to encrypt, a different private key to decrypt). Symmetric ciphers are
 * thousands of times faster than RSA, which is why real systems (TLS, 공동인증서's key file) use RSA or
 * a password only to protect a symmetric key, and the symmetric cipher for the actual data.
 *
 * How the AES block cipher works (FIPS 197; Java's Cipher does this inside):
 *   The 16-byte block is a 4x4 grid of bytes (the "state"). Each round does 4 steps:
 *     SubBytes     swap every byte through the S-box (the non-linear step: makes it hard to undo without the key)
 *     ShiftRows    rotate row r left by r places (spreads bytes across columns)
 *     MixColumns   mix the 4 bytes of each column together (one changed byte changes the whole column)
 *     AddRoundKey  XOR the state with this round's key (the only step that uses the key)
 *   Rounds: 10 for a 128-bit key, 12 for 192, 14 for 256. The key schedule stretches the one key into
 *   (rounds + 1) round keys. After 2 rounds every output bit depends on every input bit.
 *   Unlike DES and SEED (Feistel), AES is a substitution-permutation network: decrypting runs the
 *   INVERSE of each step (InvSubBytes, InvShiftRows, InvMixColumns) with the round keys in reverse order.
 *
 * The block cipher alone only handles exactly 16 bytes. The MODE decides how longer text is chained:
 *   ECB  c[i] = AES(p[i])                    each block alone: equal blocks leak as equal output
 *   CBC  c[i] = AES(p[i] XOR c[i-1])         chain on the previous output, c[-1] = random IV
 *   CTR  c[i] = p[i] XOR AES(counter + i)    AES makes a keystream; XOR with it, so no padding needed
 *   GCM  CTR + a 16-byte tag (GHASH over the ciphertext): decrypting checks the tag first
 *
 * Run:  java Aes.java                                (self-checks)
 *       java Aes.java encrypt GCM <keyHex> "text"
 *       java Aes.java decrypt GCM <keyHex> <base64>
 */
public class Aes {
    public enum Mode {
        ECB(0, "AES/ECB/PKCS5Padding"), CBC(16, "AES/CBC/PKCS5Padding"),
        CTR(16, "AES/CTR/NoPadding"), GCM(12, "AES/GCM/NoPadding");

        final int ivBytes;
        final String transform;

        Mode(int ivBytes, String transform) { this.ivBytes = ivBytes; this.transform = transform; }
    }

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final HexFormat HEX = HexFormat.of();

    /** New random key of 128, 192 or 256 bits. Keep it secret. */
    public static byte[] generateKey(int bits) {
        byte[] key = new byte[bits / 8];
        RANDOM.nextBytes(key);
        return key;
    }

    /**
     * SYMMETRIC encrypt with the secret key. A fresh random IV every call (except ECB, which has none).
     * The IV is not secret: it is sent in front of the ciphertext. It only must never repeat with the same key.
     */
    public static String encrypt(Mode mode, String plaintext, byte[] key) throws GeneralSecurityException {
        byte[] iv = new byte[mode.ivBytes];
        RANDOM.nextBytes(iv);
        byte[] ct = run(mode, mode.transform, Cipher.ENCRYPT_MODE, key, iv, plaintext.getBytes(StandardCharsets.UTF_8));
        byte[] all = Arrays.copyOf(iv, iv.length + ct.length);
        System.arraycopy(ct, 0, all, iv.length, ct.length);
        return Base64.getEncoder().encodeToString(all);
    }

    /**
     * SYMMETRIC decrypt with the SAME secret key that encrypted.
     * GCM: AEADBadTagException on wrong key / changed data. ECB, CBC: usually BadPaddingException. CTR: never fails.
     */
    public static String decrypt(Mode mode, String encrypted, byte[] key) throws GeneralSecurityException {
        byte[] all = Base64.getDecoder().decode(encrypted.trim());
        if (all.length < mode.ivBytes) throw new IllegalArgumentException("Data too short");
        byte[] iv = Arrays.copyOf(all, mode.ivBytes);
        byte[] ct = Arrays.copyOfRange(all, mode.ivBytes, all.length);
        return new String(run(mode, mode.transform, Cipher.DECRYPT_MODE, key, iv, ct), StandardCharsets.UTF_8);
    }

    private static byte[] run(Mode mode, String transform, int op, byte[] key, byte[] iv, byte[] data)
            throws GeneralSecurityException {
        if (key.length != 16 && key.length != 24 && key.length != 32)
            throw new IllegalArgumentException("AES key must be 16, 24 or 32 bytes (32, 48 or 64 hex chars)");
        Cipher c = Cipher.getInstance(transform);
        SecretKeySpec k = new SecretKeySpec(key, "AES"); // key length picks AES-128 / 192 / 256 (10 / 12 / 14 rounds)
        switch (mode) {
            case ECB -> c.init(op, k);
            case GCM -> c.init(op, k, new GCMParameterSpec(128, iv)); // 128-bit tag
            default -> c.init(op, k, new IvParameterSpec(iv));
        }
        return c.doFinal(data);
    }

    public static void main(String[] args) throws Exception {
        if (args.length == 4) {
            Mode mode = Mode.valueOf(args[1].toUpperCase());
            byte[] key = HEX.parseHex(args[2]);
            System.out.println(args[0].equals("decrypt") ? decrypt(mode, args[3], key) : encrypt(mode, args[3], key));
            return;
        }

        // ECB / CBC / CTR: NIST SP 800-38A appendix F (raw blocks, no padding).
        // GCM: NIST GCM spec (McGrew & Viega) test cases.   mode, name, key, iv, plaintext, ciphertext
        String k128 = "2b7e151628aed2a6abf7158809cf4f3c";
        String k192 = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
        String k256 = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
        String p1 = "6bc1bee22e409f96e93d7e117393172a", p2 = "ae2d8a571e03ac9c9eb76fac45af8e51";
        String cbcIv = "000102030405060708090a0b0c0d0e0f", ctrIv = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
        String gcmP = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255";
        String[][] vectors = {
            {"ECB", "F.1.1 AES-128", k128, "", p1 + p2, "3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf"},
            {"ECB", "F.1.3 AES-192", k192, "", p1, "bd334f1d6e45f25ff712a214571fa5cc"},
            {"ECB", "F.1.5 AES-256", k256, "", p1, "f3eed1bdb5d2a03c064b5a7e3db181f8"},
            {"CBC", "F.2.1 AES-128", k128, cbcIv, p1 + p2, "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2"},
            {"CBC", "F.2.3 AES-192", k192, cbcIv, p1, "4f021db243bc633d7178183a9fa071e8"},
            {"CBC", "F.2.5 AES-256", k256, cbcIv, p1, "f58c4c04d6e5f1ba779eabfb5f7bfbd6"},
            {"CTR", "F.5.1 AES-128", k128, ctrIv, p1 + p2, "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff"},
            {"CTR", "F.5.3 AES-192", k192, ctrIv, p1, "1abc932417521ca24f2b0459fe7e6e0b"},
            {"CTR", "F.5.5 AES-256", k256, ctrIv, p1, "601ec313775789a5b7a7f504bbf3d228"},
            {"GCM", "test case 3 AES-128", "feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888", gcmP,
                "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f59854d5c2af327cd64a62cf35abd2ba6fab4"},
            {"GCM", "test case 9 AES-192", "feffe9928665731c6d6a8f9467308308feffe9928665731c", "cafebabefacedbaddecaf888", gcmP,
                "3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710acade2569924a7c8587336bfb118024db8674a14"},
            {"GCM", "test case 15 AES-256", "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888", gcmP,
                "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015adb094dac5d93471bdec1a502270e3cc6c"},
        };
        for (String[] v : vectors) {
            Mode mode = Mode.valueOf(v[0]);
            String raw = mode.transform.replace("PKCS5Padding", "NoPadding"); // test vectors are whole blocks
            byte[] key = HEX.parseHex(v[2]), iv = HEX.parseHex(v[3]);
            String name = v[0] + " " + v[1];
            check(HEX.formatHex(run(mode, raw, Cipher.ENCRYPT_MODE, key, iv, HEX.parseHex(v[4]))).equals(v[5]), name + " encrypt");
            check(HEX.formatHex(run(mode, raw, Cipher.DECRYPT_MODE, key, iv, HEX.parseHex(v[5]))).equals(v[4]), name + " decrypt");
        }

        String text = "Hello, AES! Hello, AES! ";
        for (Mode mode : Mode.values()) {
            for (int bits : new int[] {128, 192, 256}) {
                byte[] key = generateKey(bits);
                String enc = encrypt(mode, text, key);
                check(decrypt(mode, enc, key).equals(text), mode + " AES-" + bits + " round trip");
            }
        }

        byte[] key = generateKey(256);
        // ECB has no IV: same text -> same output, and equal 16-byte blocks -> equal ciphertext blocks
        String sixteenA = "AAAAAAAAAAAAAAAA";
        check(encrypt(Mode.ECB, text, key).equals(encrypt(Mode.ECB, text, key)), "ECB same text twice -> SAME output (no IV)");
        byte[] ecb = Base64.getDecoder().decode(encrypt(Mode.ECB, sixteenA + sixteenA, key));
        check(Arrays.equals(Arrays.copyOf(ecb, 16), Arrays.copyOfRange(ecb, 16, 32)), "ECB equal blocks -> equal ciphertext (pattern leak)");
        for (Mode mode : new Mode[] {Mode.CBC, Mode.CTR, Mode.GCM})
            check(!encrypt(mode, text, key).equals(encrypt(mode, text, key)), mode + " same text twice -> different output (random IV)");

        // Integrity: flip one bit of the first ciphertext byte
        for (Mode mode : Mode.values()) {
            byte[] all = Base64.getDecoder().decode(encrypt(mode, text, key));
            all[mode.ivBytes] ^= 1;
            String tampered = Base64.getEncoder().encodeToString(all);
            try {
                String out = decrypt(mode, tampered, key);
                check(mode != Mode.GCM, mode + " changed data NOT detected, decrypts to: " + out.replaceAll("[^\\x20-\\x7e]", "?"));
            } catch (AEADBadTagException e) {
                check(mode == Mode.GCM, mode + " changed data is rejected (tag mismatch)");
            } catch (BadPaddingException e) {
                check(mode != Mode.GCM, mode + " changed data happened to break the padding");
            }
        }
        System.out.println("All checks passed.");
    }

    private static void check(boolean ok, String name) {
        if (!ok) throw new AssertionError("FAILED: " + name);
        System.out.println("  ok  " + name);
    }
}
