import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;

/**
 * SEED block cipher demo for learning. KISA 1998, RFC 4269. South Korea's national standard.
 * The JDK has no SEED, so the cipher is written out here (same code idea as the Implement page (src/lib/impl)).
 *
 * 16-round Feistel network. Key: 16 bytes. Block: 16 bytes.
 * Mode here: CBC + PKCS#7 padding with a random 16-byte IV. No authentication tag.
 *
 * Output format (same as the Implement page (src/lib/impl)): Base64( IV[16 bytes] + ciphertext )
 *
 * Why SYMMETRIC? ONE secret key does both jobs: the same 16 bytes encrypt and decrypt.
 * Both sides must already share that key (compare RSA: two different keys, one of them public).
 * In 공동인증서, SEED is what locks signPri.key with a key made from your password.
 *
 * How it works, from the bottom up:
 *   S-boxes S1, S2   swap each byte for another (the only non-linear step: it is what makes it hard to undo
 *                    without the key)
 *   G function       4 bytes -> 4 S-box lookups -> bits mixed between the bytes with masks
 *   F function       mixes a 64-bit half with a 64-bit round key, using G three times
 *   Key schedule     the 16-byte key -> 16 round keys (64 bits each), by rotating the key and running G
 *   Feistel rounds   block = left half L | right half R. Each round:  L, R  ->  R, L XOR F(R, round key)
 *                    16 rounds. Decrypt = the SAME rounds with the round keys in reverse order, because
 *                    XOR undoes itself. F never has to be reversed, which is the trick of a Feistel network.
 *   CBC mode         each 16-byte block is XORed with the previous ciphertext block (the IV for the first)
 *                    before it is encrypted, so equal blocks of text do not give equal ciphertext.
 */
public class Seed {
    private static final int BLOCK = 16;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final HexFormat HEX = HexFormat.of();

    // S-boxes S1, S2 from RFC 4269 (S1(x) = A1·x^247 ⊕ 169, S2(x) = A2·x^251 ⊕ 56 in GF(2^8))
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
    private static final int[][] SS = new int[4][256]; // S-box byte spread over 4 bytes with masks

    static {
        for (int b = 0; b < 4; b++)
            for (int x = 0; x < 256; x++) {
                int v = ((b % 2 == 0) ? S1 : S2)[x] & 0xff;
                SS[b][x] = (v & M[(b + 3) % 4]) << 24 | (v & M[(b + 2) % 4]) << 16 | (v & M[(b + 1) % 4]) << 8 | (v & M[b]);
            }
    }

    /** G: look up each of the 4 bytes in an S-box (pre-mixed into SS) and XOR the results. */
    private static int g(int x) {
        return SS[0][x & 0xff] ^ SS[1][x >>> 8 & 0xff] ^ SS[2][x >>> 16 & 0xff] ^ SS[3][x >>> 24];
    }

    /**
     * Key schedule: the one secret key -> 16 rounds x 2 subkeys (32-bit words).
     * Encrypt and decrypt use the SAME subkeys (symmetric), just in opposite order.
     */
    private static int[] roundKeys(byte[] key) {
        if (key.length != BLOCK) throw new IllegalArgumentException("SEED needs a 16-byte key (32 hex chars)");
        ByteBuffer kb = ByteBuffer.wrap(key);
        int k0 = kb.getInt(), k1 = kb.getInt(), k2 = kb.getInt(), k3 = kb.getInt();
        int[] out = new int[32];
        for (int i = 0; i < 16; i++) {
            int kc = Integer.rotateLeft(0x9e3779b9, i); // golden ratio constant
            out[2 * i] = g(k0 + k2 - kc);
            out[2 * i + 1] = g(k1 - k3 + kc);
            if (i % 2 == 0) { int t = k0; k0 = k0 >>> 8 | k1 << 24; k1 = k1 >>> 8 | t << 24; } // K0||K1 >>> 8
            else            { int t = k2; k2 = k2 << 8 | k3 >>> 24; k3 = k3 << 8 | t >>> 24; } // K2||K3 <<< 8
        }
        return out;
    }

    /** One 16-byte block through 16 Feistel rounds. */
    private static byte[] block(int[] k, boolean encrypt, byte[] in) {
        ByteBuffer b = ByteBuffer.wrap(in);
        int l0 = b.getInt(), l1 = b.getInt(), r0 = b.getInt(), r1 = b.getInt(); // L = l0|l1, R = r0|r1 (64 bits each)
        for (int i = 0; i < 16; i++) {
            int j = 2 * (encrypt ? i : 15 - i); // decrypt: same keys, reverse order
            int c = r0 ^ k[j], d = r1 ^ k[j + 1];                // mix R with the round key
            d = g(c ^ d); c = g(c + d); d = g(d + c); c += d;    // round function F: 3 x G
            int t0 = r0, t1 = r1;
            r0 = l0 ^ c; r1 = l1 ^ d; l0 = t0; l1 = t1;          // new L = old R, new R = old L XOR F(R)
        }
        return ByteBuffer.allocate(BLOCK).putInt(r0).putInt(r1).putInt(l0).putInt(l1).array(); // undo last swap
    }

    /**
     * ECB if iv is null, else CBC. data must be a whole number of blocks.
     * CBC encrypt: c[i] = SEED(p[i] XOR c[i-1])     CBC decrypt: p[i] = SEED^-1(c[i]) XOR c[i-1]     (c[-1] = IV)
     */
    static byte[] seed(boolean encrypt, byte[] key, byte[] iv, byte[] data) {
        int[] k = roundKeys(key);
        byte[] out = new byte[data.length], prev = iv == null ? null : iv.clone();
        for (int o = 0; o < data.length; o += BLOCK) {
            byte[] in = Arrays.copyOfRange(data, o, o + BLOCK);
            if (encrypt) {
                if (prev != null) for (int i = 0; i < BLOCK; i++) in[i] ^= prev[i];
                byte[] c = block(k, true, in);
                System.arraycopy(c, 0, out, o, BLOCK);
                if (prev != null) prev = c;
            } else {
                byte[] p = block(k, false, in);
                if (prev != null) { for (int i = 0; i < BLOCK; i++) p[i] ^= prev[i]; prev = in; }
                System.arraycopy(p, 0, out, o, BLOCK);
            }
        }
        return out;
    }

    public static byte[] generateKey() {
        byte[] key = new byte[BLOCK];
        RANDOM.nextBytes(key);
        return key;
    }

    public static String encrypt(String plaintext, byte[] key) {
        byte[] iv = new byte[BLOCK];
        RANDOM.nextBytes(iv);
        byte[] pt = plaintext.getBytes(StandardCharsets.UTF_8);
        int pad = BLOCK - pt.length % BLOCK;
        byte[] padded = Arrays.copyOf(pt, pt.length + pad);
        Arrays.fill(padded, pt.length, padded.length, (byte) pad); // PKCS#7
        byte[] ct = seed(true, key, iv, padded);
        return Base64.getEncoder().encodeToString(ByteBuffer.allocate(iv.length + ct.length).put(iv).put(ct).array());
    }

    /** Throws IllegalArgumentException if the padding is invalid (usually: wrong key or changed last block). */
    public static String decrypt(String encrypted, byte[] key) {
        byte[] all = Base64.getDecoder().decode(encrypted.trim());
        if (all.length < 2 * BLOCK || all.length % BLOCK != 0) throw new IllegalArgumentException("Bad length");
        byte[] pt = seed(false, key, Arrays.copyOf(all, BLOCK), Arrays.copyOfRange(all, BLOCK, all.length));
        int pad = pt[pt.length - 1] & 0xff;
        if (pad < 1 || pad > BLOCK) throw new IllegalArgumentException("Bad padding");
        for (int i = pt.length - pad; i < pt.length; i++)
            if ((pt[i] & 0xff) != pad) throw new IllegalArgumentException("Bad padding");
        return new String(pt, 0, pt.length - pad, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) {
        // java Seed.java encrypt <keyHex> "text"   |   java Seed.java decrypt <keyHex> <base64>
        if (args.length == 3) {
            byte[] key = HEX.parseHex(args[1]);
            System.out.println(args[0].equals("decrypt") ? decrypt(args[2], key) : encrypt(args[2], key));
            return;
        }

        check(S1.length == 256 && S2.length == 256, "S-boxes have 256 entries");

        // RFC 4269 appendix B (raw block, ECB): key, plaintext, ciphertext
        String[][] vectors = {
            {"00000000000000000000000000000000", "000102030405060708090a0b0c0d0e0f", "5ebac6e0054e166819aff1cc6d346cdb"},
            {"000102030405060708090a0b0c0d0e0f", "00000000000000000000000000000000", "c11f22f20140505084483597e4370f43"},
            {"4706480851e61be85d74bfb3fd956185", "83a2f8a288641fb9a4e9a5cc2f131c7d", "ee54d13ebcae706d226bc3142cd40d4a"},
            {"28dbc3bc49ffd87dcfa509b11d422be7", "b41e6be2eba84a148e2eed84593c5ec7", "9b9b7bfcd1813cb95d0b3618f40f5122"},
        };
        for (String[] v : vectors) {
            byte[] key = HEX.parseHex(v[0]);
            check(HEX.formatHex(seed(true, key, null, HEX.parseHex(v[1]))).equals(v[2]), "SEED(key " + v[0] + ", " + v[1] + ") = " + v[2]);
            check(HEX.formatHex(seed(false, key, null, HEX.parseHex(v[2]))).equals(v[1]), "decrypt back to " + v[1]);
        }

        // CBC, same answer as the Implement page's SEED code
        check(HEX.formatHex(seed(true, HEX.parseHex("00112233445566778899aabbccddeeff"), HEX.parseHex("0f0e0d0c0b0a09080706050403020100"),
                HEX.parseHex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51")))
                .equals("dcc829e8bfed50298b20bd140f5f62673ba7b681aaddf159ce13cf82c3c9ec0a"), "CBC two blocks match the page");

        byte[] key = generateKey();
        String text = "Hello, SEED! café ✓";
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
        } catch (IllegalArgumentException e) {
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
