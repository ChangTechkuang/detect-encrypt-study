import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;

/**
 * ARIA block cipher demo for learning. NSRI 2004, RFC 5794, Korean standard KS X 1213.
 * The name: Academy, Research Institute, Agency (the groups that built it).
 * The JDK has no ARIA, so the cipher is written out here (same code as src/lib/aria.ts on the website).
 *
 * SPN cipher (like AES; SEED is a Feistel network instead). Block: 16 bytes. Key: 16, 24 or 32 bytes
 * -> 12, 14 or 16 rounds. Mode here: CBC + PKCS#7 padding with a random 16-byte IV. No authentication tag.
 * Output format (same as the website): Base64( IV[16 bytes] + ciphertext )
 *
 * Why SYMMETRIC? ONE secret key does both jobs: the same key encrypts and decrypts.
 *
 * How it works, from the bottom up:
 *   S-boxes SB1..SB4   swap each byte for another. SB1 is the AES S-box; SB3 and SB4 undo SB1 and SB2
 *   SL1 / SL2          one S-box per byte, in the order SB1 SB2 SB3 SB4 (odd rounds) or SB3 SB4 SB1 SB2 (even)
 *   A                  diffusion: each output byte = XOR of 7 input bytes. A(A(x)) = x
 *   FO / FE            round functions: A(SL1(x XOR key)) / A(SL2(x XOR key))
 *   Key schedule       key -> W0..W3 by 3 mini-rounds with constants from 1/pi, then each round key =
 *                      two W values XORed, one of them rotated by 19, 31, 61 or 97 bits
 *   Last round         SL2(x XOR key n) XOR key n+1 (no diffusion, one extra key)
 *   Decrypt            the same rounds with keys reversed, the middle ones passed through A
 */
public class Aria {
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final HexFormat HEX = HexFormat.of();
    private static final int BLOCK = 16;

    // Copied from RFC 5794 section 2.4.2 by script
    private static final byte[] SB1 = HEX.parseHex("637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b27509832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cfd0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdbe0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9ee1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16");
    private static final byte[] SB2 = HEX.parseHex("e24e54fc94c24acc620d6a463c4d8bd15efa64cbb497be2bbc772e03d31959c11d06416b55f09969ea9c18ae63dfe7bb007366fb964c85e43a0945aa0fee10eb2d7ff429accfad918d78c895f92fcecd087a88385c832a2847dbb8c793a41253ff870e3136215848018e377432cae9b1b7ab0cd7c4564226079860d9b6b91140ec208cbda0c984044923f14f501f13dcd8c09e57e3c37b653b028f3ee82592e515ddfd17a9bfd49a7ec53967fe769d43a7e1d0f568f21b347005a38ad57986a830c6514b1ea627f635d26e2416825fdae675a2ef2cb21c9f5d6f800a72449b6c900b5b337d5a52f361a1f7b0d63f7c6ded14e0a53d22b3f889de711aafbab581");
    private static final byte[] SB3 = inverse(SB1), SB4 = inverse(SB2);
    private static final byte[][] C = { // first 384 bits of the fraction of 1/pi
        HEX.parseHex("517cc1b727220a94fe13abe8fa9a6ee0"), HEX.parseHex("6db14acc9e21c820ff28b1d5ef5de2b0"), HEX.parseHex("db92371d2126e9700324977504e8c90e")};
    private static final int[][] A_ROWS = {{3, 4, 6, 8, 9, 13, 14}, {2, 5, 7, 8, 9, 12, 15}, {1, 4, 6, 10, 11, 12, 15}, {0, 5, 7, 10, 11, 13, 14},
        {0, 2, 5, 8, 11, 14, 15}, {1, 3, 4, 9, 10, 14, 15}, {0, 2, 7, 9, 10, 12, 13}, {1, 3, 6, 8, 11, 12, 13},
        {0, 1, 4, 7, 10, 13, 15}, {0, 1, 5, 6, 11, 12, 14}, {2, 3, 5, 6, 8, 13, 15}, {2, 3, 4, 7, 9, 12, 14},
        {1, 2, 6, 7, 9, 11, 12}, {0, 3, 6, 7, 8, 10, 13}, {0, 3, 4, 5, 9, 11, 14}, {1, 2, 4, 5, 8, 10, 15}};

    private static byte[] inverse(byte[] s) {
        byte[] r = new byte[256];
        for (int i = 0; i < 256; i++) r[s[i] & 0xff] = (byte) i;
        return r;
    }

    static byte[] xor(byte[] a, byte[] b) {
        byte[] r = new byte[BLOCK];
        for (int i = 0; i < BLOCK; i++) r[i] = (byte) (a[i] ^ b[i]);
        return r;
    }

    static byte[] sl(byte[] x, boolean odd) {
        byte[][] order = odd ? new byte[][]{SB1, SB2, SB3, SB4} : new byte[][]{SB3, SB4, SB1, SB2};
        byte[] r = new byte[BLOCK];
        for (int i = 0; i < BLOCK; i++) r[i] = order[i % 4][x[i] & 0xff];
        return r;
    }

    static byte[] a(byte[] x) {
        byte[] r = new byte[BLOCK];
        for (int i = 0; i < BLOCK; i++) { int v = 0; for (int j : A_ROWS[i]) v ^= x[j]; r[i] = (byte) v; }
        return r;
    }

    static byte[] fo(byte[] d, byte[] rk) { return a(sl(xor(d, rk), true)); }
    static byte[] fe(byte[] d, byte[] rk) { return a(sl(xor(d, rk), false)); }

    /** Rotate a 128-bit value right by n bits (left by n = right by 128 - n). */
    static byte[] rotr(byte[] x, int n) {
        int q = n >> 3, r = n & 7;
        byte[] out = new byte[BLOCK];
        for (int i = 0; i < BLOCK; i++)
            out[i] = (byte) (((x[(i - q + 16) % 16] & 0xff) >>> r) | ((x[(i - q + 15) % 16] & 0xff) << (8 - r)));
        return out;
    }

    /** Encryption round keys ek1..ek{n+1}. */
    static byte[][] encKeys(byte[] key) {
        int bits = key.length * 8;
        byte[] kl = Arrays.copyOf(key, 16), kr = new byte[16];
        if (key.length > 16) System.arraycopy(key, 16, kr, 0, key.length - 16);
        byte[][] ck = bits == 128 ? new byte[][]{C[0], C[1], C[2]} : bits == 192 ? new byte[][]{C[1], C[2], C[0]} : new byte[][]{C[2], C[0], C[1]};
        byte[] w0 = kl, w1 = xor(fo(w0, ck[0]), kr), w2 = xor(fe(w1, ck[1]), w0), w3 = xor(fo(w2, ck[2]), w1);
        byte[][] w = {w0, w1, w2, w3};
        int[] rot = {19, 31, 128 - 61, 128 - 31, 128 - 19}; // as right rotations: >>>19, >>>31, <<<61, <<<31, <<<19
        byte[][] ek = new byte[17][];
        for (int g = 0; g < 5; g++)
            for (int i = 0; i < 4 && g * 4 + i < 17; i++)
                ek[g * 4 + i] = i < 3 ? xor(w[i], rotr(w[i + 1], rot[g])) : xor(rotr(w[0], rot[g]), w[3]);
        int rounds = bits == 128 ? 12 : bits == 192 ? 14 : 16;
        return Arrays.copyOf(ek, rounds + 1);
    }

    /** dk1 = ek{n+1}, dk{i} = A(ek{n+2-i}), dk{n+1} = ek1. */
    static byte[][] decKeys(byte[][] ek) {
        int n = ek.length - 1;
        byte[][] dk = new byte[n + 1][];
        for (int i = 0; i <= n; i++) dk[i] = i == 0 ? ek[n] : i == n ? ek[0] : a(ek[n - i]);
        return dk;
    }

    static byte[] block(byte[][] keys, byte[] p) {
        int n = keys.length - 1;
        for (int i = 0; i < n - 1; i++) p = i % 2 == 0 ? fo(p, keys[i]) : fe(p, keys[i]);
        return xor(sl(xor(p, keys[n - 1]), false), keys[n]);
    }

    /** ECB if iv is null, else CBC. data must be a whole number of blocks. */
    static byte[] aria(boolean encrypt, byte[] key, byte[] iv, byte[] data) {
        byte[][] ek = encKeys(key), keys = encrypt ? ek : decKeys(ek);
        byte[] out = new byte[data.length], prev = iv == null ? null : iv.clone();
        for (int o = 0; o < data.length; o += BLOCK) {
            byte[] in = Arrays.copyOfRange(data, o, o + BLOCK);
            if (encrypt) {
                byte[] c = block(keys, prev != null ? xor(in, prev) : in);
                System.arraycopy(c, 0, out, o, BLOCK);
                if (prev != null) prev = c;
            } else {
                byte[] p = block(keys, in);
                if (prev != null) { p = xor(p, prev); prev = in; }
                System.arraycopy(p, 0, out, o, BLOCK);
            }
        }
        return out;
    }

    public static byte[] generateKey(int bytes) {
        byte[] key = new byte[bytes];
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
        byte[] ct = aria(true, key, iv, padded);
        return Base64.getEncoder().encodeToString(ByteBuffer.allocate(iv.length + ct.length).put(iv).put(ct).array());
    }

    /** Throws IllegalArgumentException if the padding is invalid (usually: wrong key or changed last block). */
    public static String decrypt(String encrypted, byte[] key) {
        byte[] all = Base64.getDecoder().decode(encrypted.trim());
        if (all.length < 2 * BLOCK || all.length % BLOCK != 0) throw new IllegalArgumentException("Bad length");
        byte[] pt = aria(false, key, Arrays.copyOf(all, BLOCK), Arrays.copyOfRange(all, BLOCK, all.length));
        int pad = pt[pt.length - 1] & 0xff;
        if (pad < 1 || pad > BLOCK) throw new IllegalArgumentException("Bad padding");
        for (int i = pt.length - pad; i < pt.length; i++)
            if ((pt[i] & 0xff) != pad) throw new IllegalArgumentException("Bad padding");
        return new String(pt, 0, pt.length - pad, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) {
        // java Aria.java encrypt <keyHex> "text"   |   java Aria.java decrypt <keyHex> <base64>
        if (args.length == 3) {
            byte[] key = HEX.parseHex(args[1]);
            System.out.println(args[0].equals("decrypt") ? decrypt(args[2], key) : encrypt(args[2], key));
            return;
        }

        check((SB1[0x23] & 0xff) == 0x26 && (SB4[0xef] & 0xff) == 0xd3, "S-boxes: SB1(23) = 26 and SB4(ef) = d3, as RFC 5794 says");

        // RFC 5794 appendix A: one block, all three key sizes
        String pt = "00112233445566778899aabbccddeeff";
        String[][] vectors = {
            {"000102030405060708090a0b0c0d0e0f", "d718fbd6ab644c739da95f3be6451778"},
            {"000102030405060708090a0b0c0d0e0f1011121314151617", "26449c1805dbe7aa25a468ce263a9e79"},
            {"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "f92bd7c79fb72e2f2b8f80c1972d24fc"},
        };
        for (String[] v : vectors) {
            byte[] key = HEX.parseHex(v[0]);
            check(HEX.formatHex(aria(true, key, null, HEX.parseHex(pt))).equals(v[1]), "ARIA-" + key.length * 8 + "(" + pt + ") = " + v[1]);
            check(HEX.formatHex(aria(false, key, null, HEX.parseHex(v[1]))).equals(pt), "decrypt back to " + pt);
        }
        // RFC 5794 A.1 intermediate values: round key 1 and the state after round 1
        byte[][] ek = encKeys(HEX.parseHex(vectors[0][0]));
        check(HEX.formatHex(ek[0]).equals("d415a75c794b85c5e0d2a0b3cb793bf6"), "round key 1 matches RFC A.1");
        check(HEX.formatHex(ek[12]).equals("0f0aa16daee61bd7dfee5a599970fb35"), "round key 13 matches RFC A.1");
        check(HEX.formatHex(fo(HEX.parseHex(pt), ek[0])).equals("7fc7f12befd0a0791de87fa96b469f52"), "after round 1 matches RFC A.1 (P1)");

        // The study page's CBC example ("Hello, ARIA!", fixed key and IV, checked against OpenSSL)
        byte[] k = HEX.parseHex("4706480851e61be85d74bfb3fd956185"), iv = HEX.parseHex("000102030405060708090a0b0c0d0e0f");
        check(HEX.formatHex(aria(true, k, iv, HEX.parseHex("48656c6c6f2c20415249412104040404"))).equals("376d59ce3ff89ad4e4dcc2224b50cf5c"), "\"Hello, ARIA!\" matches the page");
        check(decrypt("AAECAwQFBgcICQoLDA0ODzdtWc4/+JrU5NzCIktQz1w=", k).equals("Hello, ARIA!"), "the page's Base64 decrypts to \"Hello, ARIA!\"");

        for (int size : new int[]{16, 24, 32}) {
            byte[] key = generateKey(size);
            String text = "Hello, ARIA! 결제 승인 ✓";
            check(decrypt(encrypt(text, key), key).equals(text), "ARIA-" + size * 8 + " round trip (UTF-8)");
        }
        byte[] key = generateKey(16);
        String enc = encrypt("Hello, ARIA!", key);
        try {
            check(!decrypt(enc, generateKey(16)).equals("Hello, ARIA!"), "wrong key -> garbage (padding happened to look valid)");
        } catch (IllegalArgumentException e) {
            check(true, "wrong key -> padding error");
        }
        System.out.println("All RFC 5794 checks passed.");
        System.out.println("Sample key : " + HEX.formatHex(key));
        System.out.println("Encrypted  : " + enc);
    }

    private static void check(boolean ok, String name) {
        if (!ok) throw new AssertionError("FAILED: " + name);
        System.out.println("  ok  " + name);
    }
}
