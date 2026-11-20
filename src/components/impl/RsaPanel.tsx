"use client";

import { useEffect, useRef, useState } from "react";
import { enc, dec, toB64, fromB64 } from "@/lib/bytes";
import {
  rsaPublic, rsaPrivate, rsaMax, rsaBits, rsaEncrypt, rsaDecrypt,
  pssPrivate, pssPublic, rsaSign, rsaVerify, rsaGenerate, rsaChecks,
} from "@/lib/impl/rsa";
import {
  Section, About, Note, Warning, Label, TextArea, Select, Button, CopyButton,
  OutputRow, Meta, Result, type ResultState, useSelfChecks, ChecksTable,
} from "./ui";

const BAD_PUB = '✗ Not a valid RSA public key (PEM "PUBLIC KEY")';
const BAD_PRIV = '✗ Not a valid RSA private key (PEM "PRIVATE KEY", PKCS #8)';

export default function RsaPanel() {
  const [bits, setBits] = useState("2048");
  const [busy, setBusy] = useState(false);
  const [genMsg, setGenMsg] = useState("");
  const [pub, setPub] = useState("");
  const [priv, setPriv] = useState("");

  const [plain, setPlain] = useState("Hello, RSA!");
  const [max, setMax] = useState<number | null>(null);
  const [encRes, setEncRes] = useState<ResultState>(null);
  const [cipher, setCipher] = useState("");

  const [dCipher, setDCipher] = useState("");
  const [dRes, setDRes] = useState<ResultState>(null);
  const [dPlain, setDPlain] = useState("");

  const [signMsg, setSignMsg] = useState("Version 1.2 release approved");
  const [signRes, setSignRes] = useState<ResultState>(null);
  const [sig, setSig] = useState("");

  const [vMsg, setVMsg] = useState("");
  const [vSig, setVSig] = useState("");
  const [vRes, setVRes] = useState<ResultState>(null);

  const started = useRef(false);

  const checks = useSelfChecks(rsaChecks, "rsa");

  // Max message size follows the public key in the box (null while it is not a valid key).
  useEffect(() => {
    let alive = true;
    rsaPublic(pub).then((k) => alive && setMax(rsaMax(k)), () => alive && setMax(null));
    return () => { alive = false; };
  }, [pub]);

  async function generate(size: number) {
    setBusy(true);
    const t0 = performance.now();
    const kp = await rsaGenerate(size);
    setPub(kp.pub);
    setPriv(kp.priv);
    setGenMsg(`✓ New ${size}-bit key pair, took ${Math.round(performance.now() - t0)} ms.`);
    setCipher(""); setDPlain(""); setDCipher(""); setSig(""); setVSig("");
    setEncRes(null); setDRes(null); setSignRes(null); setVRes(null);
    setBusy(false);
  }

  // Like the original page: a fresh 2048-bit pair when the panel opens (ref guards the Strict Mode double run).
  useEffect(() => {
    if (started.current) return;
    started.current = true;
    generate(2048);
  }, []);

  async function encrypt() {
    setCipher("");
    let key: CryptoKey;
    try { key = await rsaPublic(pub); } catch { return setEncRes({ ok: false, text: BAD_PUB }); }
    const bytes = enc(plain), m = rsaMax(key);
    if (bytes.length > m) {
      return setEncRes({ ok: false, text: `✗ Too long: ${bytes.length} bytes, but RSA-${rsaBits(key)} can encrypt at most ${m}. Real systems encrypt an AES key with RSA, and the data with AES.` });
    }
    setCipher(toB64(await rsaEncrypt(key, bytes)));
    setEncRes({ ok: true, text: `✓ Encrypted with the public key: ${bytes.length} bytes in, ${rsaBits(key) / 8} bytes out.` });
  }

  async function decrypt(b64: string) {
    setDPlain("");
    let key: CryptoKey, data: Uint8Array<ArrayBuffer>;
    try { key = await rsaPrivate(priv); } catch { return setDRes({ ok: false, text: BAD_PRIV }); }
    try { data = fromB64(b64); } catch { return setDRes({ ok: false, text: "✗ Not valid Base64" }); }
    try {
      setDPlain(dec(await rsaDecrypt(key, data)));
      setDRes({ ok: true, text: "✓ Decrypted with the private key. OAEP checks its padding, so a wrong key or changed data would have failed." });
    } catch {
      setDRes({ ok: false, text: "✗ Decryption failed: wrong private key, or the data was changed" });
    }
  }

  async function sign() {
    setSig("");
    let key: CryptoKey;
    try { key = await pssPrivate(priv); } catch { return setSignRes({ ok: false, text: BAD_PRIV }); }
    const bytes = enc(signMsg);
    setSig(toB64(await rsaSign(key, bytes)));
    setSignRes({ ok: true, text: `✓ Signed ${bytes.length} bytes with the private key.` });
  }

  async function verify(msg: string, sigB64: string) {
    let key: CryptoKey, s: Uint8Array<ArrayBuffer>;
    try { key = await pssPublic(pub); } catch { return setVRes({ ok: false, text: BAD_PUB }); }
    try { s = fromB64(sigB64); } catch { return setVRes({ ok: false, text: "✗ Signature is not valid Base64" }); }
    const ok = await rsaVerify(key, s, enc(msg));
    setVRes({
      ok,
      text: ok
        ? "✓ Valid signature: made by the owner of the private key, and the message is unchanged."
        : "✗ Invalid signature: the message or signature was changed, or it was signed with a different key.",
    });
  }

  const jumpTo = (id: string) => {
    const el = document.getElementById(id);
    el?.scrollIntoView({ behavior: "smooth", block: "center" });
    el?.focus({ preventScroll: true });
  };

  const n = enc(plain).length;

  return (
    <div className="space-y-6">
      <About>
        RSA (Rivest–Shamir–Adleman, 1977; PKCS #1 v2.2, RFC 8017) uses a key pair: anyone can encrypt with the <b>public key</b>, but
        only the owner of the <b>private key</b> can decrypt. Its security rests on how hard it is to factor a huge number. The same
        key pair works the other way round for <b>signatures</b>: only the private key can sign, and anyone with the public key can
        verify. Here: RSA-OAEP (encryption) and RSA-PSS (signatures), both with SHA-256, the paddings to use today. Java: java/rsa/Rsa.java
      </About>

      <Section n={1} title="Key pair">
        <div>
          <Label htmlFor="rsabits">Key size</Label>
          <Select id="rsabits" value={bits} onChange={(e) => setBits(e.target.value)}>
            <option value="2048">2048 bits (minimum today, max message 190 bytes)</option>
            <option value="3072">3072 bits (max message 318 bytes)</option>
            <option value="4096">4096 bits (max message 446 bytes, slow to generate)</option>
          </Select>
        </div>
        <Button disabled={busy} onClick={() => generate(+bits)}>{busy ? "Generating…" : "Generate key pair"}</Button>
        <div aria-live="polite"><Meta>{genMsg}</Meta></div>
        <div>
          <Label htmlFor="rsapub">Public key: share it, used to encrypt and to verify</Label>
          <TextArea id="rsapub" mono spellCheck={false} value={pub} onChange={(e) => setPub(e.target.value)} />
        </div>
        <div>
          <Label htmlFor="rsapriv">Private key: keep it secret, used to decrypt and to sign</Label>
          <TextArea id="rsapriv" mono spellCheck={false} value={priv} onChange={(e) => setPriv(e.target.value)} />
        </div>
        <Meta>PEM format, the same as Java. You can paste keys made by <code>java Rsa.java genkey</code>.</Meta>
      </Section>

      <Section n={2} title="Encrypt with the public key">
        <div>
          <Label htmlFor="rsaplain">Plaintext</Label>
          <TextArea id="rsaplain" placeholder="Type a short message" value={plain} onChange={(e) => setPlain(e.target.value)} />
        </div>
        <Meta bad={max !== null && n > max}>{max === null ? `${n} bytes` : `${n} / ${max} bytes`}</Meta>
        <Button onClick={encrypt}>Encrypt</Button>
        <Result r={encRes} />
        <div>
          <Label htmlFor="rsacipher">Encrypted (Base64)</Label>
          <OutputRow id="rsacipher" value={cipher}>
            <CopyButton text={cipher} />
            <Button onClick={async () => { setDCipher(cipher); await decrypt(cipher); jumpTo("rsadcipher"); }}>
              Decrypt this
            </Button>
          </OutputRow>
        </div>
        <Meta>OAEP adds randomness, so encrypting the same text twice gives different output. The output is always as long as the key (256 bytes for 2048 bits).</Meta>
      </Section>

      <Section n={3} title="Decrypt with the private key">
        <div>
          <Label htmlFor="rsadcipher">Encrypted (Base64)</Label>
          <TextArea id="rsadcipher" spellCheck={false} placeholder="Paste encrypted Base64 text"
            value={dCipher} onChange={(e) => setDCipher(e.target.value)} />
        </div>
        <Button onClick={() => decrypt(dCipher)}>Decrypt</Button>
        <Result r={dRes} />
        <div>
          <Label htmlFor="rsadplain">Decrypted text</Label>
          <OutputRow id="rsadplain" value={dPlain} plain />
        </div>
      </Section>

      <Section n={4} title="Sign with the private key">
        <Note>A signature proves who wrote a message (only the private key can make it) and that nobody changed it. The message is hashed with SHA-256 first, so any length works.</Note>
        <div>
          <Label htmlFor="rsasignmsg">Message</Label>
          <TextArea id="rsasignmsg" placeholder="Type the message to sign" value={signMsg} onChange={(e) => setSignMsg(e.target.value)} />
        </div>
        <Button onClick={sign}>Sign</Button>
        <Result r={signRes} />
        <div>
          <Label htmlFor="rsasig">Signature (Base64)</Label>
          <OutputRow id="rsasig" value={sig}>
            <CopyButton text={sig} />
            <Button onClick={async () => { setVMsg(signMsg); setVSig(sig); await verify(signMsg, sig); jumpTo("rsavmsg"); }}>
              Verify this
            </Button>
          </OutputRow>
        </div>
        <Meta>PSS adds a random salt, so signing the same message twice gives different signatures. Both verify.</Meta>
      </Section>

      <Section n={5} title="Verify with the public key">
        <div>
          <Label htmlFor="rsavmsg">Message</Label>
          <TextArea id="rsavmsg" placeholder="Paste the message" value={vMsg} onChange={(e) => setVMsg(e.target.value)} />
        </div>
        <div>
          <Label htmlFor="rsavsig">Signature (Base64)</Label>
          <TextArea id="rsavsig" spellCheck={false} placeholder="Paste the signature" value={vSig} onChange={(e) => setVSig(e.target.value)} />
        </div>
        <Button onClick={() => verify(vMsg, vSig)}>Verify</Button>
        <Result r={vRes} />
      </Section>

      <Section n={6} title="Self-checks">
        <Note>RSA-OAEP and RSA-PSS are randomized, so there are no fixed-output test vectors. Checks 1 and 8 use a ciphertext and a signature that java/rsa/Rsa.java made with a fixed test key, which proves this page and Java use the same format.</Note>
        <Note>{checks.summary}</Note>
        <ChecksTable results={checks.results} />
      </Section>

      <Warning>
        ⚠ RSA can only encrypt a small message (key bytes − 66). Real systems use it to encrypt a random AES key, and AES encrypts the
        data (&quot;hybrid encryption&quot;, as in TLS and PGP). Use OAEP, never raw RSA or PKCS #1 v1.5 encryption, and at least 2048
        bits. In real systems use separate key pairs for encrypting and signing; one pair is shared here only to keep the demo simple.
        Showing the private key on screen is for learning only.
      </Warning>
    </div>
  );
}
