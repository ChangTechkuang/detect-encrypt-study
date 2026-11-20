"use client";

// 공동인증서 (Korean NPKI certificate): RSA key pairs + a SEED-locked private key. Logic in lib/impl/npki.ts.
import { useEffect, useRef, useState } from "react";
import { enc, toB64, fromB64, toHex } from "@/lib/bytes";
import { npki, OID, gdChecks } from "@/lib/impl/npki";
import {
  Section, About, Note, Warning, Label, TextArea, Input, Button, CopyButton, OutputRow, Meta, Result, Table, useSelfChecks, ChecksTable,
  type ResultState,
} from "./ui";

const fmt = (d: Date) => d.toISOString().replace("T", " ").slice(0, 19) + " UTC";
const cell = (b: string) => <span className={b.startsWith("✓") ? "text-ok" : b.startsWith("✗") ? "text-bad" : ""}>{b}</span>;

export default function GongdongPanel() {
  const [name, setName] = useState("홍길동");
  const [pw, setPw] = useState("test1234!");
  const [issuing, setIssuing] = useState(false);
  const [issueMsg, setIssueMsg] = useState("");
  const [ca, setCa] = useState("");
  const [cert, setCert] = useState("");
  const [key, setKey] = useState("");
  const [openPw, setOpenPw] = useState("test1234!");
  const [openRes, setOpenRes] = useState<ResultState>(null);
  const [info, setInfo] = useState<[string, string][]>([]);
  const [gdKey, setGdKey] = useState<Uint8Array<ArrayBuffer> | null>(null); // unlocked private key (PKCS #8) from step 2
  const [msg, setMsg] = useState("I agree to the contract");
  const [signRes, setSignRes] = useState<ResultState>(null);
  const [sig, setSig] = useState("");
  const [vmsg, setVmsg] = useState("");
  const [vsig, setVsig] = useState("");
  const [vres, setVres] = useState<ResultState>(null);
  const issued = useRef(false);

  const checks = useSelfChecks(gdChecks, "gd");

  const files = () => ({ caCert: fromB64(ca), signCert: fromB64(cert), signPri: fromB64(key) });

  async function issue() {
    const n = name.trim() || "홍길동";
    if (!pw) { setIssueMsg("✗ Choose a password first."); return; }
    setIssuing(true);
    const t0 = performance.now(), s = await npki.issueSet(n, pw);
    setCa(toB64(s.caCert)); setCert(toB64(s.signCert)); setKey(toB64(s.signPri));
    setIssueMsg(`✓ New CA key, your RSA-2048 key pair, certificate and locked private key, took ${Math.round(performance.now() - t0)} ms. Now open it with the password.`);
    setOpenPw(pw);
    setGdKey(null);
    setSig(""); setVsig("");
    setOpenRes(null); setSignRes(null); setVres(null); setInfo([]);
    setIssuing(false);
  }

  // Issue a test set once, like the source did when the tab opened.
  useEffect(() => {
    if (issued.current) return;
    issued.current = true;
    issue();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function open() {
    setGdKey(null); setInfo([]);
    let f, c;
    try { f = files(); c = npki.parseCert(f.signCert); npki.parseCert(f.caCert); npki.keyInfo(f.signPri); }
    catch { setOpenRes({ ok: false, text: "✗ The three files are not valid Base64 certificate files. Issue a set in step 1." }); return; }
    const k = npki.keyInfo(f.signPri);
    const rows: [string, string][] = [
      ["Subject (holder)", c.subject], ["Issuer (CA)", c.issuer], ["Serial number", c.serial],
      ["Valid", `${fmt(c.notBefore)} → ${fmt(c.notAfter)}`],
      ["Signature algorithm", c.sigAlg === OID.sha256rsa ? "sha256WithRSAEncryption" : c.sigAlg],
      ["Private key locked with", k.oid === OID.seedSha1 ? `SEED-CBC, key from PBKDF1-SHA1 (OID ${k.oid})` : k.oid],
      ["Salt / rounds", `${toHex(k.salt)} / ${k.iter}`],
    ];
    let o;
    try { o = await npki.open(f, openPw); }
    catch { rows.push(["Password", "✗ wrong"]); }
    if (o) rows.push(["Password", "✓ correct"], ["Private key matches certificate", o.keyMatches ? "✓ yes" : "✗ no"],
      ["Certificate signed by the CA", o.signedByCA ? "✓ yes" : "✗ no"], ["In date", o.inDate ? "✓ yes" : "✗ no"]);
    setInfo(rows);
    if (!o) { setOpenRes({ ok: false, text: "✗ Wrong password: SEED decryption gave invalid padding or no valid key. (Real software locks the certificate after 5 wrong tries.)" }); return; }
    const ok = o.keyMatches && o.signedByCA && o.inDate;
    if (ok) setGdKey(o.pkcs8);
    setOpenRes({ ok, text: ok ? "✓ Certificate opened. The private key is unlocked in memory, ready to sign." : "✗ Opened, but a check failed: do not trust this certificate." });
  }

  async function sign() {
    setSig("");
    if (!gdKey) { setSignRes({ ok: false, text: "✗ Open the certificate with its password first (step 2)." }); return; }
    const bytes = enc(msg);
    setSig(toB64(await npki.signBytes(gdKey, bytes)));
    setSignRes({ ok: true, text: `✓ Signed ${bytes.length} bytes with your private key.` });
  }

  async function verify(m: string, s: string) {
    let f, c, a, sg;
    try { f = files(); c = npki.parseCert(f.signCert); a = npki.parseCert(f.caCert); } catch { setVres({ ok: false, text: "✗ No valid caCert.der / signCert.der in step 1" }); return; }
    try { sg = fromB64(s); } catch { setVres({ ok: false, text: "✗ Signature is not valid Base64" }); return; }
    const byCA = await npki.verifyBytes(a.spki, c.sig, c.tbs);
    const ok = await npki.verifyBytes(c.spki, sg, enc(m));
    setVres({
      ok: ok && byCA, text: !byCA ? "✗ The certificate is not signed by the CA: do not trust it."
        : ok ? `✓ Valid signature by ${c.subject.split(", ")[0].slice(3)}: the message is unchanged, and the CA vouches for the certificate.`
        : "✗ Invalid signature: the message or signature was changed, or it was signed with a different certificate.",
    });
  }

  async function verifyThis() {
    setVmsg(msg); setVsig(sig);
    await verify(msg, sig);
    const el = document.getElementById("gdvmsg"); // TextArea takes no ref
    el?.scrollIntoView({ behavior: "smooth", block: "center" });
    el?.focus({ preventScroll: true });
  }

  return (
    <div className="space-y-6">
      <About>
        공동인증서 (joint certificate, called 공인인증서 until the Electronic Signature Act changed on 10 December 2020) is Korea&apos;s NPKI certificate for banking, 홈택스 and government sites. It puts the RSA and SEED tabs together: a CA signs your name and <b>RSA-2048 public key</b> into an X.509 certificate (<code>signCert.der</code>), and your private key is stored in <code>signPri.key</code>, encrypted with <b>SEED-CBC</b> under a key made from your certificate password. To sign, the program unlocks the private key with your password and signs with SHA-256 + RSA. Java: java/gongdong/Gongdong.java
      </About>
      <Note>
        <b>Symmetric or asymmetric? Asymmetric.</b> Signing and verifying (steps 3–4) and the CA&apos;s signature use RSA key pairs: your private key signs, and the bank or 홈택스 verifies with the public key in signCert.der, so it can check your signatures but never make one. SEED (step 2) is the only symmetric part: one password-made key locks and unlocks signPri.key on your own PC, and the password never leaves it.<br />
        password —<i>SEED decrypt (symmetric)</i>→ RSA private key —<i>RSA sign (asymmetric)</i>→ signature —<i>RSA verify with the public key (asymmetric)</i>→ valid / invalid
      </Note>

      <Section n={1} title="Issue a test certificate (발급)">
        <Note>A made-up &quot;TestCA&quot; issues the set. On a Korean PC the real files sit in <code>NPKI/&lt;CA&gt;/USER/&lt;your name&gt;/</code>; the CA certificate is built into the banking software.</Note>
        <div>
          <Label htmlFor="gdname">Holder name</Label>
          <Input id="gdname" type="text" value={name} onChange={(e) => setName(e.target.value)} />
        </div>
        <div>
          <Label htmlFor="gdpw">Certificate password</Label>
          <Input id="gdpw" type="text" spellCheck={false} value={pw} onChange={(e) => setPw(e.target.value)} />
        </div>
        <Button disabled={issuing} onClick={issue}>{issuing ? "Issuing…" : "Issue certificate"}</Button>
        <Meta bad={issueMsg.startsWith("✗")}>{issueMsg}</Meta>
        <div>
          <Label htmlFor="gdca">caCert.der: the CA&apos;s certificate (Base64)</Label>
          <TextArea id="gdca" mono spellCheck={false} value={ca} onChange={(e) => setCa(e.target.value)} />
        </div>
        <div>
          <Label htmlFor="gdcert">signCert.der: your certificate, public (Base64)</Label>
          <TextArea id="gdcert" mono spellCheck={false} value={cert} onChange={(e) => setCert(e.target.value)} />
        </div>
        <div>
          <Label htmlFor="gdkey">signPri.key: your private key, locked with the password (Base64)</Label>
          <TextArea id="gdkey" mono spellCheck={false} value={key} onChange={(e) => setKey(e.target.value)} />
        </div>
        <Meta>Same file formats as Java. You can paste files made by <code>java Gongdong.java issue</code> (Base64 of each file).</Meta>
      </Section>

      <Section n={2} title="Open with the password (인증서 선택 + 암호 입력)">
        <Note>This is what happens when you pick your certificate and type its password: password + salt → SHA-1 2048 times (PBKDF1) → SEED key and IV → decrypt signPri.key. Then the program checks the key belongs to the certificate, and the certificate was signed by the CA and is in date.</Note>
        <div>
          <Label htmlFor="gdopenpw">Password</Label>
          <Input id="gdopenpw" type="password" value={openPw} onChange={(e) => setOpenPw(e.target.value)} />
        </div>
        <Button onClick={open}>Open</Button>
        <Result r={openRes} />
        {info.length > 0 && <Table rows={info.map(([a, b]) => [<span key="a" className="text-muted">{a}</span>, cell(b)])} />}
      </Section>

      <Section n={3} title="Sign (전자서명)">
        <Note>Signs with the private key unlocked by the password in step 2: SHA-256 + RSA PKCS #1 v1.5, the scheme Korean certificates use. Real services wrap the signature in a PKCS #7 / CMS envelope together with the certificate.</Note>
        <div>
          <Label htmlFor="gdmsg">Message</Label>
          <TextArea id="gdmsg" placeholder="Type the message to sign" value={msg} onChange={(e) => setMsg(e.target.value)} />
        </div>
        <Button onClick={sign}>Sign</Button>
        <Result r={signRes} />
        <div>
          <Label htmlFor="gdsig">Signature (Base64)</Label>
          <OutputRow id="gdsig" value={sig}>
            <CopyButton text={sig} />
            <Button disabled={!sig} onClick={verifyThis}>Verify this</Button>
          </OutputRow>
        </div>
        <Meta>PKCS #1 v1.5 has no random salt, so signing the same message twice gives the same signature.</Meta>
      </Section>

      <Section n={4} title="Verify with the certificate">
        <Note>The receiver (a bank, 홈택스) needs no password: it checks the signature with the public key inside signCert.der, and checks that certificate against the CA.</Note>
        <div>
          <Label htmlFor="gdvmsg">Message</Label>
          <TextArea id="gdvmsg" placeholder="Paste the message" value={vmsg} onChange={(e) => setVmsg(e.target.value)} />
        </div>
        <div>
          <Label htmlFor="gdvsig">Signature (Base64)</Label>
          <TextArea id="gdvsig" spellCheck={false} placeholder="Paste the signature" value={vsig} onChange={(e) => setVsig(e.target.value)} />
        </div>
        <Button onClick={() => verify(vmsg, vsig)}>Verify</Button>
        <Result r={vres} />
      </Section>

      <Section n={5} title="Self-checks">
        <Note>Two fixed certificate sets (password test1234!) are built in: one made by java/gongdong/Gongdong.java and one made by this page&apos;s code. Java opens both too, which proves the page and Java use the same file formats.</Note>
        <Note>{checks.summary}</Note>
        <ChecksTable results={checks.results} />
      </Section>

      <Warning>⚠ Everything here is test data from a made-up CA. Never type a real certificate password or paste a real signPri.key into a web page. Simplified: real signPri.key files also hold a random number used for identity checks (본인확인), newer ones may use PBKDF2 instead of PBKDF1, and real sets add kmCert.der / kmPri.key for encryption.</Warning>
    </div>
  );
}
