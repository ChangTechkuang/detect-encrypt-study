"use client";

// Shared panel for every symmetric method; texts and functions come from SYM_METHODS.
import { useEffect, useState } from "react";
import {
  About, Button, CopyButton, Input, Label, Meta, Note, OutputRow, Result, type ResultState,
  Section, Select, Table, Pass, TextArea, Warning, useSelfChecks,
} from "./ui";
import {
  SYM_METHODS, symConfig, parseKey, keyMessage, newKey, encryptText, decryptText, runVector, vectorName, type AesMode,
} from "@/lib/impl/symmetric";

type Id = "des" | "tripledes" | "aes" | "seed";

export default function SymPanel({ method }: { method: Id }) {
  return <Panel key={method} method={method} />; // fresh state (key, mode, outputs) per method
}

function Panel({ method }: { method: Id }) {
  const base = SYM_METHODS[method];
  const [mode, setMode] = useState<AesMode | undefined>(base.mode);
  const [keyBytes, setKeyBytes] = useState(base.keyBytes);
  const [key, setKey] = useState("");
  const [plain, setPlain] = useState("Hello, world!");
  const [cipher, setCipher] = useState("");
  const [dcipher, setDcipher] = useState("");
  const [dres, setDres] = useState<ResultState>(null);
  const [dplain, setDplain] = useState("");
  const m = symConfig(base, mode);

  // Deliberate: the random first key must be made after hydration, or server and browser HTML would differ
  // eslint-disable-next-line react-hooks/set-state-in-effect
  useEffect(() => setKey(newKey(base.keyBytes)), [base]);

  const keyOk = !!parseKey(key, keyBytes);
  const checks = useSelfChecks(() => m.vectors.map((v) => [vectorName(v), () => runVector(m, v)]), method + mode);

  async function encrypt() {
    const k = parseKey(key, keyBytes);
    if (k) setCipher(await encryptText(m, k, plain));
  }

  async function decrypt(b64 = dcipher) {
    setDplain("");
    const k = parseKey(key, keyBytes);
    if (!k) { setDres(null); return; }
    const r = await decryptText(m, k, b64);
    setDres(r);
    setDplain(r.plain);
  }

  // Mode change keeps the key: only the way blocks are chained changes
  function changeMode(v: AesMode) {
    setMode(v);
    setCipher(""); setDplain(""); setDcipher(""); setDres(null);
  }

  function changeKeySize(b: number) {
    setKeyBytes(b);
    setKey(newKey(b)); // new key of the chosen size
  }

  return (
    <div className="space-y-6">
      <About>{m.about + (m.modeAbout ? " " + m.modeAbout : "")}</About>

      <Section n={1} title={base.modes ? "Mode & key" : "Key"}>
        {base.modes && (
          <div>
            <Label htmlFor="sym-mode">Mode</Label>
            <Select id="sym-mode" value={mode} onChange={(e) => changeMode(e.target.value as AesMode)}>
              {(Object.keys(base.modes) as AesMode[]).map((name) => (
                <option key={name} value={name}>
                  {name + (name === "GCM" ? " (recommended)" : name === "ECB" ? " (insecure)" : "")}
                </option>
              ))}
            </Select>
          </div>
        )}
        {base.keySizes && (
          <div>
            <Label htmlFor="sym-keysize">Key size</Label>
            <Select id="sym-keysize" value={keyBytes} onChange={(e) => changeKeySize(+e.target.value)}>
              {base.keySizes.map((b) => <option key={b} value={b}>{`AES-${b * 8} (${b * 2} hex chars)`}</option>)}
            </Select>
          </div>
        )}
        <div>
          <Label htmlFor="sym-key">{`${keyBytes * 8}-bit key (${keyBytes * 2} hex chars)`}</Label>
          <div className="flex flex-wrap items-center gap-2">
            <Input id="sym-key" spellCheck={false} className="min-w-0 flex-[1_1_260px] font-mono text-sm"
              value={key} onChange={(e) => setKey(e.target.value)} />
            <Button onClick={() => setKey(newKey(keyBytes))}>Generate key</Button>
          </div>
        </div>
        {key && <Meta bad={!keyOk}>{keyMessage(keyOk, keyBytes)}</Meta>}
      </Section>

      <Section n={2} title="Encrypt">
        <div>
          <Label htmlFor="sym-plain">Plaintext</Label>
          <TextArea id="sym-plain" placeholder="Type or paste text to encrypt" value={plain} onChange={(e) => setPlain(e.target.value)} />
        </div>
        <Button onClick={encrypt}>Encrypt</Button>
        <div>
          <Label htmlFor="sym-cipher">{`Encrypted (Base64 of ${m.format})`}</Label>
          <OutputRow id="sym-cipher" value={cipher}>
            <CopyButton text={cipher} />
            <Button disabled={!cipher} onClick={async () => {
              setDcipher(cipher);
              await decrypt(cipher);
              const el = document.getElementById("sym-dcipher"); // TextArea takes no ref
              el?.scrollIntoView({ behavior: "smooth", block: "center" });
              el?.focus({ preventScroll: true });
            }}>Decrypt this</Button>
          </OutputRow>
        </div>
        <Meta>{m.ivNote}</Meta>
      </Section>

      <Section n={3} title="Decrypt">
        <Note>Uses the key from step 1.</Note>
        <div>
          <Label htmlFor="sym-dcipher">Encrypted (Base64)</Label>
          <TextArea id="sym-dcipher" spellCheck={false} placeholder="Paste encrypted Base64 text"
            value={dcipher} onChange={(e) => setDcipher(e.target.value)} />
        </div>
        <Button onClick={() => decrypt()}>Decrypt</Button>
        <Result r={dres} />
        <div>
          <Label htmlFor="sym-dplain">Decrypted text</Label>
          <OutputRow id="sym-dplain" value={dplain} plain />
        </div>
      </Section>

      <Section n={4} title={`Standard test vectors (${m.mode ? m.mode + ", " : ""}${m.source})`}>
        <Note>{checks.summary}</Note>
        <Table head={["Test case", "Expected ciphertext", "Result"]}
          rows={checks.results.map((r, i) => [r.name, <code key="c">{m.vectors[i]?.[4]}</code>, <Pass key="p" ok={r.ok} />])} />
      </Section>

      <Warning>{m.warning}</Warning>
    </div>
  );
}
