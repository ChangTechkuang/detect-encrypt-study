"use client";

import { useMemo, useState } from "react";
import { ENCODINGS, byId, guessEncoding, type EncodingId } from "@/lib/encoding";
import { CopyButton, Label, Note, OutputRow, Section, Select, Table, TextArea } from "./impl/ui";

export default function EncodingView() {
  const [text, setText] = useState("Hello world & <tags> 한글?");
  const [encoded, setEncoded] = useState("SGVsbG8gd29ybGQ=");
  const [pick, setPick] = useState<EncodingId | "auto">("auto");

  const decoded = useMemo(() => {
    const id = pick === "auto" ? guessEncoding(encoded) : pick;
    if (!encoded.trim()) return null;
    if (!id) return { ok: false, text: "Can't tell which encoding this is. Pick one from the list.", id };
    try { return { ok: true, text: byId(id).decode(encoded.trim()), id }; }
    catch (e) { return { ok: false, text: (e as Error).message, id }; }
  }, [encoded, pick]);

  return (
    <main style={{ "--accent": "var(--info)" } as React.CSSProperties}>
      <header>
        <p className="text-xs font-semibold uppercase tracking-[0.14em] text-muted">data-encrypt-method · encoding</p>
        <h1 className="mt-3 text-4xl font-semibold tracking-tight sm:text-5xl">Encoding</h1>
        <p className="mt-4 max-w-2xl text-lg text-muted">
          Encoding changes how data is <em>written</em>, so it can travel safely through text, URLs or web pages.
          It is not security: there is no key, and anyone can turn it back.
        </p>
      </header>

      <div className="mt-8 grid gap-5">
        <Section n={1} title="Encode: text in, every encoding out">
          <Label htmlFor="enc-text">Text</Label>
          <TextArea id="enc-text" value={text} onChange={(e) => setText(e.target.value)} className="min-h-20" />
          <div className="grid gap-4">
            {ENCODINGS.map((e) => {
              const value = e.encode(text);
              return (
                <div key={e.id}>
                  <p className="mb-1.5 text-sm"><span className="font-semibold">{e.name}</span> <span className="text-muted">· looks like: {e.looks}</span></p>
                  <OutputRow value={value}><CopyButton text={value} /></OutputRow>
                  <p className="mt-1 text-[13px] text-muted">Used for: {e.use}</p>
                </div>
              );
            })}
          </div>
        </Section>

        <Section n={2} title="Decode: encoded in, text out">
          <Label htmlFor="enc-in">Encoded text</Label>
          <TextArea id="enc-in" mono value={encoded} onChange={(e) => setEncoded(e.target.value)} className="min-h-20" />
          <div className="max-w-xs">
            <Label htmlFor="enc-pick">Encoding</Label>
            <Select id="enc-pick" value={pick} onChange={(e) => setPick(e.target.value as EncodingId | "auto")}>
              <option value="auto">Auto-detect</option>
              {ENCODINGS.map((e) => <option key={e.id} value={e.id}>{e.name}</option>)}
            </Select>
          </div>
          {decoded && (
            <>
              <p className={`font-medium ${decoded.ok ? "text-ok" : "text-bad"}`}>
                {decoded.ok ? `✓ Decoded as ${byId(decoded.id!).name}` : `✗ ${decoded.text}`}
              </p>
              {decoded.ok && <OutputRow value={decoded.text} plain><CopyButton text={decoded.text} /></OutputRow>}
            </>
          )}
          <Note>Auto-detect is a guess from the characters: a short word like &quot;cafe&quot; is valid hex and valid Base64 at the same time.</Note>
        </Section>

        <Section n={3} title="Encoding is not encryption">
          <Table head={["Family", "Get the original back?", "Needs a secret?", "Purpose"]} rows={[
            ["Encoding (Base64, URL…)", "Yes, anyone", "No", "Write data safely for a channel"],
            ["Hashing (MD5, SHA-256)", "Never", "No", "Make a fingerprint"],
            ["Symmetric (AES, SEED)", "Yes, with the key", "One shared key", "Keep data secret"],
            ["Asymmetric (RSA)", "Yes, with the private key", "A key pair", "Secret messages and signatures"],
          ]} />
          <Note>They often appear together: this project encrypts with AES first (the security), then writes the result in Base64 (just packaging).</Note>
        </Section>
      </div>
    </main>
  );
}
