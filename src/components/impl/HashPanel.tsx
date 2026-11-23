"use client";

import { useEffect, useState } from "react";
import { METHODS, byId, hashFormat, verifyHash, type HashMethod } from "@/lib/impl/hash";
import {
  About, Button, CopyButton, Label, Meta, Note, OutputRow, Pass, Result, type ResultState,
  Section, Table, TextArea, Input, Warning, useSelfChecks,
} from "./ui";

export default function HashPanel({ method }: { method: HashMethod["id"] }) {
  const m = byId(method);
  const [text, setText] = useState("abc");
  const [out, setOut] = useState("");
  const [vtext, setVtext] = useState("");
  const [vhash, setVhash] = useState("");
  const [vres, setVres] = useState<ResultState>(null);

  // Live hash as you type; `alive` ignores stale async results when the user types fast or switches tabs
  useEffect(() => {
    let alive = true;
    m.hash(text).then((h) => { if (alive) setOut(h); });
    return () => { alive = false; };
  }, [text, m]);

  // Verify runs on the button; editing either box clears the old result so it never shows a stale answer
  // No text: only check the hash format (an empty box means "no text", not the empty string)
  const verify = async () => setVres(vtext ? await verifyHash(vtext, vhash) : hashFormat(vhash));

  const { results, summary } = useSelfChecks(
    () => m.vectors.map(([input, expected]) => [input, async () => (await m.hash(input)) === expected]),
    method,
  );

  return (
    <div className="space-y-5">
      <About>{m.about}</About>

      <Section n={1} title="Hash text">
        <div>
          <Label htmlFor="text">Input</Label>
          <TextArea id="text" value={text} onChange={(e) => setText(e.target.value)} placeholder="Type or paste text, a paragraph is fine" />
        </div>
        <div>
          <Label htmlFor="out">{m.name} hash</Label>
          <OutputRow id="out" value={out}>
            <CopyButton text={out} />
          </OutputRow>
        </div>
        <Meta>{out && `${out.length} hex chars = ${m.bits} bits`}</Meta>
      </Section>

      <Section n={2} title="Verify">
        <Note>Paste a hash from anywhere and the text it should match. The text is hashed again and compared. The method is detected from the hash length, so {METHODS.map((x) => x.name).join(", ").replace(/, ([^,]*)$/, " or $1")} all work here. Leave the text empty to only check the hash type.</Note>
        <div>
          <Label htmlFor="vhash">Hash (paste from anywhere)</Label>
          <Input id="vhash" spellCheck={false} className="font-mono" value={vhash} placeholder="e.g. 900150983cd24fb0d6963f7d28e17f72"
            onChange={(e) => { setVhash(e.target.value); setVres(null); }} />
        </div>
        <div>
          <Label htmlFor="vtext">Text it should match</Label>
          <TextArea id="vtext" value={vtext} placeholder="e.g. abc (leave empty to only check the hash type)" onChange={(e) => { setVtext(e.target.value); setVres(null); }} />
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <Button onClick={verify} disabled={!vhash.trim()}>Verify</Button>
          {!vhash.trim() && <Note>Paste a hash first.</Note>}
        </div>
        <Result r={vres} />
      </Section>

      <Section n={3} title={`Standard test vectors (${m.source})`}>
        <Note>{summary}</Note>
        <Table
          head={["Input", "Expected", "Result"]}
          rows={m.vectors.map(([input, expected], i) => [
            <code key="i">{input.length > 80 ? `"a" × ${input.length.toLocaleString("en-US")}` : JSON.stringify(input)}</code>,
            <code key="e">{expected}</code>,
            <Pass key="p" ok={results[i]?.name === input ? results[i].ok : null} />,
          ])}
        />
      </Section>

      <Warning>{m.warning}</Warning>
    </div>
  );
}
