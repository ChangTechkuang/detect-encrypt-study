"use client";

import { useEffect, useRef, useState } from "react";
import { byId, verifyHash } from "@/lib/impl/hash";
import {
  About, Button, CopyButton, Label, Meta, Note, OutputRow, Pass, Result, type ResultState,
  Section, Table, TextArea, Input, Warning, useSelfChecks,
} from "./ui";

export default function HashPanel({ method }: { method: "md5" | "sha256" }) {
  const m = byId(method);
  const [text, setText] = useState("abc");
  const [out, setOut] = useState("");
  const [vtext, setVtext] = useState("");
  const [vhash, setVhash] = useState("");
  const [vres, setVres] = useState<ResultState>(null);
  const vtextRef = useRef<HTMLDivElement>(null);

  // Live hash as you type; `alive` ignores stale async results when the user types fast or switches tabs
  useEffect(() => {
    let alive = true;
    m.hash(text).then((h) => { if (alive) setOut(h); });
    return () => { alive = false; };
  }, [text, m]);

  useEffect(() => {
    let alive = true;
    verifyHash(vtext, vhash).then((r) => { if (alive) setVres(r); });
    return () => { alive = false; };
  }, [vtext, vhash]);

  // Fill Verify with the same text + its hash, so the user can then edit the text and see it fail
  async function sendVerify() {
    setVtext(text);
    setVhash(await m.hash(text));
    vtextRef.current?.scrollIntoView({ behavior: "smooth", block: "center" });
    vtextRef.current?.querySelector("textarea")?.focus({ preventScroll: true });
  }

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
            <Button onClick={sendVerify}>Verify this</Button>
          </OutputRow>
        </div>
        <Meta>{out && `${out.length} hex chars = ${m.bits} bits`}</Meta>
      </Section>

      <Section n={2} title="Verify">
        <Note>Verification hashes the input again and compares it with the stored hash. The method is detected from the hash length, so a hash from the MD5 or SHA-256 tab works here.</Note>
        <div ref={vtextRef}>
          <Label htmlFor="vtext">Input</Label>
          <TextArea id="vtext" value={vtext} onChange={(e) => setVtext(e.target.value)} placeholder="Paste the text or paragraph to check" />
        </div>
        <div>
          <Label htmlFor="vhash">Stored hash</Label>
          <Input id="vhash" spellCheck={false} value={vhash} onChange={(e) => setVhash(e.target.value)} />
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
