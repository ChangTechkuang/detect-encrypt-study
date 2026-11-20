"use client";

import { useRef, useState } from "react";
import { BCRYPT_VECTORS, COSTS, DEFAULT_COST, bcryptHash, bcryptVerify, checkVector } from "@/lib/impl/bcrypt";
import {
  About, Button, CopyButton, Input, Label, Meta, Note, OutputRow, Pass, Result, type ResultState,
  Section, Select, Table, Warning, useSelfChecks,
} from "./ui";

export default function BcryptPanel() {
  const [pass, setPass] = useState("hunter2");
  const [cost, setCost] = useState(DEFAULT_COST);
  const [out, setOut] = useState("");
  const [meta, setMeta] = useState("");
  const [busy, setBusy] = useState(false);
  const [vpass, setVpass] = useState("");
  const [vhash, setVhash] = useState("");
  const [vres, setVres] = useState<ResultState>(null);
  const vpassRef = useRef<HTMLDivElement>(null);

  async function hash() {
    setBusy(true);
    const t0 = performance.now();
    const h = await bcryptHash(pass, cost); // new random salt every call
    setOut(h);
    setMeta(`${h.length} chars · cost ${cost} = ${(2 ** cost).toLocaleString("en-US")} rounds · took ${Math.round(performance.now() - t0)} ms. Click Hash again: different salt, different hash.`);
    setBusy(false);
    return h;
  }

  const verify = async (p: string, h: string) => setVres(await bcryptVerify(p, h));

  async function sendVerify() {
    const h = out || (await bcryptHash(pass, cost));
    if (!out) setOut(h);
    setVpass(pass);
    setVhash(h);
    await verify(pass, h);
    vpassRef.current?.scrollIntoView({ behavior: "smooth", block: "center" });
    vpassRef.current?.querySelector("input")?.focus({ preventScroll: true });
  }

  const { results } = useSelfChecks(() => BCRYPT_VECTORS.map((v) => [v[0], () => checkVector(v)]), "bcrypt");
  const done = results.length > 0 && results.every((r) => r.ok !== null);
  const passed = results.filter((r) => r.ok).length;

  return (
    <div className="space-y-5">
      <About>
        bcrypt is a hash made for passwords. It adds a random salt, so the same password gives a different hash every time, and it is deliberately slow (2<sup>cost</sup> rounds) to make guessing expensive. The salt and cost are stored inside the hash.
      </About>

      <Section n={1} title="Hash password">
        <div>
          <Label htmlFor="bpass">Password</Label>
          <Input id="bpass" value={pass} onChange={(e) => setPass(e.target.value)} />
        </div>
        <div>
          <Label htmlFor="bcost">Cost factor</Label>
          <Select id="bcost" value={cost} onChange={(e) => setCost(+e.target.value)}>
            {COSTS.map((c) => <option key={c} value={c}>{c}{c === DEFAULT_COST ? " (default)" : ""}</option>)}
          </Select>
        </div>
        <div><Button onClick={hash} disabled={busy}>{busy ? "Hashing…" : "Hash"}</Button></div>
        <div>
          <Label htmlFor="bout">bcrypt hash</Label>
          <OutputRow id="bout" value={out}>
            <CopyButton text={out} />
            <Button onClick={sendVerify}>Verify this</Button>
          </OutputRow>
        </div>
        <Meta>{meta}</Meta>
      </Section>

      <Section n={2} title="Verify">
        <Note>bcrypt reads the salt and cost from the stored hash, hashes the password again with them, and compares.</Note>
        <div ref={vpassRef}>
          <Label htmlFor="bvpass">Password</Label>
          <Input id="bvpass" value={vpass} onChange={(e) => setVpass(e.target.value)} />
        </div>
        <div>
          <Label htmlFor="bvhash">Stored hash</Label>
          <Input id="bvhash" spellCheck={false} value={vhash} onChange={(e) => setVhash(e.target.value)} />
        </div>
        <div><Button onClick={() => verify(vpass, vhash)}>Verify</Button></div>
        <Result r={vres} />
      </Section>

      <Section n={3} title="Standard test vectors (OpenBSD bcrypt test suite, fixed salt)">
        <Note>
          {done ? `${passed} / ${BCRYPT_VECTORS.length} passed: hash with fixed salt, verify, reject altered. Run live in your browser.` : "Running…"}
        </Note>
        <Table
          head={["Password", "Expected", "Result"]}
          rows={BCRYPT_VECTORS.map(([pw, , expected], i) => [
            <code key="p">{JSON.stringify(pw)}</code>,
            <code key="e">{expected}</code>,
            <Pass key="r" ok={results[i]?.ok ?? null} />,
          ])}
        />
      </Section>

      <Warning>Use bcrypt (or Argon2 / PBKDF2) for passwords, not MD5 or SHA-256. bcrypt only uses the first 72 bytes of the password. Pick the highest cost that is still fast enough for your login, around 10–12 today.</Warning>
    </div>
  );
}
