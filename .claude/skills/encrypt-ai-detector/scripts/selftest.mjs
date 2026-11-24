// Offline check (no Claude call): facts line, formatting and claude.exe lookup.
import assert from "node:assert/strict";
import { facts, findClaude, format } from "./ask.mjs";

const v = "dyjC2xjmP3+S3V0qVwjbdDtxfLl5jOZo";
assert.match(facts(v), /category=symmetric .*bytes=24/);
const out = format({ summary: "s", nextStep: "n", candidates: [{ type: "AES-CTR", family: "symmetric", confidence: "possible", reason: "r", studyId: "aes" }] }, v);
assert.match(out, /1\. AES-CTR \(symmetric, possible\): r/);
assert.match(out, /Calculated: 24 bytes, base64/);
console.log("ok; claude.exe:", findClaude() ?? "NOT FOUND");
