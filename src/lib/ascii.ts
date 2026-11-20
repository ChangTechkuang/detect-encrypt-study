// ASCII (American Standard Code for Information Interchange): numbers 0–127 for letters, digits, symbols
// and invisible control codes. Plain data, no React, so it can be checked on its own.

export type Group = "control" | "symbol" | "digit" | "upper" | "lower";

// Short names of the invisible control codes 0–31, with a plain meaning
const CONTROL: [string, string][] = [
  ["NUL", "Null: nothing"], ["SOH", "Start of heading"], ["STX", "Start of text"], ["ETX", "End of text"],
  ["EOT", "End of transmission"], ["ENQ", "Enquiry"], ["ACK", "Acknowledge"], ["BEL", "Bell: makes a beep"],
  ["BS", "Backspace"], ["HT", "Tab"], ["LF", "New line (line feed)"], ["VT", "Vertical tab"],
  ["FF", "New page (form feed)"], ["CR", "Carriage return: back to line start"], ["SO", "Shift out"], ["SI", "Shift in"],
  ["DLE", "Data link escape"], ["DC1", "Device control 1"], ["DC2", "Device control 2"], ["DC3", "Device control 3"],
  ["DC4", "Device control 4"], ["NAK", "Negative acknowledge"], ["SYN", "Synchronous idle"], ["ETB", "End of block"],
  ["CAN", "Cancel"], ["EM", "End of medium"], ["SUB", "Substitute"], ["ESC", "Escape"],
  ["FS", "File separator"], ["GS", "Group separator"], ["RS", "Record separator"], ["US", "Unit separator"],
];

export type Row = { dec: number; hex: string; bin: string; char: string; name: string; group: Group };

const groupOf = (n: number): Group =>
  n < 32 || n === 127 ? "control" : n >= 48 && n <= 57 ? "digit" : n >= 65 && n <= 90 ? "upper" : n >= 97 && n <= 122 ? "lower" : "symbol";

const nameOf = (n: number, ch: string) => {
  if (n < 32) return CONTROL[n][1];
  if (n === 32) return "Space";
  if (n === 127) return "Delete";
  const g = groupOf(n);
  return g === "digit" ? `Digit ${ch}` : g === "upper" ? `Capital letter ${ch}` : g === "lower" ? `Small letter ${ch}` : "Symbol";
};

export const ROWS: Row[] = Array.from({ length: 128 }, (_, n) => {
  const ch = String.fromCharCode(n);
  return {
    dec: n,
    hex: n.toString(16).padStart(2, "0"),
    bin: n.toString(2).padStart(8, "0"),
    char: n < 32 ? CONTROL[n][0] : n === 32 ? "SP" : n === 127 ? "DEL" : ch,
    name: nameOf(n, ch),
    group: groupOf(n),
  };
});

export const GROUPS: { id: Group | "all"; name: string; range: string }[] = [
  { id: "all", name: "All", range: "0–127" },
  { id: "control", name: "Control (invisible)", range: "0–31, 127" },
  { id: "symbol", name: "Space & symbols", range: "32–47, 58–64, 91–96, 123–126" },
  { id: "digit", name: "Digits", range: "48–57" },
  { id: "upper", name: "Capital letters", range: "65–90" },
  { id: "lower", name: "Small letters", range: "97–122" },
];

/** Each character of the text with its bytes. Non-ASCII characters (e.g. Korean) take 2–4 UTF-8 bytes. */
export function explain(text: string) {
  return [...text].map((ch) => {
    const bytes = [...new TextEncoder().encode(ch)];
    return { ch, bytes, ascii: bytes.length === 1 && bytes[0] < 128 };
  });
}
