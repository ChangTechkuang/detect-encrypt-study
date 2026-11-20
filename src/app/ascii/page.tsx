import type { Metadata } from "next";
import AsciiView from "@/components/AsciiView";

export const metadata: Metadata = {
  title: "ASCII Table · Study Cases",
  description: "Every ASCII character 0–127 with its decimal, hex and binary number, plus a text converter.",
};

export default function Page() {
  return <AsciiView />;
}
