import type { Metadata } from "next";
import DetectView from "@/components/DetectView";

export const metadata: Metadata = {
  title: "Detect · Study Cases",
  description: "Paste a hash, ciphertext or key and let Claude identify what it most likely is.",
};

export default function Page() {
  return <DetectView />;
}
