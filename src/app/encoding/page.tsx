import type { Metadata } from "next";
import EncodingView from "@/components/EncodingView";

export const metadata: Metadata = {
  title: "Encoding · Study Cases",
  description: "Encode and decode Hex, Base64, Base64URL, URL encoding and HTML entities, and see why encoding is not encryption.",
};

export default function Page() {
  return <EncodingView />;
}
