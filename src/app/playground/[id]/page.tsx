import type { Metadata } from "next";
import { notFound } from "next/navigation";
import ImplementView from "@/components/impl/ImplementView";
import { CASES, caseById } from "@/content";

export const generateStaticParams = () => CASES.map((c) => ({ id: c.id }));

type Props = { params: Promise<{ id: string }> };

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const c = caseById((await params).id);
  return c ? { title: `${c.name} · Playground · Study Cases`, description: `Run ${c.name} live in your browser.` } : {};
}

export default async function Page({ params }: Props) {
  const c = caseById((await params).id);
  if (!c) notFound();
  return <ImplementView id={c.id} />;
}
