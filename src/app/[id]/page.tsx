import type { Metadata } from "next";
import { notFound } from "next/navigation";
import StudyCaseView from "@/components/StudyCaseView";
import { CASES, caseById } from "@/content";

export const generateStaticParams = () => CASES.map((c) => ({ id: c.id }));

type Props = { params: Promise<{ id: string }> };

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const c = caseById((await params).id);
  return c ? { title: `${c.name} · Study Cases`, description: c.tagline } : {};
}

export default async function Page({ params }: Props) {
  const c = caseById((await params).id);
  if (!c) notFound();
  const i = CASES.indexOf(c);
  return <StudyCaseView c={c} prev={CASES[i - 1]} next={CASES[i + 1]} />;
}
