import { redirect } from "next/navigation";
import { CASES } from "@/content";

// /playground opens the first method
export default function Page() {
  redirect(`/playground/${CASES[0].id}`);
}
