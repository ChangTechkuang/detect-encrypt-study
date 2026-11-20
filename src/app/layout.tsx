import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import LayoutSwitch from "@/components/LayoutSwitch";
import "./globals.css";

const geistSans = Geist({ variable: "--font-geist-sans", subsets: ["latin"] });
const geistMono = Geist_Mono({ variable: "--font-geist-mono", subsets: ["latin"] });

export const metadata: Metadata = {
  title: "Study Cases",
  description: "Hashing, symmetric and asymmetric methods, each explained in 5 short steps.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body className={`${geistSans.variable} ${geistMono.variable} font-sans antialiased`}>
        <div className="mx-auto max-w-5xl px-4 py-10 sm:px-6 sm:py-14">
          {/* Two layouts: Study (5-step docs) and Implement (live tools with self-checks) */}
          <LayoutSwitch />
          {children}
        </div>
      </body>
    </html>
  );
}
