import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "WeakScan 弱掃平台",
  description: "網站與 API 弱點掃描平台",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="zh-Hant">
      <body>{children}</body>
    </html>
  );
}
