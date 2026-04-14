"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { FormEvent, useState } from "react";

import { storeAuth } from "@/lib/auth";

const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000/api";

export default function RegisterPage() {
  const router = useRouter();
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSubmitting(true);
    setError("");

    try {
      const response = await fetch(`${API_BASE_URL}/auth/register/`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, email, password }),
      });
      const payload = await response.json();
      if (!response.ok) {
        const message =
          payload.email?.[0] ?? payload.username?.[0] ?? payload.password?.[0] ?? payload.detail ?? "註冊失敗。";
        throw new Error(message);
      }

      storeAuth(payload.tokens, payload.user);
      router.push("/");
    } catch (submitError) {
      setError(submitError instanceof Error ? submitError.message : "註冊失敗。");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <main className="mx-auto flex min-h-screen max-w-6xl items-center px-4 py-10 sm:px-6">
      <section className="grid w-full gap-6 lg:grid-cols-[1.05fr_0.95fr]">
        <div className="rounded-[2rem] border border-white/50 bg-[rgba(255,248,239,0.78)] p-8 shadow-[0_30px_90px_rgba(15,23,42,0.10)] backdrop-blur-xl">
          <p className="text-xs font-bold uppercase tracking-[0.35em] text-[var(--accent)]">WeakScan Register</p>
          <h1 className="mt-5 text-4xl font-black tracking-tight text-slate-950 sm:text-5xl">建立新帳號</h1>
          <p className="mt-4 max-w-xl text-base leading-7 text-slate-600">
            註冊後即可開始使用平台弱掃功能，系統會提供預設額度，讓你能立即提交網站或 API 掃描任務。
          </p>
        </div>

        <div className="rounded-[2rem] border border-slate-900/80 bg-[linear-gradient(180deg,#0f172a_0%,#111827_100%)] p-8 text-white shadow-[0_40px_100px_rgba(15,23,42,0.28)]">
          <h2 className="text-3xl font-black tracking-tight">使用者與 Email 註冊</h2>
          <form onSubmit={handleSubmit} className="mt-8 space-y-5">
            <AuthField label="使用者名稱">
              <input
                value={username}
                onChange={(event) => setUsername(event.target.value)}
                className="w-full rounded-[1.25rem] border border-white/10 bg-white/6 px-4 py-3 text-sm text-white outline-none placeholder:text-slate-500"
                placeholder="請輸入使用者名稱"
                required
              />
            </AuthField>
            <AuthField label="Email">
              <input
                type="email"
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                className="w-full rounded-[1.25rem] border border-white/10 bg-white/6 px-4 py-3 text-sm text-white outline-none placeholder:text-slate-500"
                placeholder="name@example.com"
                required
              />
            </AuthField>
            <AuthField label="密碼">
              <input
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                className="w-full rounded-[1.25rem] border border-white/10 bg-white/6 px-4 py-3 text-sm text-white outline-none placeholder:text-slate-500"
                placeholder="至少 8 個字元"
                required
              />
            </AuthField>
            <button
              type="submit"
              disabled={submitting}
              className="inline-flex w-full items-center justify-center rounded-full bg-[linear-gradient(135deg,#f97316_0%,#dc2626_100%)] px-6 py-3.5 text-sm font-bold text-white disabled:opacity-60"
            >
              {submitting ? "建立中..." : "建立帳號"}
            </button>
          </form>

          {error ? <p className="mt-5 text-sm text-red-300">{error}</p> : null}

          <p className="mt-8 text-sm text-slate-400">
            已經有帳號？{" "}
            <Link href="/login" className="font-semibold text-orange-300">
              前往登入
            </Link>
          </p>
        </div>
      </section>
    </main>
  );
}

function AuthField({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="block">
      <span className="mb-2 block text-sm font-semibold text-white">{label}</span>
      {children}
    </label>
  );
}
