"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { FormEvent, useState } from "react";

import { GoogleLoginButton } from "@/components/google-login-button";
import { AuthUser, storeAuth } from "@/lib/auth";

const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000/api";
const GOOGLE_CLIENT_ID = process.env.NEXT_PUBLIC_GOOGLE_CLIENT_ID ?? "";

type TokenPair = {
  access: string;
  refresh: string;
};

type GoogleLoginResponse = {
  tokens: TokenPair;
  user: AuthUser;
  detail?: string;
};

export default function LoginPage() {
  const router = useRouter();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  async function fetchProfile(access: string) {
    const response = await fetch(`${API_BASE_URL}/auth/me/`, {
      headers: { Authorization: `Bearer ${access}` },
    });
    const payload = (await readApiPayload(response)) as Partial<AuthUser> & { detail?: string };
    if (!response.ok) {
      throw new Error(payload.detail ?? "無法取得使用者資料");
    }
    return payload as AuthUser;
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSubmitting(true);
    setError("");

    try {
      const response = await fetch(`${API_BASE_URL}/auth/token/`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });
      const payload = (await readApiPayload(response)) as Partial<TokenPair> & { detail?: string };
      if (!response.ok) {
        throw new Error(payload.detail ?? "登入失敗");
      }

      if (!payload.access || !payload.refresh) {
        throw new Error("登入回應缺少 token。");
      }

      const user = await fetchProfile(payload.access);
      storeAuth({ access: payload.access, refresh: payload.refresh }, user);
      router.push("/");
    } catch (submitError) {
      setError(submitError instanceof Error ? submitError.message : "登入失敗");
    } finally {
      setSubmitting(false);
    }
  }

  async function handleGoogleLogin(credential: string) {
    setError("");
    try {
      const response = await fetch(`${API_BASE_URL}/auth/google/`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ credential }),
      });
      const payload = (await readApiPayload(response)) as GoogleLoginResponse;
      if (!response.ok) {
        throw new Error(payload.detail ?? "Google 登入失敗");
      }
      if (!payload.tokens?.access || !payload.tokens?.refresh || !payload.user) {
        throw new Error("Google 登入回應格式不完整。");
      }
      storeAuth(payload.tokens, payload.user);
      router.push("/");
    } catch (submitError) {
      setError(submitError instanceof Error ? submitError.message : "Google 登入失敗");
    }
  }

  return (
    <main className="mx-auto flex min-h-screen max-w-6xl items-center px-4 py-10 sm:px-6">
      <section className="grid w-full gap-6 lg:grid-cols-[1.1fr_0.9fr]">
        <div className="rounded-[2rem] border border-white/50 bg-[rgba(255,248,239,0.78)] p-8 shadow-[0_30px_90px_rgba(15,23,42,0.10)] backdrop-blur-xl">
          <p className="text-xs font-bold uppercase tracking-[0.35em] text-[var(--accent)]">WeakScan Login</p>
          <h1 className="mt-5 text-4xl font-black tracking-tight text-slate-950 sm:text-5xl">登入弱掃平台</h1>
          <p className="mt-4 max-w-xl text-base leading-7 text-slate-600">
            登入後即可提交掃描任務、查看 credit、下載 PDF 報告。支援帳號密碼與 Google 登入。
          </p>
          <div className="mt-8 rounded-[1.5rem] bg-slate-950 p-6 text-white">
            <p className="text-sm font-semibold uppercase tracking-[0.3em] text-orange-300">登入後可用</p>
            <ul className="mt-4 space-y-3 text-sm text-slate-200">
              <li>建立網站與 API 掃描任務</li>
              <li>查看任務狀態與風險摘要</li>
              <li>下載 PDF 弱掃報告</li>
            </ul>
          </div>
        </div>

        <div className="rounded-[2rem] border border-slate-900/80 bg-[linear-gradient(180deg,#0f172a_0%,#111827_100%)] p-8 text-white shadow-[0_40px_100px_rgba(15,23,42,0.28)]">
          <h2 className="text-3xl font-black tracking-tight">帳號登入</h2>
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
            <AuthField label="密碼">
              <input
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                className="w-full rounded-[1.25rem] border border-white/10 bg-white/6 px-4 py-3 text-sm text-white outline-none placeholder:text-slate-500"
                placeholder="請輸入密碼"
                required
              />
            </AuthField>
            <button
              type="submit"
              disabled={submitting}
              className="inline-flex w-full items-center justify-center rounded-full bg-[linear-gradient(135deg,#f97316_0%,#dc2626_100%)] px-6 py-3.5 text-sm font-bold text-white disabled:opacity-60"
            >
              {submitting ? "登入中..." : "登入"}
            </button>
          </form>

          <div className="my-6 flex items-center gap-4 text-xs uppercase tracking-[0.28em] text-slate-500">
            <div className="h-px flex-1 bg-white/10" />
            或
            <div className="h-px flex-1 bg-white/10" />
          </div>

          {GOOGLE_CLIENT_ID ? (
            <GoogleLoginButton clientId={GOOGLE_CLIENT_ID} onCredential={handleGoogleLogin} />
          ) : (
            <p className="text-sm text-slate-400">尚未設定 Google OAuth Client ID。</p>
          )}

          {error ? <p className="mt-5 text-sm text-red-300">{error}</p> : null}

          <p className="mt-8 text-sm text-slate-400">
            還沒有帳號？{" "}
            <Link href="/register" className="font-semibold text-orange-300">
              前往註冊
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

async function readApiPayload(response: Response) {
  const text = await response.text();

  try {
    return JSON.parse(text) as Record<string, any>;
  } catch {
    throw new Error(`後端回傳了非 JSON 內容，請檢查 API 狀態。HTTP ${response.status}`);
  }
}
