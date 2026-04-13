"use client";

import Link from "next/link";
import { FormEvent, useEffect, useState } from "react";

import { AuthUser, clearAuth, getStoredAccessToken, getStoredUser } from "@/lib/auth";

type ScanJob = {
  id: number;
  project_name: string;
  scan_type: "web" | "api";
  target_url: string;
  status: "pending" | "running" | "completed" | "failed";
  result_summary: {
    issue_count?: number;
    critical_count?: number;
    high_count?: number;
    medium_count?: number;
    low_count?: number;
  };
  error_message: string;
  report_file: string | null;
};

const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000/api";

const capabilityCards = [
  {
    title: "攻擊面盤點",
    description: "探測常見 API 路徑、公開文件、robots.txt、sitemap.xml 與外露端點。",
  },
  {
    title: "基礎錯誤設定檢查",
    description: "檢查安全標頭、萬用 CORS、敏感檔案與常見部署外洩風險。",
  },
  {
    title: "非同步執行",
    description: "將掃描排入 Celery worker 佇列，避免 API 因長任務而卡住。",
  },
];

export default function HomePage() {
  const [token, setToken] = useState("");
  const [manualToken, setManualToken] = useState("");
  const [projectName, setProjectName] = useState("");
  const [targetUrl, setTargetUrl] = useState("");
  const [scanType, setScanType] = useState<"web" | "api">("web");
  const [job, setJob] = useState<ScanJob | null>(null);
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [user, setUser] = useState<AuthUser | null>(null);

  useEffect(() => {
    const storedToken = getStoredAccessToken();
    setToken(storedToken);
    setManualToken(storedToken);
    setUser(getStoredUser());
  }, []);

  useEffect(() => {
    if (!job || !token || !["pending", "running"].includes(job.status)) {
      return;
    }

    const timer = window.setInterval(async () => {
      const response = await fetch(`${API_BASE_URL}/scans/${job.id}/`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!response.ok) {
        return;
      }
      const nextJob = (await response.json()) as ScanJob;
      setJob(nextJob);
    }, 4000);

    return () => window.clearInterval(timer);
  }, [job, token]);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    const activeToken = manualToken.trim() || token;
    if (!activeToken) {
      setError("請先登入，或在進階設定中手動填入 JWT 後再建立掃描任務。");
      return;
    }

    setSubmitting(true);
    setError("");

    try {
      const resolvedProjectName = projectName.trim() || deriveProjectName(targetUrl);
      const response = await fetch(`${API_BASE_URL}/scans/`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${activeToken}`,
        },
        body: JSON.stringify({
          project_name: resolvedProjectName,
          scan_type: scanType,
          target_url: targetUrl,
        }),
      });

      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload.detail ?? "掃描任務建立失敗");
      }

      setJob(payload as ScanJob);
    } catch (submitError) {
      setError(submitError instanceof Error ? submitError.message : "發生未知錯誤");
    } finally {
      setSubmitting(false);
    }
  }

  const statusTone = getStatusTone(job?.status);
  const canSubmit = Boolean(manualToken.trim() || token);

  return (
    <main className="relative overflow-hidden px-4 py-6 sm:px-6 lg:px-10">
      <div className="absolute inset-x-0 top-0 -z-10 h-[28rem] bg-[radial-gradient(circle_at_top,rgba(242,104,33,0.22),transparent_42%)]" />
      <div className="absolute right-[-8rem] top-28 -z-10 h-72 w-72 rounded-full bg-[rgba(17,24,39,0.08)] blur-3xl" />
      <div className="absolute left-[-6rem] top-56 -z-10 h-80 w-80 rounded-full bg-[rgba(190,24,93,0.10)] blur-3xl" />

      <div className="mx-auto flex min-h-screen max-w-7xl flex-col gap-6">
        <nav className="flex items-center justify-between rounded-[1.5rem] border border-white/40 bg-white/50 px-5 py-4 backdrop-blur">
          <div>
            <p className="text-sm font-bold uppercase tracking-[0.3em] text-[var(--accent)]">WeakScan</p>
            <p className="text-sm text-slate-600">網站與 API 弱掃平台</p>
          </div>
          <div className="flex items-center gap-3 text-sm">
            {user ? (
              <>
                <span className="rounded-full bg-slate-950 px-4 py-2 font-semibold text-white">
                  {user.username} / {user.credits} credits
                </span>
                <button
                  type="button"
                  onClick={() => {
                    clearAuth();
                    setToken("");
                    setManualToken("");
                    setUser(null);
                  }}
                  className="rounded-full border border-slate-300 px-4 py-2 font-semibold text-slate-900"
                >
                  登出
                </button>
              </>
            ) : (
              <>
                <Link href="/login" className="rounded-full border border-slate-300 px-4 py-2 font-semibold text-slate-900">
                  登入
                </Link>
                <Link href="/register" className="rounded-full bg-slate-950 px-4 py-2 font-semibold text-white">
                  註冊
                </Link>
              </>
            )}
          </div>
        </nav>

        <header className="grid gap-6 lg:grid-cols-[1.15fr_0.85fr]">
          <section className="rounded-[2rem] border border-white/55 bg-[rgba(255,248,239,0.78)] p-7 shadow-[0_30px_90px_rgba(15,23,42,0.10)] backdrop-blur-xl sm:p-9">
            <div className="inline-flex items-center gap-3 rounded-full border border-black/10 bg-white/70 px-4 py-2 text-xs font-bold uppercase tracking-[0.35em] text-[var(--accent-strong)]">
              WeakScan 弱掃控制台
            </div>
            <h1 className="mt-6 max-w-4xl text-4xl font-black leading-none tracking-[-0.04em] text-slate-950 sm:text-6xl">
              用更接近實戰操作的介面，遠端掃描網站與 API 的弱點風險。
            </h1>
            <p className="mt-5 max-w-2xl text-base leading-7 text-slate-600 sm:text-lg">
              輸入目標網址後，系統會在後端非同步執行探測，回傳狀態、風險摘要與報告，不讓 API 被長時間任務拖慢。
            </p>

            <div className="mt-8 grid gap-3 sm:grid-cols-3">
              <HeroMetric label="執行模式" value="Celery 佇列" />
              <HeroMetric label="掃描類型" value="網站 + API" />
              <HeroMetric label="報告輸出" value="PDF 匯出" />
            </div>
          </section>

          <section className="rounded-[2rem] border border-slate-800 bg-[#0d1320] p-7 text-white shadow-[0_30px_90px_rgba(15,23,42,0.22)] sm:p-8">
            <div className="flex items-start justify-between gap-4">
              <div>
                <p className="text-xs font-semibold uppercase tracking-[0.32em] text-orange-300">即時狀態</p>
                <h2 className="mt-3 text-2xl font-bold">任務總覽</h2>
              </div>
              <span className={`rounded-full px-4 py-2 text-xs font-semibold uppercase tracking-[0.2em] ${statusTone.badge}`}>
                {job ? getStatusLabel(job.status) : "閒置"}
              </span>
            </div>

            <div className="mt-8 space-y-4">
              <div className="rounded-[1.5rem] border border-white/10 bg-white/5 p-5">
                <div className="flex items-center justify-between text-sm text-slate-300">
                  <span>目前目標</span>
                  <span>{job?.scan_type === "api" ? "API" : "網站"}</span>
                </div>
                <p className="mt-3 break-all text-lg font-semibold text-white">
                  {job?.target_url ?? "目前尚未排入目標"}
                </p>
                <p className="mt-2 text-sm text-slate-400">
                  {job ? `目前正在追蹤 ${job.project_name} 這筆掃描任務。` : "送出網址後，系統就會開始非同步探測。"}
                </p>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <StatusMetric label="問題數" value={job?.result_summary?.issue_count ?? 0} tone="neutral" />
                <StatusMetric label="嚴重" value={job?.result_summary?.critical_count ?? 0} tone="critical" />
                <StatusMetric label="高風險" value={job?.result_summary?.high_count ?? 0} tone="high" />
                <StatusMetric label="中風險" value={job?.result_summary?.medium_count ?? 0} tone="medium" />
              </div>
            </div>
          </section>
        </header>

        <section className="grid gap-4 lg:grid-cols-3">
          {capabilityCards.map((card) => (
            <article
              key={card.title}
              className="rounded-[1.75rem] border border-white/50 bg-white/65 p-6 shadow-[0_22px_60px_rgba(15,23,42,0.08)] backdrop-blur"
            >
              <p className="text-sm font-bold uppercase tracking-[0.25em] text-[var(--accent)]">{card.title}</p>
              <p className="mt-3 text-sm leading-6 text-slate-600">{card.description}</p>
            </article>
          ))}
        </section>

        <section className="grid gap-6 lg:grid-cols-[0.95fr_1.05fr]">
          <form
            onSubmit={handleSubmit}
            className="rounded-[2rem] border border-slate-900/80 bg-[linear-gradient(180deg,#0f172a_0%,#111827_100%)] p-7 text-white shadow-[0_40px_100px_rgba(15,23,42,0.28)] sm:p-8"
          >
            <div className="flex items-start justify-between gap-4">
              <div>
                <p className="text-xs font-semibold uppercase tracking-[0.3em] text-orange-300">建立任務</p>
                <h2 className="mt-3 text-3xl font-black tracking-tight">送出新的掃描任務</h2>
              </div>
              <div className="rounded-2xl border border-white/10 bg-white/5 px-4 py-3 text-right">
                <p className="text-[10px] uppercase tracking-[0.32em] text-slate-400">執行方式</p>
                <p className="mt-1 text-sm font-semibold text-white">非同步 Worker</p>
              </div>
            </div>

            <div className="mt-8 space-y-5">
              {user ? (
                <div className="rounded-[1.35rem] border border-emerald-400/20 bg-emerald-500/10 px-4 py-4 text-sm text-emerald-100">
                  已登入為 <span className="font-semibold">{user.username}</span>，系統會自動使用你的登入權杖送出掃描任務。
                </div>
              ) : (
                <div className="rounded-[1.35rem] border border-amber-300/20 bg-amber-500/10 px-4 py-4 text-sm text-amber-100">
                  你尚未登入。請先前往{" "}
                  <Link href="/login" className="font-semibold text-amber-200 underline">
                    登入頁
                  </Link>{" "}
                  取得權限後再建立掃描任務。
                </div>
              )}

              <details className="rounded-[1.35rem] border border-white/10 bg-white/5 px-4 py-4">
                <summary className="cursor-pointer list-none text-sm font-semibold text-white">進階設定</summary>
                <p className="mt-3 text-sm text-slate-400">
                  如需手動覆蓋登入中的權杖，可在這裡貼上 JWT。一般情況下不需要填寫。
                </p>
                <div className="mt-4">
                  <Field label="JWT 存取權杖" hint="非必填，未填時會自動使用目前登入權杖。">
                    <textarea
                      value={manualToken}
                      onChange={(event) => setManualToken(event.target.value)}
                      className="dark-field min-h-28 w-full rounded-[1.35rem] border border-white/10 px-4 py-3 text-sm text-white outline-none transition placeholder:text-slate-500 focus:border-orange-300/70"
                      placeholder="可留白。只有需要手動覆蓋時才貼上 Bearer Token"
                    />
                  </Field>
                </div>
              </details>

              <div className="grid gap-5 md:grid-cols-2">
                <Field label="專案名稱" hint="可不填，系統會自動用網址主機名帶入。">
                  <input
                    value={projectName}
                    onChange={(event) => setProjectName(event.target.value)}
                    className="dark-field w-full rounded-[1.35rem] border border-white/10 px-4 py-3 text-sm text-white outline-none transition placeholder:text-slate-500 focus:border-orange-300/70"
                    placeholder="例如：客戶主站"
                  />
                </Field>

                <Field label="掃描類型" hint="選擇網站或 API 探測模式。">
                  <select
                    value={scanType}
                    onChange={(event) => setScanType(event.target.value as "web" | "api")}
                    className="dark-field w-full rounded-[1.35rem] border border-white/10 px-4 py-3 text-sm text-white outline-none transition focus:border-orange-300/70"
                  >
                    <option value="web">網站掃描</option>
                    <option value="api">API 掃描</option>
                  </select>
                </Field>
              </div>

              <Field label="目標網址" hint="後端 worker 會直接對這個網址進行探測。">
                <input
                  type="url"
                  value={targetUrl}
                  onChange={(event) => setTargetUrl(event.target.value)}
                  className="dark-field w-full rounded-[1.35rem] border border-white/10 px-4 py-3 text-sm text-white outline-none transition placeholder:text-slate-500 focus:border-orange-300/70"
                  placeholder="https://example.com"
                  required
                />
              </Field>
            </div>

            <div className="mt-8 flex flex-wrap items-center gap-4">
              <button
                type="submit"
                disabled={submitting || !canSubmit}
                className="inline-flex min-w-40 items-center justify-center rounded-full bg-[linear-gradient(135deg,#f97316_0%,#dc2626_100%)] px-6 py-3.5 text-sm font-bold text-white shadow-[0_12px_34px_rgba(249,115,22,0.32)] transition hover:scale-[1.01] disabled:cursor-not-allowed disabled:opacity-60"
              >
                {submitting ? "建立中..." : "開始掃描"}
              </button>
              <p className="text-sm text-slate-400">每次送出會扣 1 點 credit，API 會立即回傳 job id。</p>
            </div>

            {error ? (
              <div className="mt-5 rounded-2xl border border-red-400/30 bg-red-500/10 px-4 py-3 text-sm text-red-200">
                {error}
              </div>
            ) : null}
          </form>

          <section className="rounded-[2rem] border border-white/50 bg-[rgba(255,255,255,0.74)] p-7 shadow-[0_30px_90px_rgba(15,23,42,0.10)] backdrop-blur-xl sm:p-8">
            <div className="flex items-start justify-between gap-4">
              <div>
                <p className="text-xs font-semibold uppercase tracking-[0.3em] text-[var(--accent)]">結果面板</p>
                <h2 className="mt-3 text-3xl font-black tracking-tight text-slate-950">掃描狀態與結果</h2>
              </div>
              {job?.report_file ? (
                <a
                  href={`${API_BASE_URL}/scans/${job.id}/report/`}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex rounded-full border border-slate-300 bg-white px-4 py-2 text-sm font-semibold text-slate-900 shadow-sm"
                >
                  下載 PDF 報告
                </a>
              ) : null}
            </div>

            {!job ? (
              <div className="mt-8 rounded-[1.75rem] border border-dashed border-slate-300 bg-slate-50/70 p-8">
                <p className="text-sm font-semibold uppercase tracking-[0.25em] text-slate-500">尚無任務</p>
                <h3 className="mt-4 text-2xl font-bold text-slate-900">目前還沒有送出掃描</h3>
                <p className="mt-3 max-w-xl text-sm leading-7 text-slate-600">
                  先輸入網站或 API 網址。任務建立後，這裡會顯示狀態、風險數量與報告下載入口。
                </p>
              </div>
            ) : (
              <div className="mt-8 space-y-5">
                <div className="rounded-[1.5rem] border border-slate-200 bg-white p-5 shadow-sm">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div>
                      <p className="text-xs font-semibold uppercase tracking-[0.28em] text-slate-500">
                        {job.scan_type === "api" ? "API 掃描" : "網站掃描"}
                      </p>
                      <h3 className="mt-2 text-2xl font-bold text-slate-950">{job.project_name}</h3>
                    </div>
                    <span className={`rounded-full px-4 py-2 text-xs font-bold uppercase tracking-[0.24em] ${statusTone.badge}`}>
                      {getStatusLabel(job.status)}
                    </span>
                  </div>
                  <p className="mt-4 break-all rounded-2xl bg-slate-50 px-4 py-3 text-sm text-slate-600">{job.target_url}</p>
                </div>

                <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
                  <ResultCard label="總問題數" value={job.result_summary?.issue_count ?? 0} accent="text-slate-950" />
                  <ResultCard label="嚴重" value={job.result_summary?.critical_count ?? 0} accent="text-rose-700" />
                  <ResultCard label="高風險" value={job.result_summary?.high_count ?? 0} accent="text-red-700" />
                  <ResultCard label="中風險" value={job.result_summary?.medium_count ?? 0} accent="text-amber-700" />
                </div>

                <div className="rounded-[1.5rem] bg-slate-950 p-5 text-white">
                  <p className="text-xs font-semibold uppercase tracking-[0.28em] text-orange-300">執行流程</p>
                  <div className="mt-5 grid gap-3 sm:grid-cols-3">
                    <TimelineStep title="已排入" active>
                      API 接收請求後，會立即建立任務並回傳基本資訊。
                    </TimelineStep>
                    <TimelineStep title="掃描中" active={job.status === "running" || job.status === "completed" || job.status === "failed"}>
                      Worker 會在背景對目標網址執行探測並彙整風險訊號。
                    </TimelineStep>
                    <TimelineStep title="報告完成" active={job.status === "completed"}>
                      結果寫入資料庫後，就可以直接下載 PDF 報告。
                    </TimelineStep>
                  </div>
                </div>

                {job.error_message ? (
                  <div className="rounded-[1.5rem] border border-red-200 bg-red-50 p-5 text-sm text-red-800">
                    <p className="font-semibold">任務失敗</p>
                    <p className="mt-2">{job.error_message}</p>
                  </div>
                ) : null}
              </div>
            )}
          </section>
        </section>
      </div>
    </main>
  );
}

function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint: string;
  children: React.ReactNode;
}) {
  return (
    <label className="block">
      <div className="mb-2 flex items-center justify-between gap-3">
        <span className="text-sm font-semibold text-white">{label}</span>
        <span className="text-xs text-slate-400">{hint}</span>
      </div>
      {children}
    </label>
  );
}

function HeroMetric({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-[1.4rem] border border-white/60 bg-white/65 px-5 py-4 shadow-sm">
      <p className="text-xs font-semibold uppercase tracking-[0.3em] text-slate-500">{label}</p>
      <p className="mt-2 text-lg font-black tracking-tight text-slate-950">{value}</p>
    </div>
  );
}

function StatusMetric({
  label,
  value,
  tone,
}: {
  label: string;
  value: number;
  tone: "neutral" | "critical" | "high" | "medium";
}) {
  const toneClass =
    tone === "critical"
      ? "bg-rose-500/12 text-rose-100 border-rose-400/20"
      : tone === "high"
        ? "bg-red-500/12 text-red-100 border-red-400/20"
        : tone === "medium"
          ? "bg-amber-500/12 text-amber-100 border-amber-400/20"
          : "bg-white/5 text-white border-white/10";

  return (
    <div className={`rounded-[1.35rem] border p-4 ${toneClass}`}>
      <p className="text-[11px] font-semibold uppercase tracking-[0.28em]">{label}</p>
      <p className="mt-3 text-3xl font-black tracking-tight">{value}</p>
    </div>
  );
}

function ResultCard({ label, value, accent }: { label: string; value: number; accent: string }) {
  return (
    <div className="rounded-[1.4rem] border border-slate-200 bg-white p-5 shadow-sm">
      <p className="text-xs font-semibold uppercase tracking-[0.28em] text-slate-500">{label}</p>
      <p className={`mt-3 text-4xl font-black tracking-tight ${accent}`}>{value}</p>
    </div>
  );
}

function TimelineStep({
  title,
  active,
  children,
}: {
  title: string;
  active?: boolean;
  children: React.ReactNode;
}) {
  return (
    <div className={`rounded-[1.35rem] border p-4 ${active ? "border-orange-300/40 bg-white/7" : "border-white/10 bg-white/4"}`}>
      <p className={`text-sm font-bold ${active ? "text-white" : "text-slate-400"}`}>{title}</p>
      <p className={`mt-2 text-sm leading-6 ${active ? "text-slate-200" : "text-slate-500"}`}>{children}</p>
    </div>
  );
}

function getStatusTone(status?: ScanJob["status"]) {
  switch (status) {
    case "running":
      return { badge: "bg-amber-200 text-amber-900" };
    case "completed":
      return { badge: "bg-emerald-200 text-emerald-900" };
    case "failed":
      return { badge: "bg-rose-200 text-rose-900" };
    case "pending":
      return { badge: "bg-slate-200 text-slate-900" };
    default:
      return { badge: "bg-slate-200 text-slate-900" };
  }
}

function getStatusLabel(status: ScanJob["status"]) {
  switch (status) {
    case "pending":
      return "等待中";
    case "running":
      return "掃描中";
    case "completed":
      return "已完成";
    case "failed":
      return "失敗";
  }
}

function deriveProjectName(targetUrl: string) {
  try {
    return new URL(targetUrl).hostname;
  } catch {
    return "未命名掃描";
  }
}
