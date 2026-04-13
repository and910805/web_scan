"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { FormEvent, useEffect, useState } from "react";

import { AuthUser, clearAuth, getStoredAccessToken, getStoredUser, refreshAccessToken } from "@/lib/auth";

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
    risk_score?: number;
    new_count?: number;
    persistent_count?: number;
    resolved_count?: number;
  };
  error_message: string;
  report_file: string | null;
};

type TrendSnapshot = {
  scan_count: number;
  completed_count: number;
  failed_count: number;
  severity_totals: Record<string, number>;
  recent_jobs: Array<{
    id: number;
    project_name: string;
    target_url: string;
    status: ScanJob["status"];
    issue_count: number;
    risk_score: number;
  }>;
  top_targets: Array<{ target_url: string; total: number }>;
};

const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000/api";

const capabilityCards = [
  {
    title: "Baseline Web Checks",
    description: "Security headers, TLS posture, sensitive paths, robots.txt, sitemap.xml, and basic HTTP behavior.",
  },
  {
    title: "API Surface Review",
    description: "OpenAPI and docs exposure, CORS signals, dangerous methods, and common unauthenticated paths.",
  },
  {
    title: "Async Report Flow",
    description: "Submit a scan job, let the worker process it, then download a PDF report when the job completes.",
  },
];

export default function HomePage() {
  const router = useRouter();
  const [manualToken, setManualToken] = useState("");
  const [projectName, setProjectName] = useState("");
  const [targetUrl, setTargetUrl] = useState("");
  const [scanType, setScanType] = useState<"web" | "api">("web");
  const [job, setJob] = useState<ScanJob | null>(null);
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [downloading, setDownloading] = useState(false);
  const [user, setUser] = useState<AuthUser | null>(null);
  const [trends, setTrends] = useState<TrendSnapshot | null>(null);

  useEffect(() => {
    syncAuthState(setManualToken, setUser);
    const sync = () => syncAuthState(setManualToken, setUser);
    window.addEventListener("focus", sync);
    window.addEventListener("storage", sync);
    document.addEventListener("visibilitychange", sync);

    return () => {
      window.removeEventListener("focus", sync);
      window.removeEventListener("storage", sync);
      document.removeEventListener("visibilitychange", sync);
    };
  }, []);

  useEffect(() => {
    const activeToken = getActiveToken(manualToken);
    if (!job || !activeToken || !["pending", "running"].includes(job.status)) {
      return;
    }

    const timer = window.setInterval(async () => {
      const response = await fetchWithStoredAuth(`${API_BASE_URL}/scans/${job.id}/`);
      if (!response.ok) {
        if (response.status === 401) {
          syncAuthState(setManualToken, setUser);
        }
        return;
      }

      const nextJob = (await response.json()) as ScanJob;
      setJob(nextJob);
    }, 4000);

    return () => window.clearInterval(timer);
  }, [job, manualToken]);

  useEffect(() => {
    const activeToken = getActiveToken(manualToken);
    if (!activeToken) {
      setTrends(null);
      return;
    }

    void fetchTrends().then(setTrends).catch(() => undefined);
  }, [manualToken, job?.status]);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    const activeToken = getActiveToken(manualToken);
    if (!activeToken) {
      setError("Please sign in before starting a scan.");
      return;
    }

    setSubmitting(true);
    setError("");

    try {
      const resolvedProjectName = projectName.trim() || deriveProjectName(targetUrl);
      const response = await fetchWithStoredAuth(`${API_BASE_URL}/scans/`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          project_name: resolvedProjectName,
          scan_type: scanType,
          target_url: targetUrl,
        }),
      });

      const payload = await response.json();
      if (!response.ok) {
        throw new Error((payload as { detail?: string }).detail ?? "Scan submission failed.");
      }

      setJob(payload as ScanJob);
      syncAuthState(setManualToken, setUser);
    } catch (submitError) {
      setError(submitError instanceof Error ? submitError.message : "Scan submission failed.");
    } finally {
      setSubmitting(false);
    }
  }

  async function handleDownloadReport() {
    const activeToken = getActiveToken(manualToken);
    if (!job?.id || !activeToken) {
      setError("Please sign in before downloading the PDF report.");
      router.push("/login");
      return;
    }

    setDownloading(true);
    setError("");

    try {
      const response = await fetchWithStoredAuth(`${API_BASE_URL}/scans/${job.id}/report/`, {
        timeoutMs: 45000,
      });

      if (response.status === 401) {
        clearAuth();
        setUser(null);
        setManualToken("");
        throw new Error("Your login session expired. Please sign in again.");
      }

      if (!response.ok) {
        if (response.status === 404) {
          throw new Error("PDF report is not ready yet. Please wait a few seconds and try again.");
        }
        throw new Error(`PDF download failed with HTTP ${response.status}`);
      }

      const blob = await response.blob();
      const blobUrl = window.URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = blobUrl;
      link.download = `scan-report-${job.id}.pdf`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.setTimeout(() => window.URL.revokeObjectURL(blobUrl), 1000);
    } catch (downloadError) {
      if (downloadError instanceof Error && downloadError.name === "AbortError") {
        setError("PDF download timed out. Please try again in a few seconds.");
      } else {
        setError(downloadError instanceof Error ? downloadError.message : "PDF download failed.");
      }
    } finally {
      setDownloading(false);
    }
  }

  async function fetchTrends() {
    const response = await fetchWithStoredAuth(`${API_BASE_URL}/scans/trends/`);
    if (!response.ok) {
      throw new Error("Unable to load scan trends.");
    }
    return (await response.json()) as TrendSnapshot;
  }

  const statusTone = getStatusTone(job?.status);
  const activeToken = typeof window === "undefined" ? manualToken.trim() : getActiveToken(manualToken);
  const canSubmit = Boolean(activeToken) && !submitting;

  return (
    <main className="relative overflow-hidden px-4 py-6 sm:px-6 lg:px-10">
      <div className="absolute inset-x-0 top-0 -z-10 h-[28rem] bg-[radial-gradient(circle_at_top,rgba(242,104,33,0.22),transparent_42%)]" />
      <div className="absolute right-[-8rem] top-28 -z-10 h-72 w-72 rounded-full bg-[rgba(17,24,39,0.08)] blur-3xl" />
      <div className="absolute left-[-6rem] top-56 -z-10 h-80 w-80 rounded-full bg-[rgba(190,24,93,0.10)] blur-3xl" />

      <div className="mx-auto flex min-h-screen max-w-7xl flex-col gap-6">
        <nav className="flex items-center justify-between rounded-[1.5rem] border border-white/40 bg-white/50 px-5 py-4 backdrop-blur">
          <div>
            <p className="text-sm font-bold uppercase tracking-[0.3em] text-[var(--accent)]">WeakScan</p>
            <p className="text-sm text-slate-600">Async website and API assessment</p>
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
                    setManualToken("");
                    setUser(null);
                    setJob(null);
                  }}
                  className="rounded-full border border-slate-300 px-4 py-2 font-semibold text-slate-900"
                >
                  Log out
                </button>
              </>
            ) : (
              <>
                <Link href="/login" className="rounded-full border border-slate-300 px-4 py-2 font-semibold text-slate-900">
                  Log in
                </Link>
                <Link href="/register" className="rounded-full bg-slate-950 px-4 py-2 font-semibold text-white">
                  Register
                </Link>
              </>
            )}
          </div>
        </nav>

        <header className="grid gap-6 lg:grid-cols-[1.15fr_0.85fr]">
          <section className="rounded-[2rem] border border-white/55 bg-[rgba(255,248,239,0.78)] p-7 shadow-[0_30px_90px_rgba(15,23,42,0.10)] backdrop-blur-xl sm:p-9">
            <div className="inline-flex items-center gap-3 rounded-full border border-black/10 bg-white/70 px-4 py-2 text-xs font-bold uppercase tracking-[0.35em] text-[var(--accent-strong)]">
              WeakScan Dashboard
            </div>
            <h1 className="mt-6 max-w-4xl text-4xl font-black leading-none tracking-[-0.04em] text-slate-950 sm:text-6xl">
              Run a weak scan, keep the session alive, and export a clean report.
            </h1>
            <p className="mt-5 max-w-2xl text-base leading-7 text-slate-600 sm:text-lg">
              Submit a web or API target, let the worker process it in the background, and download the PDF report when
              the scan finishes.
            </p>

            <div className="mt-8 grid gap-3 sm:grid-cols-3">
              <HeroMetric label="Processing" value="Celery worker" />
              <HeroMetric label="Scan Modes" value="Web + API" />
              <HeroMetric label="Output" value="PDF report" />
            </div>
          </section>

          <section className="rounded-[2rem] border border-slate-800 bg-[#0d1320] p-7 text-white shadow-[0_30px_90px_rgba(15,23,42,0.22)] sm:p-8">
            <div className="flex items-start justify-between gap-4">
              <div>
                <p className="text-xs font-semibold uppercase tracking-[0.32em] text-orange-300">Current Job</p>
                <h2 className="mt-3 text-2xl font-bold">Live status</h2>
              </div>
              <span className={`rounded-full px-4 py-2 text-xs font-semibold uppercase tracking-[0.2em] ${statusTone.badge}`}>
                {job ? getStatusLabel(job.status) : "Idle"}
              </span>
            </div>

            <div className="mt-8 space-y-4">
              <div className="rounded-[1.5rem] border border-white/10 bg-white/5 p-5">
                <div className="flex items-center justify-between text-sm text-slate-300">
                  <span>Target</span>
                  <span>{job?.scan_type === "api" ? "API" : "Website"}</span>
                </div>
                <p className="mt-3 break-all text-lg font-semibold text-white">{job?.target_url ?? "No active target"}</p>
                <p className="mt-2 text-sm text-slate-400">
                  {job ? `Project ${job.project_name}` : "Start a scan to see live progress and summary metrics."}
                </p>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <StatusMetric label="Findings" value={job?.result_summary?.issue_count ?? 0} tone="neutral" />
                <StatusMetric label="Critical" value={job?.result_summary?.critical_count ?? 0} tone="critical" />
                <StatusMetric label="High" value={job?.result_summary?.high_count ?? 0} tone="high" />
                <StatusMetric label="Medium" value={job?.result_summary?.medium_count ?? 0} tone="medium" />
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

        {trends ? (
          <section className="grid gap-6 lg:grid-cols-[1fr_1fr]">
            <div className="rounded-[2rem] border border-white/50 bg-white/70 p-7 shadow-[0_22px_60px_rgba(15,23,42,0.08)] backdrop-blur">
              <p className="text-xs font-semibold uppercase tracking-[0.3em] text-[var(--accent)]">Trend Dashboard</p>
              <h2 className="mt-3 text-3xl font-black tracking-tight text-slate-950">Recent scan trends</h2>
              <div className="mt-6 grid gap-4 sm:grid-cols-3">
                <ResultCard label="All Scans" value={trends.scan_count} accent="text-slate-950" />
                <ResultCard label="Completed" value={trends.completed_count} accent="text-emerald-700" />
                <ResultCard label="Failed" value={trends.failed_count} accent="text-rose-700" />
              </div>
              <div className="mt-6 grid gap-4 sm:grid-cols-4">
                <ResultCard label="Crit Total" value={trends.severity_totals.critical ?? 0} accent="text-rose-700" />
                <ResultCard label="High Total" value={trends.severity_totals.high ?? 0} accent="text-red-700" />
                <ResultCard label="Med Total" value={trends.severity_totals.medium ?? 0} accent="text-amber-700" />
                <ResultCard label="Low Total" value={trends.severity_totals.low ?? 0} accent="text-sky-700" />
              </div>
            </div>

            <div className="rounded-[2rem] border border-white/50 bg-white/70 p-7 shadow-[0_22px_60px_rgba(15,23,42,0.08)] backdrop-blur">
              <p className="text-xs font-semibold uppercase tracking-[0.3em] text-[var(--accent)]">Exposure View</p>
              <h2 className="mt-3 text-3xl font-black tracking-tight text-slate-950">Top targets and recent jobs</h2>
              <div className="mt-6 space-y-3">
                {trends.top_targets.map((target) => (
                  <div key={target.target_url} className="flex items-center justify-between rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm">
                    <span className="truncate pr-4 text-slate-700">{target.target_url}</span>
                    <span className="font-bold text-slate-950">{target.total}</span>
                  </div>
                ))}
              </div>
              <div className="mt-6 space-y-3">
                {trends.recent_jobs.slice(0, 5).map((recentJob) => (
                  <div key={recentJob.id} className="rounded-2xl border border-slate-200 bg-white px-4 py-3">
                    <div className="flex items-center justify-between gap-3">
                      <p className="font-semibold text-slate-950">{recentJob.project_name}</p>
                      <span className={`rounded-full px-3 py-1 text-xs font-bold ${getStatusTone(recentJob.status).badge}`}>
                        {getStatusLabel(recentJob.status)}
                      </span>
                    </div>
                    <p className="mt-2 truncate text-sm text-slate-600">{recentJob.target_url}</p>
                    <p className="mt-2 text-xs uppercase tracking-[0.22em] text-slate-500">
                      Findings {recentJob.issue_count} / Risk {recentJob.risk_score}
                    </p>
                  </div>
                ))}
              </div>
            </div>
          </section>
        ) : null}

        <section className="grid gap-6 lg:grid-cols-[0.95fr_1.05fr]">
          <form
            onSubmit={handleSubmit}
            className="rounded-[2rem] border border-slate-900/80 bg-[linear-gradient(180deg,#0f172a_0%,#111827_100%)] p-7 text-white shadow-[0_40px_100px_rgba(15,23,42,0.28)] sm:p-8"
          >
            <div className="flex items-start justify-between gap-4">
              <div>
                <p className="text-xs font-semibold uppercase tracking-[0.3em] text-orange-300">New Scan</p>
                <h2 className="mt-3 text-3xl font-black tracking-tight">Submit target</h2>
              </div>
              <div className="rounded-2xl border border-white/10 bg-white/5 px-4 py-3 text-right">
                <p className="text-[10px] uppercase tracking-[0.32em] text-slate-400">Auth</p>
                <p className="mt-1 text-sm font-semibold text-white">{user ? "Stored session" : "Login required"}</p>
              </div>
            </div>

            <div className="mt-8 space-y-5">
              {user ? (
                <div className="rounded-[1.35rem] border border-emerald-400/20 bg-emerald-500/10 px-4 py-4 text-sm text-emerald-100">
                  Signed in as <span className="font-semibold">{user.username}</span>. You can keep submitting scans
                  without logging in again while the session is valid.
                </div>
              ) : (
                <div className="rounded-[1.35rem] border border-amber-300/20 bg-amber-500/10 px-4 py-4 text-sm text-amber-100">
                  Please <Link href="/login" className="font-semibold text-amber-200 underline">log in</Link> before submitting a scan.
                </div>
              )}

              <details className="rounded-[1.35rem] border border-white/10 bg-white/5 px-4 py-4">
                <summary className="cursor-pointer list-none text-sm font-semibold text-white">Manual token override</summary>
                <p className="mt-3 text-sm text-slate-400">
                  Normally the app uses the stored access token automatically. You only need this box if you want to
                  test with a pasted JWT manually.
                </p>
                <div className="mt-4">
                  <Field label="JWT token" hint="Optional override">
                    <textarea
                      value={manualToken}
                      onChange={(event) => setManualToken(event.target.value)}
                      className="dark-field min-h-28 w-full rounded-[1.35rem] border border-white/10 px-4 py-3 text-sm text-white outline-none transition placeholder:text-slate-500 focus:border-orange-300/70"
                      placeholder="Paste a Bearer token only if you want to override the stored session."
                    />
                  </Field>
                </div>
              </details>

              <div className="grid gap-5 md:grid-cols-2">
                <Field label="Project name" hint="Optional">
                  <input
                    value={projectName}
                    onChange={(event) => setProjectName(event.target.value)}
                    className="dark-field w-full rounded-[1.35rem] border border-white/10 px-4 py-3 text-sm text-white outline-none transition placeholder:text-slate-500 focus:border-orange-300/70"
                    placeholder="customer-portal"
                  />
                </Field>

                <Field label="Scan type" hint="Website or API">
                  <select
                    value={scanType}
                    onChange={(event) => setScanType(event.target.value as "web" | "api")}
                    className="dark-field w-full rounded-[1.35rem] border border-white/10 px-4 py-3 text-sm text-white outline-none transition focus:border-orange-300/70"
                  >
                    <option value="web">Website</option>
                    <option value="api">API</option>
                  </select>
                </Field>
              </div>

              <Field label="Target URL" hint="Required">
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
                disabled={!canSubmit}
                className="inline-flex min-w-40 items-center justify-center rounded-full bg-[linear-gradient(135deg,#f97316_0%,#dc2626_100%)] px-6 py-3.5 text-sm font-bold text-white shadow-[0_12px_34px_rgba(249,115,22,0.32)] transition hover:scale-[1.01] disabled:cursor-not-allowed disabled:opacity-60"
              >
                {submitting ? "Submitting..." : "Start scan"}
              </button>
              <p className="text-sm text-slate-400">Each scan currently costs 1 credit.</p>
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
                <p className="text-xs font-semibold uppercase tracking-[0.3em] text-[var(--accent)]">Results</p>
                <h2 className="mt-3 text-3xl font-black tracking-tight text-slate-950">Scan output</h2>
              </div>
              {job?.report_file ? (
                <button
                  type="button"
                  onClick={handleDownloadReport}
                  disabled={downloading}
                  className="inline-flex rounded-full border border-slate-300 bg-white px-4 py-2 text-sm font-semibold text-slate-900 shadow-sm disabled:opacity-60"
                >
                  {downloading ? "Downloading..." : "Download PDF"}
                </button>
              ) : null}
            </div>

            {!job ? (
              <div className="mt-8 rounded-[1.75rem] border border-dashed border-slate-300 bg-slate-50/70 p-8">
                <p className="text-sm font-semibold uppercase tracking-[0.25em] text-slate-500">Waiting</p>
                <h3 className="mt-4 text-2xl font-bold text-slate-900">No scan yet</h3>
                <p className="mt-3 max-w-xl text-sm leading-7 text-slate-600">
                  Submit a target URL to start an async job. Once the worker completes, this panel will show the summary
                  and let you download the PDF report.
                </p>
              </div>
            ) : (
              <div className="mt-8 space-y-5">
                <div className="rounded-[1.5rem] border border-slate-200 bg-white p-5 shadow-sm">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div>
                      <p className="text-xs font-semibold uppercase tracking-[0.28em] text-slate-500">
                        {job.scan_type === "api" ? "API scan" : "Website scan"}
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
                  <ResultCard label="Total Findings" value={job.result_summary?.issue_count ?? 0} accent="text-slate-950" />
                  <ResultCard label="Critical" value={job.result_summary?.critical_count ?? 0} accent="text-rose-700" />
                  <ResultCard label="High" value={job.result_summary?.high_count ?? 0} accent="text-red-700" />
                  <ResultCard label="Risk Score" value={job.result_summary?.risk_score ?? 0} accent="text-amber-700" />
                </div>

                <div className="grid gap-4 sm:grid-cols-3">
                  <ResultCard label="New" value={job.result_summary?.new_count ?? 0} accent="text-orange-700" />
                  <ResultCard label="Persistent" value={job.result_summary?.persistent_count ?? 0} accent="text-slate-900" />
                  <ResultCard label="Resolved" value={job.result_summary?.resolved_count ?? 0} accent="text-emerald-700" />
                </div>

                <div className="rounded-[1.5rem] bg-slate-950 p-5 text-white">
                  <p className="text-xs font-semibold uppercase tracking-[0.28em] text-orange-300">Job timeline</p>
                  <div className="mt-5 grid gap-3 sm:grid-cols-3">
                    <TimelineStep title="Submitted" active>
                      The API accepted the target and created a scan job.
                    </TimelineStep>
                    <TimelineStep title="Processing" active={job.status === "running" || job.status === "completed" || job.status === "failed"}>
                      The worker is evaluating the target and producing findings.
                    </TimelineStep>
                    <TimelineStep title="Report ready" active={job.status === "completed"}>
                      When the PDF is available, the download button will appear above.
                    </TimelineStep>
                  </div>
                </div>

                {job.error_message ? (
                  <div className="rounded-[1.5rem] border border-red-200 bg-red-50 p-5 text-sm text-red-800">
                    <p className="font-semibold">Job error</p>
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
      return "Pending";
    case "running":
      return "Running";
    case "completed":
      return "Completed";
    case "failed":
      return "Failed";
  }
}

function deriveProjectName(targetUrl: string) {
  try {
    return new URL(targetUrl).hostname;
  } catch {
    return "untitled-target";
  }
}

function getActiveToken(manualToken: string) {
  return manualToken.trim() || getStoredAccessToken();
}

function syncAuthState(
  setManualToken: (value: string) => void,
  setUser: (value: AuthUser | null) => void,
) {
  setManualToken(getStoredAccessToken());
  setUser(getStoredUser());
}

async function fetchWithStoredAuth(
  input: string,
  init: RequestInit & { timeoutMs?: number } = {},
) {
  const { timeoutMs = 20000, headers, ...rest } = init;

  const run = async (accessToken: string) => {
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), timeoutMs);
    try {
      return await fetch(input, {
        ...rest,
        headers: {
          ...headers,
          Authorization: `Bearer ${accessToken}`,
        },
        signal: controller.signal,
      });
    } finally {
      window.clearTimeout(timeout);
    }
  };

  let accessToken = getStoredAccessToken();
  if (!accessToken) {
    accessToken = await refreshAccessToken(API_BASE_URL);
  }
  if (!accessToken) {
    return new Response(null, { status: 401 });
  }

  let response = await run(accessToken);
  if (response.status !== 401) {
    return response;
  }

  accessToken = await refreshAccessToken(API_BASE_URL);
  if (!accessToken) {
    return response;
  }
  return run(accessToken);
}
