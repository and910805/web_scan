"use client";

import { FormEvent, useEffect, useState } from "react";

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
    title: "Surface Mapping",
    description: "Probe common API routes, public docs, robots.txt, sitemap.xml, and exposed endpoints.",
  },
  {
    title: "Baseline Misconfig Checks",
    description: "Review security headers, wildcard CORS, sensitive files, and common deployment leaks.",
  },
  {
    title: "Async Execution",
    description: "Queue scans to Celery workers so API latency stays stable while checks run in the background.",
  },
];

export default function HomePage() {
  const [token, setToken] = useState("");
  const [projectName, setProjectName] = useState("");
  const [targetUrl, setTargetUrl] = useState("");
  const [scanType, setScanType] = useState<"web" | "api">("web");
  const [job, setJob] = useState<ScanJob | null>(null);
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

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
    setSubmitting(true);
    setError("");

    try {
      const response = await fetch(`${API_BASE_URL}/scans/`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          project_name: projectName,
          scan_type: scanType,
          target_url: targetUrl,
        }),
      });

      if (!response.ok) {
        const payload = (await response.json()) as { detail?: string };
        throw new Error(payload.detail ?? "Scan request failed");
      }

      const createdJob = (await response.json()) as ScanJob;
      setJob(createdJob);
    } catch (submitError) {
      setError(submitError instanceof Error ? submitError.message : "Unknown error");
    } finally {
      setSubmitting(false);
    }
  }

  const statusTone = getStatusTone(job?.status);

  return (
    <main className="relative overflow-hidden px-4 py-6 sm:px-6 lg:px-10">
      <div className="absolute inset-x-0 top-0 -z-10 h-[28rem] bg-[radial-gradient(circle_at_top,rgba(242,104,33,0.22),transparent_42%)]" />
      <div className="absolute right-[-8rem] top-28 -z-10 h-72 w-72 rounded-full bg-[rgba(17,24,39,0.08)] blur-3xl" />
      <div className="absolute left-[-6rem] top-56 -z-10 h-80 w-80 rounded-full bg-[rgba(190,24,93,0.10)] blur-3xl" />

      <div className="mx-auto flex min-h-screen max-w-7xl flex-col gap-6">
        <header className="grid gap-6 lg:grid-cols-[1.15fr_0.85fr]">
          <section className="rounded-[2rem] border border-white/55 bg-[rgba(255,248,239,0.78)] p-7 shadow-[0_30px_90px_rgba(15,23,42,0.10)] backdrop-blur-xl sm:p-9">
            <div className="inline-flex items-center gap-3 rounded-full border border-black/10 bg-white/70 px-4 py-2 text-xs font-bold uppercase tracking-[0.35em] text-[var(--accent-strong)]">
              WeakScan Control
            </div>
            <h1 className="mt-6 max-w-4xl text-4xl font-black leading-none tracking-[-0.04em] text-slate-950 sm:text-6xl">
              Remote weak scanning for websites and APIs with an operator-grade dashboard.
            </h1>
            <p className="mt-5 max-w-2xl text-base leading-7 text-slate-600 sm:text-lg">
              Queue a target, let the backend execute probes asynchronously, and review risk signals without forcing the API
              into long-running requests.
            </p>

            <div className="mt-8 grid gap-3 sm:grid-cols-3">
              <HeroMetric label="Execution Model" value="Celery Queue" />
              <HeroMetric label="Scan Modes" value="Web + API" />
              <HeroMetric label="Report Output" value="PDF Export" />
            </div>
          </section>

          <section className="rounded-[2rem] border border-slate-800 bg-[#0d1320] p-7 text-white shadow-[0_30px_90px_rgba(15,23,42,0.22)] sm:p-8">
            <div className="flex items-start justify-between gap-4">
              <div>
                <p className="text-xs font-semibold uppercase tracking-[0.32em] text-orange-300">Live Status</p>
                <h2 className="mt-3 text-2xl font-bold">Queue Overview</h2>
              </div>
              <span className={`rounded-full px-4 py-2 text-xs font-semibold uppercase tracking-[0.2em] ${statusTone.badge}`}>
                {job ? job.status : "idle"}
              </span>
            </div>

            <div className="mt-8 space-y-4">
              <div className="rounded-[1.5rem] border border-white/10 bg-white/5 p-5">
                <div className="flex items-center justify-between text-sm text-slate-300">
                  <span>Current target</span>
                  <span>{job?.scan_type === "api" ? "API" : "Website"}</span>
                </div>
                <p className="mt-3 break-all text-lg font-semibold text-white">
                  {job?.target_url ?? "No target queued yet"}
                </p>
                <p className="mt-2 text-sm text-slate-400">
                  {job ? `${job.project_name} is being tracked in the current session.` : "Submit a target to start asynchronous probing."}
                </p>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <StatusMetric label="Issues" value={job?.result_summary?.issue_count ?? 0} tone="neutral" />
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

        <section className="grid gap-6 lg:grid-cols-[0.95fr_1.05fr]">
          <form
            onSubmit={handleSubmit}
            className="rounded-[2rem] border border-slate-900/80 bg-[linear-gradient(180deg,#0f172a_0%,#111827_100%)] p-7 text-white shadow-[0_40px_100px_rgba(15,23,42,0.28)] sm:p-8"
          >
            <div className="flex items-start justify-between gap-4">
              <div>
                <p className="text-xs font-semibold uppercase tracking-[0.3em] text-orange-300">Queue Scan</p>
                <h2 className="mt-3 text-3xl font-black tracking-tight">Dispatch a new assessment</h2>
              </div>
              <div className="rounded-2xl border border-white/10 bg-white/5 px-4 py-3 text-right">
                <p className="text-[10px] uppercase tracking-[0.32em] text-slate-400">Execution</p>
                <p className="mt-1 text-sm font-semibold text-white">Async Worker</p>
              </div>
            </div>

            <div className="mt-8 space-y-5">
              <Field label="JWT access token" hint="Use the access token returned by /api/auth/token/.">
                <textarea
                  value={token}
                  onChange={(event) => setToken(event.target.value)}
                  className="min-h-28 w-full rounded-[1.35rem] border border-white/10 bg-white/6 px-4 py-3 text-sm text-white outline-none transition placeholder:text-slate-500 focus:border-orange-300/70 focus:bg-white/10"
                  placeholder="Paste your bearer token here"
                  required
                />
              </Field>

              <div className="grid gap-5 md:grid-cols-2">
                <Field label="Project name" hint="Internal label for this client or system.">
                  <input
                    value={projectName}
                    onChange={(event) => setProjectName(event.target.value)}
                    className="w-full rounded-[1.35rem] border border-white/10 bg-white/6 px-4 py-3 text-sm text-white outline-none transition placeholder:text-slate-500 focus:border-orange-300/70 focus:bg-white/10"
                    placeholder="Customer portal"
                    required
                  />
                </Field>

                <Field label="Scan type" hint="Choose baseline web or API probes.">
                  <select
                    value={scanType}
                    onChange={(event) => setScanType(event.target.value as "web" | "api")}
                    className="w-full rounded-[1.35rem] border border-white/10 bg-white/6 px-4 py-3 text-sm text-white outline-none transition focus:border-orange-300/70 focus:bg-white/10"
                  >
                    <option value="web">Web scan</option>
                    <option value="api">API scan</option>
                  </select>
                </Field>
              </div>

              <Field label="Target URL" hint="The worker will probe this host directly from the backend.">
                <input
                  type="url"
                  value={targetUrl}
                  onChange={(event) => setTargetUrl(event.target.value)}
                  className="w-full rounded-[1.35rem] border border-white/10 bg-white/6 px-4 py-3 text-sm text-white outline-none transition placeholder:text-slate-500 focus:border-orange-300/70 focus:bg-white/10"
                  placeholder="https://example.com"
                  required
                />
              </Field>
            </div>

            <div className="mt-8 flex flex-wrap items-center gap-4">
              <button
                type="submit"
                disabled={submitting}
                className="inline-flex min-w-40 items-center justify-center rounded-full bg-[linear-gradient(135deg,#f97316_0%,#dc2626_100%)] px-6 py-3.5 text-sm font-bold text-white shadow-[0_12px_34px_rgba(249,115,22,0.32)] transition hover:scale-[1.01] disabled:cursor-not-allowed disabled:opacity-60"
              >
                {submitting ? "Queueing..." : "Launch Scan"}
              </button>
              <p className="text-sm text-slate-400">Each request consumes one credit and returns a job id immediately.</p>
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
                <p className="text-xs font-semibold uppercase tracking-[0.3em] text-[var(--accent)]">Investigation Panel</p>
                <h2 className="mt-3 text-3xl font-black tracking-tight text-slate-950">Result timeline</h2>
              </div>
              {job?.report_file ? (
                <a
                  href={`${API_BASE_URL}/scans/${job.id}/report/`}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex rounded-full border border-slate-300 bg-white px-4 py-2 text-sm font-semibold text-slate-900 shadow-sm"
                >
                  Download PDF
                </a>
              ) : null}
            </div>

            {!job ? (
              <div className="mt-8 rounded-[1.75rem] border border-dashed border-slate-300 bg-slate-50/70 p-8">
                <p className="text-sm font-semibold uppercase tracking-[0.25em] text-slate-500">Queue Empty</p>
                <h3 className="mt-4 text-2xl font-bold text-slate-900">No scan submitted yet</h3>
                <p className="mt-3 max-w-xl text-sm leading-7 text-slate-600">
                  Start with a website or API base URL. Once the job is queued, this panel will show its status, severity
                  counts, and report access.
                </p>
              </div>
            ) : (
              <div className="mt-8 space-y-5">
                <div className="rounded-[1.5rem] border border-slate-200 bg-white p-5 shadow-sm">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div>
                      <p className="text-xs font-semibold uppercase tracking-[0.28em] text-slate-500">{job.scan_type} scan</p>
                      <h3 className="mt-2 text-2xl font-bold text-slate-950">{job.project_name}</h3>
                    </div>
                    <span className={`rounded-full px-4 py-2 text-xs font-bold uppercase tracking-[0.24em] ${statusTone.badge}`}>
                      {job.status}
                    </span>
                  </div>
                  <p className="mt-4 break-all rounded-2xl bg-slate-50 px-4 py-3 text-sm text-slate-600">{job.target_url}</p>
                </div>

                <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
                  <ResultCard label="Total Issues" value={job.result_summary?.issue_count ?? 0} accent="text-slate-950" />
                  <ResultCard label="Critical" value={job.result_summary?.critical_count ?? 0} accent="text-rose-700" />
                  <ResultCard label="High" value={job.result_summary?.high_count ?? 0} accent="text-red-700" />
                  <ResultCard label="Medium" value={job.result_summary?.medium_count ?? 0} accent="text-amber-700" />
                </div>

                <div className="rounded-[1.5rem] bg-slate-950 p-5 text-white">
                  <p className="text-xs font-semibold uppercase tracking-[0.28em] text-orange-300">Execution Flow</p>
                  <div className="mt-5 grid gap-3 sm:grid-cols-3">
                    <TimelineStep title="Queued" active>
                      API accepts the request and returns the task metadata immediately.
                    </TimelineStep>
                    <TimelineStep title="Running" active={job.status === "running" || job.status === "completed" || job.status === "failed"}>
                      Worker probes the target URL and aggregates baseline risk signals.
                    </TimelineStep>
                    <TimelineStep title="Report" active={job.status === "completed"}>
                      Findings are stored and the PDF report becomes downloadable.
                    </TimelineStep>
                  </div>
                </div>

                {job.error_message ? (
                  <div className="rounded-[1.5rem] border border-red-200 bg-red-50 p-5 text-sm text-red-800">
                    <p className="font-semibold">Task failed</p>
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
      return {
        badge: "bg-amber-200 text-amber-900",
      };
    case "completed":
      return {
        badge: "bg-emerald-200 text-emerald-900",
      };
    case "failed":
      return {
        badge: "bg-rose-200 text-rose-900",
      };
    case "pending":
      return {
        badge: "bg-slate-200 text-slate-900",
      };
    default:
      return {
        badge: "bg-slate-200 text-slate-900",
      };
  }
}
