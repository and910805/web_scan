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

  return (
    <main className="mx-auto flex min-h-screen max-w-6xl flex-col gap-8 px-6 py-10">
      <section className="rounded-[2rem] border border-white/60 bg-[var(--panel)] p-8 shadow-[0_30px_80px_rgba(17,24,39,0.12)] backdrop-blur">
        <p className="text-sm font-semibold uppercase tracking-[0.35em] text-[var(--accent)]">WeakScan</p>
        <h1 className="mt-3 max-w-3xl text-4xl font-black tracking-tight text-slate-900 sm:text-6xl">
          Queue remote website and API scans without blocking the backend.
        </h1>
        <p className="mt-4 max-w-2xl text-base leading-7 text-slate-600">
          Submit a target URL, let Celery run the checks, and poll for a report when the job finishes.
        </p>
      </section>

      <section className="grid gap-6 lg:grid-cols-[1.1fr_0.9fr]">
        <form onSubmit={handleSubmit} className="rounded-[2rem] bg-slate-950 p-8 text-white shadow-xl">
          <h2 className="text-2xl font-bold">Start Scan</h2>
          <div className="mt-6 space-y-5">
            <label className="block">
              <span className="mb-2 block text-sm text-slate-300">JWT access token</span>
              <textarea
                value={token}
                onChange={(event) => setToken(event.target.value)}
                className="min-h-28 w-full rounded-2xl border border-slate-700 bg-slate-900 px-4 py-3 text-sm outline-none ring-0"
                placeholder="Paste token from /api/auth/token/"
                required
              />
            </label>
            <label className="block">
              <span className="mb-2 block text-sm text-slate-300">Project name</span>
              <input
                value={projectName}
                onChange={(event) => setProjectName(event.target.value)}
                className="w-full rounded-2xl border border-slate-700 bg-slate-900 px-4 py-3 text-sm outline-none"
                placeholder="Customer portal"
                required
              />
            </label>
            <label className="block">
              <span className="mb-2 block text-sm text-slate-300">Target URL</span>
              <input
                type="url"
                value={targetUrl}
                onChange={(event) => setTargetUrl(event.target.value)}
                className="w-full rounded-2xl border border-slate-700 bg-slate-900 px-4 py-3 text-sm outline-none"
                placeholder="https://example.com"
                required
              />
            </label>
            <label className="block">
              <span className="mb-2 block text-sm text-slate-300">Scan type</span>
              <select
                value={scanType}
                onChange={(event) => setScanType(event.target.value as "web" | "api")}
                className="w-full rounded-2xl border border-slate-700 bg-slate-900 px-4 py-3 text-sm outline-none"
              >
                <option value="web">Web scan</option>
                <option value="api">API scan</option>
              </select>
            </label>
          </div>
          <button
            type="submit"
            disabled={submitting}
            className="mt-6 rounded-full bg-[var(--accent)] px-6 py-3 font-semibold text-white transition hover:bg-[var(--accent-strong)] disabled:cursor-not-allowed disabled:opacity-60"
          >
            {submitting ? "Queueing..." : "Queue Scan"}
          </button>
          {error ? <p className="mt-4 text-sm text-amber-300">{error}</p> : null}
        </form>

        <div className="rounded-[2rem] border border-white/60 bg-white/80 p-8 shadow-lg">
          <h2 className="text-2xl font-bold text-slate-900">Job Status</h2>
          {!job ? (
            <p className="mt-4 text-slate-600">No scan submitted yet.</p>
          ) : (
            <div className="mt-6 space-y-4 text-sm text-slate-700">
              <div className="rounded-2xl bg-slate-100 p-4">
                <p className="font-semibold text-slate-900">{job.project_name}</p>
                <p className="mt-1 break-all">{job.target_url}</p>
                <p className="mt-2">Status: {job.status}</p>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <Metric label="Issues" value={job.result_summary?.issue_count ?? 0} />
                <Metric label="Critical" value={job.result_summary?.critical_count ?? 0} />
                <Metric label="High" value={job.result_summary?.high_count ?? 0} />
                <Metric label="Medium" value={job.result_summary?.medium_count ?? 0} />
              </div>
              {job.error_message ? <p className="text-red-700">{job.error_message}</p> : null}
              {job.report_file ? (
                <a
                  href={`${API_BASE_URL}/scans/${job.id}/report/`}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex rounded-full bg-slate-950 px-5 py-3 font-semibold text-white"
                >
                  Download Report
                </a>
              ) : null}
            </div>
          )}
        </div>
      </section>
    </main>
  );
}

function Metric({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-2xl bg-amber-50 p-4">
      <p className="text-xs uppercase tracking-[0.28em] text-amber-700">{label}</p>
      <p className="mt-2 text-3xl font-black text-slate-900">{value}</p>
    </div>
  );
}
