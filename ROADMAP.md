# WeakScan Roadmap

This file tracks the next major product upgrades for WeakScan.

## Product Goal

WeakScan is moving from a feature-complete prototype into a usable security scanning product.

The next roadmap should focus on:

- making the platform stable for real users
- improving scan depth and signal quality
- making reports and results easier to act on
- preparing billing, team usage, and production operations

## Current Status

Already implemented:

- [x] Historical scan comparison
- [x] API schema and attack surface analysis
- [x] Scan trend dashboard
- [x] Ignore rules and baseline management
- [x] Scheduled rescans
- [x] Notification hooks
- [x] Finding deduplication and smarter risk scoring

## Phase 1: Product Stabilization

Priority: highest

- [x] Full authentication cleanup
  Remove all remaining manual JWT UX, tighten session/token flows, and make login/register/Google login fully stable.

- [x] User profile sync and credit consistency
  Refresh user credit balances and account state from the backend instead of relying on stale frontend storage.

- [x] Report download reliability
  Ensure PDF generation, storage, and download work consistently across web/worker deployments.

- [x] Scan job reliability improvements
  Add better retry handling, clearer task failures, timeout visibility, and worker-side error classification.

- [x] Deployment hardening
  Finalize Zeabur-ready service configuration, health checks, static/media strategy, and environment validation.

## Phase 2: Better Scanning Coverage

Priority: high

- [x] OWASP ZAP integration
  Add an advanced scan mode for deeper DAST checks beyond the current baseline probes.

- [x] API Top 10 baseline checks
  Expand API analysis for auth weaknesses, excessive exposure, unsafe methods, weak CORS, and documentation leaks.

- [x] JavaScript asset inspection
  Crawl frontend bundles and inspect exposed routes, leaked keys, public configs, and hidden API endpoints.

- [x] Login-aware scanning
  Support authenticated target scans using supplied cookies, headers, or test accounts.

- [x] Smarter crawling and surface discovery
  Improve discovery of paths, forms, linked assets, and application entry points before scanning.

## Phase 3: Reporting and Analyst Workflow

Priority: high

- [ ] Finding detail pages
  Give each finding a dedicated view with evidence, history, first seen, last seen, and remediation guidance.

- [ ] Better PDF and export suite
  Add executive summary mode, analyst appendix, CSV export, JSON export, and customer-branded reports.

- [ ] Remediation guidance library
  Add structured fix suggestions for headers, TLS, CORS, exposed files, and API misconfiguration issues.

- [ ] Evidence retention and screenshots
  Save response previews, headers, selected artifacts, and optionally screenshots for important findings.

- [ ] Multi-scan diff UX
  Make it easy to compare two scan runs side by side in the frontend.

## Phase 4: Account, Billing, and Teams

Priority: medium

- [ ] Credit top-up flow
  Finish ECPay integration and make purchases automatically increase credits.

- [ ] Subscription and usage plans
  Add monthly quotas, recurring plans, and per-feature entitlements.

- [ ] Team workspaces
  Support multiple users under one organization with shared scans, permissions, and billing.

- [ ] Audit log
  Record important actions such as sign-ins, credit changes, scan creation, ignore rules, and webhook edits.

- [ ] Role-based access control
  Add owner, admin, analyst, and viewer roles.

## Phase 5: Platform Operations

Priority: medium

- [ ] Metrics and observability
  Add structured logs, task metrics, scan latency, queue depth, error rate, and webhook delivery tracking.

- [ ] Security hardening
  Add rate limiting, brute-force protection, request validation, secret rotation guidance, and admin lock-down.

- [ ] Data retention policy
  Add configurable cleanup for old reports, scan evidence, notifications, and expired scheduled jobs.

- [ ] Background maintenance jobs
  Add recurring cleanup, retry, notification repair, and stale task recovery commands.

- [ ] Backup and restore strategy
  Define database backup, report retention, and service recovery steps.

## Phase 6: Longer-Term Expansion

Priority: lower

- [ ] Source-code scanning mode
  Add ZIP or repo-based static analysis for secrets, misconfigurations, and code-level weaknesses.

- [ ] Plugin scanner architecture
  Allow new check modules to be added without rewriting the core scanner flow.

- [ ] Risk scoring engine v2
  Weight findings using exploitability, exposure, recurrence, and asset criticality.

- [ ] Customer-facing portal
  Let end users or clients view reports, trends, and remediation status directly.

- [ ] Asset inventory and continuous monitoring
  Move from one-off scan jobs toward persistent monitored assets and recurring posture tracking.

## Suggested Execution Order

If building in strict order, the recommended sequence is:

1. Phase 1: Product Stabilization
2. Phase 2: Better Scanning Coverage
3. Phase 3: Reporting and Analyst Workflow
4. Phase 4: Account, Billing, and Teams
5. Phase 5: Platform Operations
6. Phase 6: Longer-Term Expansion

## Best Next Milestone

If only one milestone should be started next, use this:

- [ ] Milestone A: Stable private beta
  Finish auth cleanup, report reliability, deployment hardening, and scan failure handling so real users can use the product without manual intervention.
