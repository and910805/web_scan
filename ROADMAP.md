# WeakScan Roadmap

This file tracks the next major product upgrades for WeakScan.

## Completed

- [x] Historical scan comparison
  Compare the latest completed scan against the previous completed scan for the same user, target URL, and scan type.
  Mark findings as `new` or `persistent`, and record `resolved` findings in the scan history summary.

## Completed (Continued)

- [x] API schema and attack surface analysis
  Parse exposed `openapi.json` or similar API documentation and enumerate endpoints, methods, and authentication requirements.

- [x] Scan trend dashboard
  Show new, resolved, and persistent findings over time in the frontend, not just inside raw API output and PDF reports.

- [x] Ignore rules and baseline management
  Allow users to suppress accepted risks and keep reports focused on meaningful regressions.

- [x] Scheduled rescans
  Add daily or weekly automatic scans for recurring monitoring.

- [x] Notification hooks
  Send email or webhook notifications when scans complete or risk levels change.

- [x] Finding deduplication and smarter risk scoring
  Group highly similar findings together and make severity weighting more consistent across exposed files, TLS, cookies, and disclosure issues.
