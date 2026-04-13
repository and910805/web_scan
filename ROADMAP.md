# WeakScan Roadmap

This file tracks the next major product upgrades for WeakScan.

## Completed

- [x] Historical scan comparison
  Compare the latest completed scan against the previous completed scan for the same user, target URL, and scan type.
  Mark findings as `new` or `persistent`, and record `resolved` findings in the scan history summary.

## In Progress

- [ ] Finding deduplication and smarter risk scoring
  Group highly similar findings together and make severity weighting more consistent across exposed files, TLS, cookies, and disclosure issues.

## Planned

- [ ] API schema and attack surface analysis
  Parse exposed `openapi.json` or similar API documentation and enumerate endpoints, methods, and authentication requirements.

- [ ] Scan trend dashboard
  Show new, resolved, and persistent findings over time in the frontend, not just inside raw API output and PDF reports.

- [ ] Ignore rules and baseline management
  Allow users to suppress accepted risks and keep reports focused on meaningful regressions.

- [ ] Scheduled rescans
  Add daily or weekly automatic scans for recurring monitoring.

- [ ] Notification hooks
  Send email or webhook notifications when scans complete or risk levels change.
