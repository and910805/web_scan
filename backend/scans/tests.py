from datetime import timedelta

from django.utils import timezone
from django.test import SimpleTestCase

from .models import IgnoreRule, ScheduledScan
from .scanner import (
    _analyze_api_schema,
    _analyze_robots,
    _analyze_sitemap,
    _calculate_risk_score,
    _deduplicate_issues,
    _format_probe_evidence,
    _inspect_cookie_security,
    _build_issue,
)
from .tasks import _apply_history_comparison, _apply_ignore_rules


class ScannerHelperTests(SimpleTestCase):
    def test_cookie_security_flags_missing_attributes(self):
        response = {
            "header_values": {
                "set-cookie": [
                    "sessionid=abc123; Path=/; HttpOnly",
                    "csrftoken=def456; Path=/",
                ]
            }
        }

        result = _inspect_cookie_security(response)

        self.assertEqual(len(result["cookies"]), 2)
        self.assertEqual(result["missing_secure"], ["csrftoken", "sessionid"])
        self.assertEqual(result["missing_httponly"], ["csrftoken"])
        self.assertEqual(result["missing_samesite"], ["csrftoken", "sessionid"])

    def test_robots_analysis_flags_sensitive_disallow_entries(self):
        common_files = [
            {
                "path": "/robots.txt",
                "status_code": 200,
                "body_preview": "User-agent: *\nDisallow: /admin\nDisallow: /private-api\n",
            }
        ]

        result = _analyze_robots(common_files, "https://example.com")

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["flagged_paths"], ["/admin", "/private-api"])

    def test_sitemap_analysis_flags_sensitive_urls(self):
        common_files = [
            {
                "path": "/sitemap.xml",
                "status_code": 200,
                "body_preview": (
                    "<urlset>"
                    "<url><loc>https://example.com/blog</loc></url>"
                    "<url><loc>https://example.com/staging/admin</loc></url>"
                    "</urlset>"
                ),
            }
        ]

        result = _analyze_sitemap(common_files, "https://example.com")

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["flagged_urls"], ["https://example.com/staging/admin"])

    def test_risk_score_uses_severity_weights(self):
        issues = [
            {"severity": "critical", "category": "sensitive_path"},
            {"severity": "high", "category": "tls"},
            {"severity": "medium", "category": "cookie_security"},
            {"severity": "low", "category": "information_disclosure"},
        ]

        self.assertEqual(_calculate_risk_score(issues), 98)

    def test_deduplication_merges_similar_robots_findings(self):
        issues = [
            {
                "category": "robots_disclosure",
                "severity": "low",
                "title": "robots.txt discloses sensitive path hints",
                "details": "robots.txt references /admin.",
                "evidence": "robots.txt preview: /admin",
                "recommendation": "Avoid listing sensitive paths.",
            },
            {
                "category": "robots_disclosure",
                "severity": "low",
                "title": "robots.txt discloses sensitive path hints",
                "details": "robots.txt references /private.",
                "evidence": "robots.txt preview: /private",
                "recommendation": "Avoid listing sensitive paths.",
            },
        ]

        result, stats = _deduplicate_issues(issues)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["occurrence_count"], 2)
        self.assertEqual(stats["merged_issue_count"], 1)
        self.assertIn("/admin", result[0]["evidence"])
        self.assertIn("/private", result[0]["evidence"])

    def test_public_login_page_is_low_risk_surface_not_sensitive_path(self):
        issue = _build_issue(
            category="exposed_surface",
            severity="low",
            title="Public attack surface discovered: /login",
            details="https://example.com/login is publicly reachable and should be reviewed as part of the exposed surface.",
            evidence=_format_probe_evidence(
                {
                    "status_code": 200,
                    "url": "https://example.com/login",
                    "content_type": "text/html",
                }
            ),
            recommendation="Ensure this public entry point has authentication, rate limits, and monitoring where appropriate.",
        )

        self.assertEqual(issue["category"], "exposed_surface")
        self.assertEqual(issue["severity"], "low")
        self.assertIn("/login", issue["title"])

    def test_api_schema_analysis_detects_public_and_sensitive_operations(self):
        original_fetch = _analyze_api_schema.__globals__["_fetch_schema_url"]

        def fake_fetch(base_url, path, headers):
            return {
                "path": path,
                "url": "https://example.com/openapi.json",
                "status_code": 200,
                "content_type": "application/json",
                "body_preview": (
                    '{"paths":{'
                    '"/health":{"get":{"summary":"health"}} ,'
                    '"/admin/users":{"get":{"security":[{"bearerAuth":[]}]}},'
                    '"/auth/login":{"post":{"summary":"login"}}'
                    "}}"
                ),
                "headers": {},
            }

        _analyze_api_schema.__globals__["_fetch_schema_url"] = fake_fetch
        try:
            result = _analyze_api_schema("https://example.com", {"User-Agent": "WeakScanBot/2.0"})
        finally:
            _analyze_api_schema.__globals__["_fetch_schema_url"] = original_fetch

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["path_count"], 3)
        self.assertEqual(result["public_endpoint_count"], 2)
        self.assertEqual(result["sensitive_endpoint_count"], 2)
        self.assertIn("GET /health", result["public_examples"])

    def test_history_comparison_marks_new_persistent_and_resolved(self):
        findings = {
            "summary": {"issue_count": 2},
            "issues": [
                {
                    "category": "tls",
                    "severity": "high",
                    "title": "TLS certificate expires soon",
                    "details": "Certificate expires in 10 days.",
                },
                {
                    "category": "cookie_security",
                    "severity": "medium",
                    "title": "Cookie missing HttpOnly attribute",
                    "details": "A session cookie is readable by client-side scripts.",
                },
            ],
        }
        previous_job = type(
            "PreviousJob",
            (),
            {
                "id": 7,
                "finished_at": None,
                "findings": {
                    "issues": [
                        {
                            "category": "tls",
                            "severity": "high",
                            "title": "TLS certificate expires soon",
                            "details": "Certificate expires in 10 days.",
                        },
                        {
                            "category": "information_disclosure",
                            "severity": "low",
                            "title": "Server banner exposed",
                            "details": "The application discloses the Server response header.",
                        },
                    ]
                },
            },
        )()

        result = _apply_history_comparison(findings, previous_job)

        self.assertEqual(result["summary"]["new_count"], 1)
        self.assertEqual(result["summary"]["persistent_count"], 1)
        self.assertEqual(result["summary"]["resolved_count"], 1)
        self.assertEqual(result["summary"]["compared_to_job_id"], 7)
        self.assertEqual(result["issues"][0]["history_status"], "persistent")
        self.assertEqual(result["issues"][1]["history_status"], "new")
        self.assertEqual(result["history"]["resolved_findings"][0]["title"], "Server banner exposed")

    def test_ignore_rule_suppresses_matching_issue(self):
        findings = {
            "summary": {"issue_count": 1},
            "issues": [
                {
                    "category": "security_headers",
                    "severity": "medium",
                    "title": "Missing Content-Security-Policy",
                }
            ],
        }
        rule = IgnoreRule(category="security_headers", active=True)
        scan_job = type("ScanJobStub", (), {"user": object(), "target_url": "https://example.com"})()

        original_filter = _apply_ignore_rules.__globals__["IgnoreRule"].objects.filter
        _apply_ignore_rules.__globals__["IgnoreRule"].objects.filter = lambda **kwargs: [rule]
        try:
            result = _apply_ignore_rules(findings, scan_job)
        finally:
            _apply_ignore_rules.__globals__["IgnoreRule"].objects.filter = original_filter

        self.assertEqual(result["summary"]["ignored_count"], 1)
        self.assertEqual(result["summary"]["issue_count"], 0)
        self.assertEqual(len(result["issues"]), 0)

    def test_scheduled_scan_next_run_uses_frequency(self):
        scheduled_scan = ScheduledScan(frequency=ScheduledScan.Frequency.WEEKLY)
        reference = timezone.now()

        scheduled_scan.schedule_next_run(reference=reference)

        self.assertEqual(scheduled_scan.next_run_at, reference + timedelta(days=7))
