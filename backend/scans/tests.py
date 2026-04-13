from django.test import SimpleTestCase

from .scanner import _analyze_robots, _analyze_sitemap, _calculate_risk_score, _inspect_cookie_security


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
            {"severity": "critical"},
            {"severity": "high"},
            {"severity": "medium"},
            {"severity": "low"},
        ]

        self.assertEqual(_calculate_risk_score(issues), 71)
