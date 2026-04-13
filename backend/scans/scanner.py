import re
import socket
import ssl
import time
import json
from http.cookies import SimpleCookie
from urllib import error, parse, request


DEFAULT_TIMEOUT = 12
DEFAULT_USER_AGENT = "WeakScanBot/2.0"
COMMON_API_PATHS = (
    "/api",
    "/api/v1",
    "/api/docs",
    "/swagger",
    "/openapi.json",
    "/graphql",
)
SENSITIVE_PATHS = (
    "/.env",
    "/.env.local",
    "/.git/config",
    "/.git/HEAD",
    "/.svn/entries",
    "/.DS_Store",
    "/backup.zip",
    "/backup.tar.gz",
    "/server-status",
    "/phpinfo.php",
)
EXPOSED_SURFACE_PATHS = (
    "/admin",
    "/login",
)
COMMON_DISCOVERY_PATHS = (
    "/robots.txt",
    "/sitemap.xml",
)
REQUIRED_SECURITY_HEADERS = (
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
)
DANGEROUS_HTTP_METHODS = {"TRACE", "PUT", "DELETE", "CONNECT"}
SENSITIVE_HINTS = (
    "admin",
    "backup",
    "config",
    "console",
    "debug",
    "internal",
    "login",
    "manage",
    "phpmyadmin",
    "private",
    "staging",
    "test",
)
ERROR_DISCLOSURE_PATTERNS = (
    "traceback",
    "stack trace",
    "django",
    "exception",
    "sqlstate",
    "syntax error",
    "referenceerror",
    "typeerror",
    "fatal error",
)
SEVERITY_WEIGHTS = {
    "critical": 40,
    "high": 20,
    "medium": 8,
    "low": 3,
}
CATEGORY_RISK_BONUS = {
    "sensitive_path": 12,
    "exposed_surface": 2,
    "tls": 8,
    "api_schema": 4,
    "http_methods": 7,
    "cookie_security": 5,
    "transport_security": 6,
    "error_disclosure": 5,
    "api_surface": 4,
    "security_headers": 3,
    "information_disclosure": 2,
    "robots_disclosure": 1,
    "sitemap_disclosure": 1,
    "cors": 4,
}


class _NoRedirectHandler(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def run_target_scan(scan_type: str, target_url: str) -> dict:
    parsed = parse.urlparse(target_url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only http and https URLs are supported.")

    normalized_url = parsed.geturl()
    base_headers = {"User-Agent": DEFAULT_USER_AGENT}

    homepage = _request(normalized_url, headers=base_headers)
    tls_details = _inspect_tls(parsed)
    security_headers = _inspect_security_headers(homepage)
    sensitive_paths = [_probe_path(normalized_url, path, base_headers) for path in SENSITIVE_PATHS]
    exposed_surface_paths = [_probe_path(normalized_url, path, base_headers) for path in EXPOSED_SURFACE_PATHS]
    api_paths = [_probe_path(normalized_url, path, base_headers, method="OPTIONS") for path in COMMON_API_PATHS]
    api_schema_analysis = _analyze_api_schema(normalized_url, base_headers)
    common_files = [_probe_path(normalized_url, path, base_headers) for path in COMMON_DISCOVERY_PATHS]
    cookie_assessment = _inspect_cookie_security(homepage)
    http_methods = _inspect_http_methods(normalized_url, base_headers)
    https_redirect = _check_https_redirect(parsed, base_headers)
    error_disclosure = _inspect_error_disclosure(normalized_url, base_headers)
    metadata_exposure = _inspect_metadata_headers(homepage)
    robots_analysis = _analyze_robots(common_files, normalized_url)
    sitemap_analysis = _analyze_sitemap(common_files, normalized_url)

    if scan_type == "api":
        cors_check = _inspect_cors(homepage)
        unauthenticated_paths = [item for item in api_paths if item["status_code"] in {200, 204, 401, 403}]
    else:
        cors_check = None
        unauthenticated_paths = []

    issues = []
    for header in security_headers["missing"]:
        severity = "medium" if header in {"Content-Security-Policy", "Strict-Transport-Security"} else "low"
        issues.append(
            _build_issue(
                category="security_headers",
                severity=severity,
                title=f"Missing {header}",
                details=f"The response from {normalized_url} does not include {header}.",
                evidence=f"Observed response headers: {', '.join(sorted(homepage['headers'].keys())) or 'none'}",
                recommendation=f"Add the {header} header at the reverse proxy or application layer.",
            )
        )

    if tls_details.get("status") == "ok":
        if tls_details.get("days_remaining", 0) < 0:
            issues.append(
                _build_issue(
                    category="tls",
                    severity="critical",
                    title="TLS certificate has expired",
                    details=f"Certificate expired {abs(tls_details['days_remaining'])} days ago.",
                    evidence=f"Certificate notAfter: {tls_details.get('not_after', 'unknown')}",
                    recommendation="Renew the certificate immediately and reload the HTTPS endpoint.",
                )
            )
        elif tls_details.get("days_remaining", 0) < 14:
            issues.append(
                _build_issue(
                    category="tls",
                    severity="high",
                    title="TLS certificate expires soon",
                    details=f"Certificate expires in {tls_details['days_remaining']} days.",
                    evidence=f"Certificate notAfter: {tls_details.get('not_after', 'unknown')}",
                    recommendation="Renew the certificate before it expires to avoid service disruption.",
                )
            )

        if tls_details.get("tls_version") in {"TLSv1", "TLSv1.1"}:
            issues.append(
                _build_issue(
                    category="tls",
                    severity="high",
                    title="Legacy TLS version negotiated",
                    details=f"The server negotiated {tls_details['tls_version']}.",
                    evidence=f"Negotiated protocol: {tls_details['tls_version']}",
                    recommendation="Disable TLS 1.0/1.1 and allow only TLS 1.2 or newer.",
                )
            )

    if tls_details.get("status") not in {"ok", "not_applicable"}:
        issues.append(
            _build_issue(
                category="tls",
                severity="high",
                title="TLS inspection failed",
                details=tls_details.get("message", "TLS handshake could not be completed."),
                evidence=f"TLS status: {tls_details.get('status', 'error')}",
                recommendation="Verify the certificate chain, hostname, and TLS listener configuration.",
            )
        )

    for item in sensitive_paths:
        if item["status_code"] in {200, 206}:
            issues.append(
                _build_issue(
                    category="sensitive_path",
                    severity="critical",
                    title=f"Sensitive path exposed: {item['path']}",
                    details=f"{item['url']} returned HTTP {item['status_code']}.",
                    evidence=_format_probe_evidence(item),
                    recommendation="Restrict public access to this path and remove sensitive files from the web root.",
                )
            )

    for item in exposed_surface_paths:
        if item["status_code"] == 200:
            issues.append(
                _build_issue(
                    category="exposed_surface",
                    severity="low",
                    title=f"Public attack surface discovered: {item['path']}",
                    details=f"{item['url']} is publicly reachable and should be reviewed as part of the exposed surface.",
                    evidence=_format_probe_evidence(item),
                    recommendation="Ensure this public entry point has authentication, rate limits, and monitoring where appropriate.",
                )
            )

    for item in api_paths:
        if item["path"] in {"/openapi.json", "/swagger", "/api/docs"} and item["status_code"] == 200:
            issues.append(
                _build_issue(
                    category="api_surface",
                    severity="medium",
                    title=f"Public API documentation exposed: {item['path']}",
                    details=f"{item['url']} returned HTTP 200.",
                    evidence=_format_probe_evidence(item),
                    recommendation="Restrict interactive API docs to authenticated or internal users only.",
                )
            )

    if api_schema_analysis["status"] == "ok":
        if api_schema_analysis["public_endpoint_count"] > 0:
            issues.append(
                _build_issue(
                    category="api_schema",
                    severity="medium",
                    title="API schema exposes public endpoints",
                    details=(
                        f"Schema analysis found {api_schema_analysis['path_count']} paths and "
                        f"{api_schema_analysis['public_endpoint_count']} operations without obvious security requirements."
                    ),
                    evidence=(
                        f"Schema URL: {api_schema_analysis['url']} | "
                        f"Example public operations: {', '.join(api_schema_analysis['public_examples']) or 'none'}"
                    ),
                    recommendation="Review exposed endpoints and add authentication or authorization requirements where needed.",
                )
            )
        if api_schema_analysis["sensitive_endpoint_count"] > 0:
            issues.append(
                _build_issue(
                    category="api_schema",
                    severity="low",
                    title="API schema lists sensitive-looking endpoints",
                    details=(
                        f"The published schema includes {api_schema_analysis['sensitive_endpoint_count']} "
                        "endpoints with admin, internal, or auth-related naming."
                    ),
                    evidence=(
                        f"Examples: {', '.join(api_schema_analysis['sensitive_examples']) or 'none'}"
                    ),
                    recommendation="Confirm that sensitive API routes are protected and intentionally documented.",
                )
            )

    if cors_check and cors_check["allow_origin"] == "*":
        issues.append(
            _build_issue(
                category="cors",
                severity="medium",
                title="Wildcard CORS policy detected",
                details="Access-Control-Allow-Origin is set to '*'.",
                evidence=f"Allow-Origin: {cors_check['allow_origin']}",
                recommendation="Replace the wildcard with an allowlist of trusted front-end origins.",
            )
        )

    if cookie_assessment["cookies"]:
        if cookie_assessment["missing_secure"]:
            issues.append(
                _build_issue(
                    category="cookie_security",
                    severity="medium",
                    title="Cookie missing Secure attribute",
                    details="One or more cookies can be transmitted without the Secure flag.",
                    evidence=f"Affected cookies: {', '.join(cookie_assessment['missing_secure'])}",
                    recommendation="Set the Secure attribute on cookies that should only travel over HTTPS.",
                )
            )
        if cookie_assessment["missing_httponly"]:
            issues.append(
                _build_issue(
                    category="cookie_security",
                    severity="medium",
                    title="Cookie missing HttpOnly attribute",
                    details="One or more cookies are accessible to browser-side scripts.",
                    evidence=f"Affected cookies: {', '.join(cookie_assessment['missing_httponly'])}",
                    recommendation="Set HttpOnly on session and authentication cookies to reduce XSS impact.",
                )
            )
        if cookie_assessment["missing_samesite"]:
            issues.append(
                _build_issue(
                    category="cookie_security",
                    severity="low",
                    title="Cookie missing SameSite attribute",
                    details="One or more cookies do not declare a SameSite policy.",
                    evidence=f"Affected cookies: {', '.join(cookie_assessment['missing_samesite'])}",
                    recommendation="Set SameSite=Lax or SameSite=Strict unless cross-site behavior is required.",
                )
            )

    if metadata_exposure["server"]:
        issues.append(
            _build_issue(
                category="information_disclosure",
                severity="low",
                title="Server banner exposed",
                details="The application discloses the Server response header.",
                evidence=f"Server: {metadata_exposure['server']}",
                recommendation="Remove or normalize the Server header at the web server or CDN layer.",
            )
        )
    if metadata_exposure["x_powered_by"]:
        issues.append(
            _build_issue(
                category="information_disclosure",
                severity="low",
                title="Technology banner exposed",
                details="The application discloses the X-Powered-By response header.",
                evidence=f"X-Powered-By: {metadata_exposure['x_powered_by']}",
                recommendation="Remove X-Powered-By to reduce unnecessary stack disclosure.",
            )
        )

    if http_methods["dangerous_methods"]:
        dangerous = ", ".join(http_methods["dangerous_methods"])
        severity = "high" if "TRACE" in http_methods["dangerous_methods"] else "medium"
        issues.append(
            _build_issue(
                category="http_methods",
                severity=severity,
                title="Potentially dangerous HTTP methods allowed",
                details=f"The target appears to allow these methods: {dangerous}.",
                evidence=f"Allow header: {http_methods.get('allow_header', '') or 'not provided'}",
                recommendation="Disable unused methods such as TRACE, PUT, DELETE, and CONNECT on public endpoints.",
            )
        )

    if https_redirect.get("status") == "ok" and not https_redirect.get("redirects_to_https", True):
        issues.append(
            _build_issue(
                category="transport_security",
                severity="medium",
                title="HTTP does not force redirect to HTTPS",
                details="A plaintext HTTP request did not redirect to an HTTPS URL.",
                evidence=f"Observed HTTP status {https_redirect.get('status_code')} with Location {https_redirect.get('location') or 'none'}",
                recommendation="Redirect all HTTP traffic to HTTPS at the edge or load balancer.",
            )
        )

    if error_disclosure.get("detected"):
        issues.append(
            _build_issue(
                category="error_disclosure",
                severity="medium",
                title="Verbose error response detected",
                details="The application returned an error page with framework or stack-trace hints.",
                evidence=f"Matched pattern '{error_disclosure['matched_pattern']}' at {error_disclosure['url']}",
                recommendation="Return generic error pages and disable debug-style exception output in production.",
            )
        )

    for flagged_path in robots_analysis["flagged_paths"]:
        issues.append(
            _build_issue(
                category="robots_disclosure",
                severity="low",
                title="robots.txt discloses sensitive path hints",
                details=f"robots.txt references {flagged_path}.",
                evidence=f"robots.txt preview: {robots_analysis['preview']}",
                recommendation="Avoid listing highly sensitive administrative or backup paths in robots.txt.",
            )
        )

    for flagged_url in sitemap_analysis["flagged_urls"]:
        issues.append(
            _build_issue(
                category="sitemap_disclosure",
                severity="low",
                title="sitemap.xml lists potentially sensitive URL",
                details=f"sitemap.xml includes {flagged_url}.",
                evidence=f"sitemap.xml preview: {sitemap_analysis['preview']}",
                recommendation="Remove sensitive, internal, or staging URLs from public sitemap.xml output.",
            )
        )

    issues, deduplication = _deduplicate_issues(issues)

    summary = {
        "scan_type": scan_type,
        "target_url": normalized_url,
        "issue_count": len(issues),
        "raw_issue_count": deduplication["raw_issue_count"],
        "deduplicated_issue_count": deduplication["merged_issue_count"],
        "critical_count": len([item for item in issues if item["severity"] == "critical"]),
        "high_count": len([item for item in issues if item["severity"] == "high"]),
        "medium_count": len([item for item in issues if item["severity"] == "medium"]),
        "low_count": len([item for item in issues if item["severity"] == "low"]),
        "http_status": homepage["status_code"],
        "risk_score": _calculate_risk_score(issues),
    }

    return {
        "summary": summary,
        "target": {
            "url": normalized_url,
            "scan_type": scan_type,
            "resolved_ip": _resolve_ip(parsed.hostname),
        },
        "http": {
            "status_code": homepage["status_code"],
            "headers": homepage["headers"],
            "server": metadata_exposure["server"],
            "x_powered_by": metadata_exposure["x_powered_by"],
            "content_type": _header_value(homepage, "Content-Type"),
            "final_url": homepage["final_url"],
        },
        "tls": tls_details,
        "security_headers": security_headers,
        "common_files": common_files,
        "sensitive_paths": sensitive_paths,
        "exposed_surface_paths": exposed_surface_paths,
        "api_paths": api_paths,
        "api_schema_analysis": api_schema_analysis,
        "cookie_security": cookie_assessment,
        "http_methods": http_methods,
        "https_redirect": https_redirect,
        "error_disclosure": error_disclosure,
        "robots_analysis": robots_analysis,
        "sitemap_analysis": sitemap_analysis,
        "deduplication": deduplication,
        "cors": cors_check,
        "unauthenticated_paths": unauthenticated_paths,
        "issues": issues,
    }


def _request(url: str, headers: dict[str, str], method: str = "GET", follow_redirects: bool = True) -> dict:
    req = request.Request(url, headers=headers, method=method)
    opener = request.build_opener() if follow_redirects else request.build_opener(_NoRedirectHandler())
    try:
        with opener.open(req, timeout=DEFAULT_TIMEOUT) as response:
            body = response.read(4096)
            return _build_response(
                status_code=response.getcode(),
                headers=response.headers,
                body=body,
                final_url=response.geturl(),
            )
    except error.HTTPError as exc:
        body = exc.read(2048) if exc.fp else b""
        return _build_response(
            status_code=exc.code,
            headers=exc.headers,
            body=body,
            final_url=exc.geturl(),
        )


def _build_response(status_code: int, headers, body: bytes, final_url: str) -> dict:
    header_values = {}
    simple_headers = {}
    for key in headers.keys():
        values = headers.get_all(key) or [headers.get(key)]
        header_values[key.lower()] = values
        if key not in simple_headers:
            simple_headers[key] = values[0]

    return {
        "status_code": status_code,
        "headers": simple_headers,
        "header_values": header_values,
        "body_preview": body.decode("utf-8", errors="replace"),
        "final_url": final_url,
    }


def _probe_path(base_url: str, path: str, headers: dict[str, str], method: str = "GET") -> dict:
    url = parse.urljoin(_ensure_trailing_slash(base_url), path.lstrip("/"))
    try:
        response = _request(url, headers=headers, method=method)
        return {
            "path": path,
            "url": url,
            "status_code": response["status_code"],
            "content_type": _header_value(response, "Content-Type"),
            "body_preview": response["body_preview"],
            "headers": response["headers"],
        }
    except Exception as exc:
        return {
            "path": path,
            "url": url,
            "status_code": 0,
            "error": str(exc),
            "body_preview": "",
            "headers": {},
        }


def _fetch_schema_url(base_url: str, path: str, headers: dict[str, str]) -> dict:
    url = parse.urljoin(_ensure_trailing_slash(base_url), path.lstrip("/"))
    try:
        response = _request(url, headers=headers, method="GET")
        return {
            "path": path,
            "url": url,
            "status_code": response["status_code"],
            "content_type": _header_value(response, "Content-Type"),
            "body_preview": response["body_preview"],
            "headers": response["headers"],
        }
    except Exception as exc:
        return {
            "path": path,
            "url": url,
            "status_code": 0,
            "error": str(exc),
            "body_preview": "",
            "headers": {},
        }


def _inspect_security_headers(response: dict) -> dict:
    headers = response["headers"]
    present = [header for header in REQUIRED_SECURITY_HEADERS if header in headers]
    missing = [header for header in REQUIRED_SECURITY_HEADERS if header not in headers]
    return {"present": present, "missing": missing}


def _inspect_cors(response: dict) -> dict:
    return {
        "allow_origin": _header_value(response, "Access-Control-Allow-Origin"),
        "allow_methods": _header_value(response, "Access-Control-Allow-Methods"),
        "allow_headers": _header_value(response, "Access-Control-Allow-Headers"),
    }


def _inspect_tls(parsed_url: parse.ParseResult) -> dict:
    if parsed_url.scheme != "https":
        return {"status": "not_applicable", "message": "Target does not use HTTPS."}

    hostname = parsed_url.hostname
    port = parsed_url.port or 443
    if not hostname:
        return {"status": "error", "message": "Hostname is missing."}

    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=DEFAULT_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as wrapped:
                cert = wrapped.getpeercert()
                tls_version = wrapped.version()
                cipher = wrapped.cipher()
        expires_at = ssl.cert_time_to_seconds(cert["notAfter"])
        days_remaining = int((expires_at - time.time()) / 86400)
        return {
            "status": "ok",
            "issuer": dict(item[0] for item in cert.get("issuer", [])),
            "subject": dict(item[0] for item in cert.get("subject", [])),
            "not_after": cert["notAfter"],
            "days_remaining": days_remaining,
            "tls_version": tls_version,
            "cipher": cipher[0] if cipher else "",
        }
    except Exception as exc:
        return {"status": "error", "message": str(exc)}


def _inspect_cookie_security(response: dict) -> dict:
    cookies = []
    missing_secure = []
    missing_httponly = []
    missing_samesite = []

    for raw_cookie in _header_values(response, "Set-Cookie"):
        jar = SimpleCookie()
        try:
            jar.load(raw_cookie)
        except Exception:
            continue

        for name, morsel in jar.items():
            cookie_data = {
                "name": name,
                "secure": bool(morsel["secure"]),
                "httponly": bool(morsel["httponly"]),
                "samesite": morsel["samesite"] or "",
            }
            cookies.append(cookie_data)
            if not cookie_data["secure"]:
                missing_secure.append(name)
            if not cookie_data["httponly"]:
                missing_httponly.append(name)
            if not cookie_data["samesite"]:
                missing_samesite.append(name)

    return {
        "cookies": cookies,
        "missing_secure": sorted(set(missing_secure)),
        "missing_httponly": sorted(set(missing_httponly)),
        "missing_samesite": sorted(set(missing_samesite)),
    }


def _inspect_metadata_headers(response: dict) -> dict:
    return {
        "server": _header_value(response, "Server"),
        "x_powered_by": _header_value(response, "X-Powered-By"),
    }


def _inspect_http_methods(base_url: str, headers: dict[str, str]) -> dict:
    try:
        response = _request(base_url, headers=headers, method="OPTIONS")
    except Exception as exc:
        return {"status": "error", "message": str(exc), "allowed_methods": [], "dangerous_methods": []}

    advertised = set()
    for raw_value in (
        _header_value(response, "Allow"),
        _header_value(response, "Access-Control-Allow-Methods"),
    ):
        if raw_value:
            advertised.update(part.strip().upper() for part in raw_value.split(",") if part.strip())

    dangerous = sorted(method for method in advertised if method in DANGEROUS_HTTP_METHODS)
    return {
        "status": "ok",
        "status_code": response["status_code"],
        "allowed_methods": sorted(advertised),
        "dangerous_methods": dangerous,
        "allow_header": _header_value(response, "Allow"),
    }


def _check_https_redirect(parsed_url: parse.ParseResult, headers: dict[str, str]) -> dict:
    hostname = parsed_url.hostname
    if not hostname:
        return {"status": "error", "message": "Hostname is missing."}

    if parsed_url.scheme == "https" and parsed_url.port not in {None, 443}:
        return {
            "status": "not_applicable",
            "message": "HTTPS redirect probe skipped for a non-standard HTTPS port.",
        }

    http_netloc = hostname
    if parsed_url.scheme == "http" and parsed_url.port not in {None, 80}:
        http_netloc = f"{hostname}:{parsed_url.port}"
    http_url = parse.urlunparse(parsed_url._replace(scheme="http", netloc=http_netloc))

    try:
        response = _request(http_url, headers=headers, follow_redirects=False)
    except Exception as exc:
        return {"status": "error", "message": str(exc), "url": http_url}

    location = _header_value(response, "Location")
    return {
        "status": "ok",
        "url": http_url,
        "status_code": response["status_code"],
        "location": location,
        "redirects_to_https": response["status_code"] in {301, 302, 307, 308} and location.startswith("https://"),
    }


def _inspect_error_disclosure(base_url: str, headers: dict[str, str]) -> dict:
    probe_path = "/__weakscan_probe__?source=weakscan"
    probe = _probe_path(base_url, probe_path, headers)
    body = probe.get("body_preview", "").lower()

    for pattern in ERROR_DISCLOSURE_PATTERNS:
        if pattern in body:
            return {
                "detected": True,
                "matched_pattern": pattern,
                "url": probe["url"],
                "status_code": probe["status_code"],
            }

    return {
        "detected": False,
        "matched_pattern": "",
        "url": probe["url"],
        "status_code": probe["status_code"],
    }


def _analyze_robots(common_files: list[dict], base_url: str) -> dict:
    robots = next((item for item in common_files if item["path"] == "/robots.txt"), None)
    if not robots or robots["status_code"] != 200:
        return {"status": "not_found", "flagged_paths": [], "preview": ""}

    flagged_paths = []
    for line in robots.get("body_preview", "").splitlines():
        stripped = line.strip()
        if not stripped.lower().startswith("disallow:"):
            continue
        path = stripped.split(":", 1)[1].strip()
        if _contains_sensitive_hint(path):
            flagged_paths.append(path)

    return {
        "status": "ok",
        "flagged_paths": flagged_paths[:5],
        "preview": _preview_text(robots.get("body_preview", "")),
        "url": parse.urljoin(_ensure_trailing_slash(base_url), "robots.txt"),
    }


def _analyze_sitemap(common_files: list[dict], base_url: str) -> dict:
    sitemap = next((item for item in common_files if item["path"] == "/sitemap.xml"), None)
    if not sitemap or sitemap["status_code"] != 200:
        return {"status": "not_found", "flagged_urls": [], "preview": ""}

    flagged_urls = []
    for loc in re.findall(r"<loc>(.*?)</loc>", sitemap.get("body_preview", ""), flags=re.IGNORECASE):
        if _contains_sensitive_hint(loc):
            flagged_urls.append(loc.strip())

    return {
        "status": "ok",
        "flagged_urls": flagged_urls[:5],
        "preview": _preview_text(sitemap.get("body_preview", "")),
        "url": parse.urljoin(_ensure_trailing_slash(base_url), "sitemap.xml"),
    }


def _analyze_api_schema(base_url: str, headers: dict[str, str]) -> dict:
    for path in ("/openapi.json", "/swagger.json"):
        candidate = _fetch_schema_url(base_url, path, headers)
        if candidate["status_code"] != 200:
            continue

        try:
            schema = json.loads(candidate["body_preview"])
        except json.JSONDecodeError:
            continue

        paths = schema.get("paths", {}) if isinstance(schema, dict) else {}
        if not isinstance(paths, dict):
            continue

        operations = []
        public_examples = []
        sensitive_examples = []

        for route, route_definition in paths.items():
            if not isinstance(route_definition, dict):
                continue

            for method, operation in route_definition.items():
                if method.lower() not in {"get", "post", "put", "patch", "delete", "options", "head"}:
                    continue
                if not isinstance(operation, dict):
                    continue

                security = operation.get("security", route_definition.get("security", schema.get("security", [])))
                operation_key = f"{method.upper()} {route}"
                operations.append(
                    {
                        "operation": operation_key,
                        "has_security": bool(security),
                    }
                )

                if not security and len(public_examples) < 5:
                    public_examples.append(operation_key)
                if _contains_sensitive_hint(route) and len(sensitive_examples) < 5:
                    sensitive_examples.append(operation_key)

        return {
            "status": "ok",
            "url": candidate["url"],
            "path_count": len(paths),
            "operation_count": len(operations),
            "public_endpoint_count": len([item for item in operations if not item["has_security"]]),
            "sensitive_endpoint_count": len({item for item in sensitive_examples}),
            "public_examples": public_examples,
            "sensitive_examples": sensitive_examples,
        }

    return {
        "status": "not_found",
        "url": "",
        "path_count": 0,
        "operation_count": 0,
        "public_endpoint_count": 0,
        "sensitive_endpoint_count": 0,
        "public_examples": [],
        "sensitive_examples": [],
    }


def _build_issue(category: str, severity: str, title: str, details: str, evidence: str, recommendation: str) -> dict:
    return {
        "category": category,
        "severity": severity,
        "title": title,
        "details": details,
        "evidence": evidence,
        "recommendation": recommendation,
    }


def _calculate_risk_score(issues: list[dict]) -> int:
    total = 0
    for issue in issues:
        severity = issue.get("severity", "")
        category = issue.get("category", "")
        occurrences = int(issue.get("occurrence_count", 1) or 1)
        base = SEVERITY_WEIGHTS.get(severity, 0)
        bonus = CATEGORY_RISK_BONUS.get(category, 0)
        total += base + bonus + min(max(occurrences - 1, 0), 4)
    return min(total, 100)


def _deduplicate_issues(issues: list[dict]) -> tuple[list[dict], dict]:
    deduped: dict[str, dict] = {}
    merged_issue_count = 0

    for issue in issues:
        key = _issue_dedup_key(issue)
        existing = deduped.get(key)
        if not existing:
            normalized = dict(issue)
            normalized["occurrence_count"] = 1
            normalized["evidence_items"] = [issue.get("evidence", "")]
            deduped[key] = normalized
            continue

        merged_issue_count += 1
        existing["occurrence_count"] += 1
        if issue.get("evidence"):
            evidence_items = existing.setdefault("evidence_items", [])
            if issue["evidence"] not in evidence_items:
                evidence_items.append(issue["evidence"])

        existing["severity"] = _max_severity(existing.get("severity", "low"), issue.get("severity", "low"))
        existing["details"] = _merge_text(existing.get("details", ""), issue.get("details", ""))
        existing["recommendation"] = _merge_text(existing.get("recommendation", ""), issue.get("recommendation", ""))
        existing["evidence"] = " | ".join(existing.get("evidence_items", [])[:4])

    deduped_issues = list(deduped.values())
    return deduped_issues, {
        "raw_issue_count": len(issues),
        "merged_issue_count": merged_issue_count,
        "unique_issue_count": len(deduped_issues),
    }


def _issue_dedup_key(issue: dict) -> str:
    title = str(issue.get("title", "")).strip().lower()
    category = str(issue.get("category", "")).strip().lower()

    if title.startswith("robots.txt discloses sensitive path hints"):
        return f"{category}|robots_disclosure"
    if title.startswith("sitemap.xml lists potentially sensitive url"):
        return f"{category}|sitemap_disclosure"

    return "|".join([category, title, str(issue.get("recommendation", "")).strip().lower()])


def _max_severity(left: str, right: str) -> str:
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    return left if order.get(left, 0) >= order.get(right, 0) else right


def _merge_text(left: str, right: str) -> str:
    if not left:
        return right
    if not right or right == left:
        return left
    return f"{left} Also observed: {right}"


def _format_probe_evidence(item: dict) -> str:
    content_type = item.get("content_type") or "unknown"
    return f"HTTP {item.get('status_code', 0)} at {item.get('url', '')} (Content-Type: {content_type})"


def _contains_sensitive_hint(value: str) -> bool:
    lowered = value.lower()
    return any(hint in lowered for hint in SENSITIVE_HINTS)


def _preview_text(value: str, limit: int = 180) -> str:
    compact = " ".join(value.split())
    if len(compact) <= limit:
        return compact
    return f"{compact[: limit - 3]}..."


def _header_value(response: dict, name: str) -> str:
    values = _header_values(response, name)
    return values[0] if values else ""


def _header_values(response: dict, name: str) -> list[str]:
    return response.get("header_values", {}).get(name.lower(), [])


def _resolve_ip(hostname: str | None) -> str:
    if not hostname:
        return ""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return ""


def _ensure_trailing_slash(url: str) -> str:
    parsed_url = parse.urlparse(url)
    path = parsed_url.path or "/"
    if not path.endswith("/"):
        path = f"{path}/"
    return parse.urlunparse(parsed_url._replace(path=path))
