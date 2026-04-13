import socket
import ssl
import time
from urllib import error, parse, request


DEFAULT_TIMEOUT = 12
DEFAULT_USER_AGENT = "WeakScanBot/1.0"
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
    "/.git/config",
    "/backup.zip",
    "/server-status",
    "/phpinfo.php",
)
REQUIRED_SECURITY_HEADERS = (
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
)


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
    api_paths = [_probe_path(normalized_url, path, base_headers, method="OPTIONS") for path in COMMON_API_PATHS]
    common_files = [
        _probe_path(normalized_url, "/robots.txt", base_headers),
        _probe_path(normalized_url, "/sitemap.xml", base_headers),
    ]

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
            {
                "category": "security_headers",
                "severity": severity,
                "title": f"Missing {header}",
                "details": f"The response from {normalized_url} does not include {header}.",
            }
        )

    if tls_details.get("status") == "ok" and tls_details.get("days_remaining", 0) < 14:
        issues.append(
            {
                "category": "tls",
                "severity": "high",
                "title": "TLS certificate expires soon",
                "details": f"Certificate expires in {tls_details['days_remaining']} days.",
            }
        )
    if tls_details.get("status") not in {"ok", "not_applicable"}:
        issues.append(
            {
                "category": "tls",
                "severity": "high",
                "title": "TLS inspection failed",
                "details": tls_details.get("message", "TLS handshake could not be completed."),
            }
        )

    for item in sensitive_paths:
        if item["status_code"] in {200, 206}:
            issues.append(
                {
                    "category": "sensitive_path",
                    "severity": "critical",
                    "title": f"Sensitive path exposed: {item['path']}",
                    "details": f"{item['url']} returned HTTP {item['status_code']}.",
                }
            )

    for item in api_paths:
        if item["path"] in {"/openapi.json", "/swagger", "/api/docs"} and item["status_code"] == 200:
            issues.append(
                {
                    "category": "api_surface",
                    "severity": "medium",
                    "title": f"Public API documentation exposed: {item['path']}",
                    "details": f"{item['url']} returned HTTP 200.",
                }
            )

    if cors_check and cors_check["allow_origin"] == "*":
        issues.append(
            {
                "category": "cors",
                "severity": "medium",
                "title": "Wildcard CORS policy detected",
                "details": "Access-Control-Allow-Origin is set to '*'.",
            }
        )

    summary = {
        "scan_type": scan_type,
        "target_url": normalized_url,
        "issue_count": len(issues),
        "critical_count": len([item for item in issues if item["severity"] == "critical"]),
        "high_count": len([item for item in issues if item["severity"] == "high"]),
        "medium_count": len([item for item in issues if item["severity"] == "medium"]),
        "low_count": len([item for item in issues if item["severity"] == "low"]),
        "http_status": homepage["status_code"],
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
            "server": homepage["headers"].get("Server", ""),
            "content_type": homepage["headers"].get("Content-Type", ""),
        },
        "tls": tls_details,
        "security_headers": security_headers,
        "common_files": common_files,
        "sensitive_paths": sensitive_paths,
        "api_paths": api_paths,
        "cors": cors_check,
        "unauthenticated_paths": unauthenticated_paths,
        "issues": issues,
    }


def _request(url: str, headers: dict[str, str], method: str = "GET") -> dict:
    req = request.Request(url, headers=headers, method=method)
    try:
        with request.urlopen(req, timeout=DEFAULT_TIMEOUT) as response:
            body = response.read(4096)
            return {
                "status_code": response.getcode(),
                "headers": dict(response.headers.items()),
                "body_preview": body.decode("utf-8", errors="replace"),
            }
    except error.HTTPError as exc:
        body = exc.read(2048) if exc.fp else b""
        return {
            "status_code": exc.code,
            "headers": dict(exc.headers.items()),
            "body_preview": body.decode("utf-8", errors="replace"),
        }


def _probe_path(base_url: str, path: str, headers: dict[str, str], method: str = "GET") -> dict:
    url = parse.urljoin(_ensure_trailing_slash(base_url), path.lstrip("/"))
    try:
        response = _request(url, headers=headers, method=method)
        return {
            "path": path,
            "url": url,
            "status_code": response["status_code"],
            "content_type": response["headers"].get("Content-Type", ""),
        }
    except Exception as exc:
        return {
            "path": path,
            "url": url,
            "status_code": 0,
            "error": str(exc),
        }


def _inspect_security_headers(response: dict) -> dict:
    headers = response["headers"]
    present = [header for header in REQUIRED_SECURITY_HEADERS if header in headers]
    missing = [header for header in REQUIRED_SECURITY_HEADERS if header not in headers]
    return {"present": present, "missing": missing}


def _inspect_cors(response: dict) -> dict:
    headers = response["headers"]
    return {
        "allow_origin": headers.get("Access-Control-Allow-Origin", ""),
        "allow_methods": headers.get("Access-Control-Allow-Methods", ""),
        "allow_headers": headers.get("Access-Control-Allow-Headers", ""),
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
        expires_at = ssl.cert_time_to_seconds(cert["notAfter"])
        days_remaining = int((expires_at - time.time()) / 86400)
        return {
            "status": "ok",
            "issuer": dict(item[0] for item in cert.get("issuer", [])),
            "subject": dict(item[0] for item in cert.get("subject", [])),
            "not_after": cert["notAfter"],
            "days_remaining": days_remaining,
        }
    except Exception as exc:
        return {"status": "error", "message": str(exc)}


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
