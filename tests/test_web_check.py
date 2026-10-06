from datetime import UTC, datetime, timedelta

from backend.tools.web_check import check_expiry, check_headers, redirects_to_https

NOW = datetime(2026, 10, 5, tzinfo=UTC)

ALL_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000",
    "Content-Security-Policy": "default-src 'self'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=()",
}


def test_no_findings_when_all_headers_present():
    assert check_headers(ALL_HEADERS) == []


def test_each_missing_header_is_reported_with_its_severity():
    findings = check_headers({"Content-Type": "text/html"})
    severities = {f["key"]: f["severity"] for f in findings}
    assert len(findings) == 6
    assert severities["web.missing_hsts"] == "medium"
    assert severities["web.missing_referrer_policy"] == "low"


def test_certificate_expiry_levels():
    assert [f["key"] for f in check_expiry(NOW - timedelta(days=1), NOW)] == ["web.cert_expired"]
    assert [f["key"] for f in check_expiry(NOW + timedelta(days=10), NOW)] == ["web.cert_expiring_soon"]
    assert check_expiry(NOW + timedelta(days=90), NOW) == []


def test_http_redirect_detection():
    assert redirects_to_https(301, "https://example.com/")
    assert not redirects_to_https(200, None)
    assert not redirects_to_https(302, "http://example.com/login")
