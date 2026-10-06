from backend.tools.dns_check import analyze, check_dmarc, check_spf


def keys(findings):
    return [finding["key"] for finding in findings]


def test_missing_spf_is_medium():
    findings = check_spf(["google-site-verification=abc"])
    assert keys(findings) == ["dns.spf_missing"]
    assert findings[0]["severity"] == "medium"


def test_spf_plus_all_is_high():
    findings = check_spf(["v=spf1 include:_spf.example.com +all"])
    assert keys(findings) == ["dns.spf_allows_all"]
    assert findings[0]["severity"] == "high"


def test_spf_problems_multiple_records_and_no_all():
    assert keys(check_spf(["v=spf1 -all", "v=spf1 ~all"])) == ["dns.spf_multiple"]
    assert keys(check_spf(["v=spf1 include:_spf.example.com"])) == ["dns.spf_no_all"]
    assert check_spf(["v=spf1 include:_spf.example.com ~all"]) == []  # softfail is fine


def test_dmarc_missing_invalid_and_monitor_only():
    assert keys(check_dmarc([])) == ["dns.dmarc_missing"]
    assert keys(check_dmarc(["v=DMARC1; rua=mailto:x@example.com"])) == ["dns.dmarc_invalid"]
    findings = check_dmarc(["v=DMARC1; p=none"])
    assert keys(findings) == ["dns.dmarc_policy_none"]
    assert findings[0]["severity"] == "low"


def test_analyze_reports_missing_a_and_mx():
    findings = analyze(a=[], mx=[], txt=["v=spf1 -all"], dmarc=["v=DMARC1; p=reject"])
    assert keys(findings) == ["dns.no_a_record", "dns.no_mx_record"]
