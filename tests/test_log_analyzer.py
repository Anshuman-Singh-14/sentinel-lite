from backend.tools.log_analyzer import MAX_BYTES, analyze_text, parse_line


def failed(ip, second, minute=0):
    return f"Oct  5 10:{minute:02d}:{second:02d} web1 sshd[812]: Failed password for root from {ip} port 4242 ssh2"


def accepted(ip, second):
    return f"Oct  5 10:00:{second:02d} web1 sshd[812]: Accepted password for alice from {ip} port 4242 ssh2"


def nginx(ip, status, path="/"):
    return f'{ip} - - [05/Oct/2026:10:00:01 +0000] "GET {path} HTTP/1.1" {status} 153 "-" "curl/8.0"'


def keys(findings):
    return [finding["key"] for finding in findings]


def test_parses_sshd_and_nginx_lines():
    assert parse_line(failed("203.0.113.9", 1)).kind == "failed_login"
    invalid_user = "Oct  5 10:00:01 web1 sshd[9]: Failed password for invalid user admin from 198.51.100.4 port 22 ssh2"
    assert parse_line(invalid_user).ip == "198.51.100.4"
    assert parse_line(nginx("198.51.100.4", 404)).kind == "not_found"
    assert parse_line(nginx("198.51.100.4", 200)) is None
    assert parse_line("just some text") is None


def test_five_failures_in_a_minute_is_a_high_burst():
    log = "\n".join(failed("203.0.113.9", second) for second in range(0, 50, 10))
    summary, findings = analyze_text(log)
    assert keys(findings) == ["log.failed_login_burst"]
    assert findings[0]["severity"] == "high"
    assert summary["top_ips"][0] == {
        "ip": "203.0.113.9", "failed_logins": 5, "auth_failures": 0, "not_found": 0, "total": 5,
    }


def test_failures_spread_over_minutes_are_not_a_burst():
    log = "\n".join(failed("203.0.113.9", 0, minute) for minute in range(5))
    assert analyze_text(log)[1] == []


def test_successful_login_after_failures_is_flagged():
    log = "\n".join([failed("203.0.113.9", s) for s in range(5)] + [accepted("203.0.113.9", 30)])
    assert "log.success_after_failures" in keys(analyze_text(log)[1])


def test_nginx_probing_and_auth_failures():
    log = "\n".join([nginx("198.51.100.4", 404, f"/page{i}") for i in range(20)]
                    + [nginx("192.0.2.1", 401) for _ in range(10)])
    summary, findings = analyze_text(log)
    assert sorted(keys(findings)) == ["log.http_auth_burst", "log.many_not_found"]
    assert [row["ip"] for row in summary["top_ips"]] == ["198.51.100.4", "192.0.2.1"]


def test_upload_through_the_api(user_client):
    files = {"file": ("auth.log", "\n".join(failed("203.0.113.9", s) for s in range(5)), "text/plain")}
    response = user_client.post("/api/tools/log-analyzer", files=files)
    assert response.status_code == 200
    assert response.json()["target"] == "auth.log"
    assert keys(response.json()["findings"]) == ["log.failed_login_burst"]


def test_upload_rejects_wrong_type_and_large_files(user_client):
    wrong_type = user_client.post("/api/tools/log-analyzer", files={"file": ("app.exe", b"MZ", "text/plain")})
    assert wrong_type.status_code == 400
    too_big = user_client.post("/api/tools/log-analyzer", files={"file": ("big.log", b"a" * (MAX_BYTES + 1))})
    assert too_big.status_code == 413
