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
    spread_out = "\n".join(failed("203.0.113.9", 0, minute) for minute in range(5))  # one a minute
    assert analyze_text(spread_out)[1] == []


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


# --- Sentinel Lite's own log ---


def sl_new(user, action, ip="203.0.113.9", minute=0, second=0, detail="wrong password", result="fail"):
    return (f'2026-11-16T06:{minute:02d}:{second:02d}Z ip={ip} user={user} action={action} result={result} '
            f'detail="{detail}"')


def sl_old(user, action, detail, minute=0, second=0):
    return f"2026-10-30 06:{minute:02d}:{second:02d} UTC | {user} | {action} | {detail}"


def test_parses_both_sentinel_line_formats():
    new = parse_line(sl_new("alice", "login_failed"))
    assert (new.kind, new.ip, new.user, new.time.minute) == ("failed_login", "203.0.113.9", "alice", 0)
    old = parse_line(sl_old("bob", "login_failed", "from 198.51.100.4"))
    assert (old.kind, old.ip, old.user) == ("failed_login", "198.51.100.4", "bob")
    assert parse_line(sl_old("bob", "login", "from 198.51.100.4")).kind == "accepted_login"
    refused = parse_line(sl_new("eve", "scan_refused", detail="port_scan example.com: not approved", result="denied"))
    assert (refused.kind, refused.user, refused.target) == ("scan_refused", "eve", "example.com")
    assert parse_line(sl_new("eve", "rate_limited", detail="scan", result="denied")).kind == "rate_limited"
    assert parse_line(sl_new("alice", "target_added", detail="example.com", result="ok")) is None
    # A quoted username with spaces and an escaped quote comes back whole.
    tricky = parse_line('2026-11-16T06:00:00Z ip=192.0.2.1 user="a \\"b\\" c" action=login_failed result=fail detail=x')
    assert tricky.user == 'a "b" c'
    # An old line whose username itself contains " | ".
    piped = parse_line(sl_old("x fake | admin", "login_failed", "from 192.0.2.1"))
    assert (piped.user, piped.ip) == ("x fake | admin", "192.0.2.1")


def test_both_csv_variants_parse():
    with_ip = ("﻿id,time_utc,ip,username,action,result,detail\n"
               "1,2026-11-16 06:00:00,203.0.113.9,alice,login_failed,fail,wrong password\n"
               "2,2026-11-16 06:00:05,203.0.113.9,'=evil,login_failed,fail,unknown user\n")
    without_ip = ("﻿id,time_utc,username,action,detail\n"
                  "1,2026-10-30 06:00:00,alice,login_failed,from 203.0.113.9\n"
                  "2,2026-10-30 06:00:01,alice,target_added,example.com\n")
    summary, _ = analyze_text(with_ip)
    assert summary["recognized_events"] == 2
    assert summary["top_ips"][0]["ip"] == "203.0.113.9" and summary["top_ips"][0]["failed_logins"] == 2
    assert analyze_text(without_ip)[0]["recognized_events"] == 1


def test_password_spraying_from_sentinel_lite_is_flagged():
    users = ["alice", "bob", "carol", "dave", "erin"]
    log = "\n".join(sl_new(user, "login_failed", minute=n * 2) for n, user in enumerate(users))  # over 8 minutes
    findings = analyze_text(log)[1]
    assert keys(findings) == ["log.password_spray"]
    assert findings[0]["severity"] == "high"
    assert findings[0]["details"] == {"ip": "203.0.113.9", "usernames_in_10_min": 5}
    # The same username five times is not spraying (and spread out it isn't a burst either).
    same_user = "\n".join(sl_new("alice", "login_failed", minute=n * 2) for n in range(5))
    assert analyze_text(same_user)[1] == []
    # Five usernames spread over more than 10 minutes isn't flagged.
    slow = "\n".join(sl_new(user, "login_failed", minute=n * 4) for n, user in enumerate(users))
    assert analyze_text(slow)[1] == []


def sshd_session_failed(user, minute, invalid=False):
    who = f"invalid user {user}" if invalid else user
    return f"Nov 16 06:{minute:02d}:00 web1 sshd-session[812]: Failed password for {who} from 198.51.100.7 port 22 ssh2"


def test_password_spraying_from_sshd_lines_is_flagged():
    log = "\n".join(sshd_session_failed(user, n, invalid=n % 2 == 0)
                    for n, user in enumerate(["root", "admin", "ubuntu", "pi", "oracle"]))
    event = parse_line(sshd_session_failed("admin", 0, invalid=True))
    assert (event.kind, event.user, event.ip) == ("failed_login", "admin", "198.51.100.7")
    assert keys(analyze_text(log)[1]) == ["log.password_spray"]


def test_target_probing_is_flagged():
    log = "\n".join(sl_new("eve", "scan_refused", minute=n, detail=f"port_scan host{n}.example: not approved",
                           result="denied") for n in range(5))
    findings = analyze_text(log)[1]
    assert keys(findings) == ["log.target_probing"]
    assert findings[0]["details"] == {"user": "eve", "refused_scans_in_10_min": 5}
    four = "\n".join(log.splitlines()[:4])
    assert analyze_text(four)[1] == []


def test_rate_limit_abuse_is_flagged_by_user_and_by_ip():
    by_user = "\n".join(sl_new("eve", "rate_limited", ip=f"192.0.2.{n}", minute=n * 10, detail="scan",
                               result="denied") for n in range(5))
    findings = analyze_text(by_user)[1]
    assert [f["details"] for f in findings] == [{"who": "user eve", "hits_in_1_hour": 5}]
    by_ip = "\n".join(sl_new("-", "rate_limited", minute=n * 10, detail="access_request", result="denied")
                      for n in range(5))
    assert [f["details"]["who"] for f in analyze_text(by_ip)[1]] == ["IP 203.0.113.9"]
    assert keys(analyze_text(by_ip)[1]) == ["log.rate_limit_abuse"]


def test_burst_and_success_after_failures_apply_to_sentinel_logins():
    log = [sl_new("alice", "login_failed", second=s) for s in range(0, 50, 10)]
    log.append(sl_new("alice", "login", second=55, detail="", result="ok"))
    assert sorted(keys(analyze_text("\n".join(log))[1])) == ["log.failed_login_burst", "log.success_after_failures"]


def test_new_rules_report_at_most_ten_each():
    lines = []
    for n in range(12):
        lines += [sl_new(f"u{n}-{k}", "login_failed", ip=f"192.0.2.{n}", minute=k * 2) for k in range(5)]
    assert keys(analyze_text("\n".join(lines))[1]).count("log.password_spray") == 10


def test_csv_upload_through_the_api(user_client):
    csv_text = "id,time_utc,ip,username,action,result,detail\n" + "".join(
        f"{n},2026-11-16 06:{n * 2:02d}:00,203.0.113.9,user{n},login_failed,fail,wrong password\n" for n in range(5)
    )
    files = {"file": ("sentinel-activity.csv", csv_text.encode("utf-8-sig"), "text/csv")}
    response = user_client.post("/api/tools/log-analyzer", files=files)
    assert response.status_code == 200
    assert keys(response.json()["findings"]) == ["log.password_spray"]


# --- Key-only SSH servers: attempts that never reach a password prompt ---

# Real lines from our Azure VM's auth.log.
CLOSED_AUTHENTICATING = ("2026-11-16T01:31:06.833119+00:00 sentinel-vm sshd[16193]: Connection closed by "
                         "authenticating user root 195.178.110.217 port 58846 [preauth]")
INVALID_USER = ("2026-11-16T01:32:10.778064+00:00 sentinel-vm sshd[16419]: Invalid user ubuntu from "
                "222.210.35.197 port 46162")
CLOSED_INVALID = ("2026-11-16T01:32:10.896531+00:00 sentinel-vm sshd[16419]: Connection closed by invalid user "
                  "ubuntu 222.210.35.197 port 46162 [preauth]")


def vm_line(message, pid, minute=40, second=0):
    return f"2026-11-16T01:{minute:02d}:{second:02d}.000000+00:00 sentinel-vm sshd[{pid}]: {message}"


def test_each_preauth_line_type_is_a_failed_attempt():
    cases = [
        (CLOSED_AUTHENTICATING, "195.178.110.217", "root", False),
        (INVALID_USER, "222.210.35.197", "ubuntu", True),
        (CLOSED_INVALID, "222.210.35.197", "ubuntu", True),
        (vm_line("Disconnected from invalid user admin 203.0.113.5 port 5022 [preauth]", 1), "203.0.113.5", "admin",
         True),
        (vm_line("Disconnected from authenticating user root 203.0.113.5 port 5022 [preauth]", 1), "203.0.113.5",
         "root", False),
        (vm_line("Failed none for invalid user oracle from 203.0.113.6 port 40022 ssh2", 2), "203.0.113.6", "oracle",
         True),
        (vm_line("Failed keyboard-interactive/pam for invalid user pi from 203.0.113.7 port 22 ssh2", 3),
         "203.0.113.7", "pi", True),
    ]
    for line, ip, user, invalid in cases:
        event = parse_line(line)
        assert event is not None, line
        assert (event.kind, event.ip, event.user, event.invalid_user) == ("failed_login", ip, user, invalid), line
    assert parse_line(INVALID_USER).pid == "16419"


def test_ipv6_and_empty_usernames_parse():
    ipv6 = parse_line(vm_line("Invalid user test from 2001:db8::1f port 51000", 5))
    assert (ipv6.ip, ipv6.user) == ("2001:db8::1f", "test")
    empty = parse_line(vm_line("Invalid user  from 198.51.100.20 port 51000", 6))
    assert (empty.kind, empty.ip, empty.user, empty.invalid_user) == ("failed_login", "198.51.100.20", "", True)
    closed_empty = parse_line(vm_line("Connection closed by invalid user  198.51.100.20 port 51000 [preauth]", 6))
    assert (closed_empty.ip, closed_empty.user) == ("198.51.100.20", "")


def test_one_connection_writing_two_lines_counts_once():
    summary, _ = analyze_text("\n".join([INVALID_USER, CLOSED_INVALID]))
    assert summary["failed_attempts"] == 1
    assert summary["top_ips"][0]["ip"] == "222.210.35.197" and summary["top_ips"][0]["failed_logins"] == 1


def test_failed_password_and_its_closing_line_count_once():
    log = [vm_line("Failed password for root from 203.0.113.9 port 4242 ssh2", 900, second=1),
           vm_line("Connection closed by authenticating user root 203.0.113.9 port 4242 [preauth]", 900, second=2)]
    assert analyze_text("\n".join(log))[0]["failed_attempts"] == 1


def test_each_password_guess_in_one_connection_counts_but_its_other_lines_do_not():
    # Invalid user -> Failed password -> Connection closed: one guess.
    one_guess = [vm_line("Invalid user bob from 203.0.113.9 port 1", 950, second=1),
                 vm_line("Failed password for invalid user bob from 203.0.113.9 port 1 ssh2", 950, second=2),
                 vm_line("Connection closed by invalid user bob 203.0.113.9 port 1 [preauth]", 950, second=3)]
    assert analyze_text("\n".join(one_guess))[0]["failed_attempts"] == 1
    # Three passwords tried in one connection (sshd allows several): three guesses.
    three_guesses = [vm_line("Failed password for root from 203.0.113.9 port 1 ssh2", 951, second=s)
                     for s in (1, 2, 3)]
    three_guesses.append(vm_line("Connection closed by authenticating user root 203.0.113.9 port 1 [preauth]", 951,
                                 second=4))
    assert analyze_text("\n".join(three_guesses))[0]["failed_attempts"] == 3


def test_a_reused_pid_later_on_is_a_new_connection():
    log = [vm_line("Invalid user ubuntu from 203.0.113.9 port 1", 700, minute=10),
           vm_line("Invalid user ubuntu from 203.0.113.9 port 2", 700, minute=40)]  # 30 minutes later
    assert analyze_text("\n".join(log))[0]["failed_attempts"] == 2


def test_normal_session_disconnects_are_not_attempts():
    normal = [
        vm_line("Received disconnect from 203.0.113.50 port 50122:11: disconnected by user", 800),
        vm_line("Received disconnect from 203.0.113.50 port 50122:11: Normal Shutdown", 800),
        vm_line("Disconnected from user azureuser 203.0.113.50 port 50122", 800),
        "2026-11-16T01:40:00.000000+00:00 sentinel-vm sshd[800]: pam_unix(sshd:session): session closed for user "
        "azureuser",
        vm_line("Accepted publickey for azureuser from 203.0.113.50 port 50122 ssh2: ED25519 SHA256:abc", 800),
    ]
    summary, findings = analyze_text("\n".join(normal))
    assert summary["failed_attempts"] == 0
    assert summary["recognized_events"] == 1  # only the accepted login
    assert findings == []


def test_a_burst_of_preauth_attempts_raises_a_failed_login_burst():
    log = []
    for n in range(5):  # five connections, each writing two lines, all within 50 seconds
        log.append(vm_line("Connection closed by authenticating user root 195.178.110.217 port 1 [preauth]",
                           2000 + n, second=n * 10))
        log.append(vm_line("Disconnected from authenticating user root 195.178.110.217 port 1 [preauth]",
                           2000 + n, second=n * 10 + 1))
    summary, findings = analyze_text("\n".join(log))
    assert summary["failed_attempts"] == 5
    assert keys(findings) == ["log.failed_login_burst"]
    assert findings[0]["details"] == {"ip": "195.178.110.217", "failures_in_60s": 5}


def test_five_invalid_usernames_from_one_ip_is_a_username_scan():
    log = []
    for n, user in enumerate(["ubuntu", "admin", "oracle", "test", "postgres"]):  # one every 8 minutes
        log.append(vm_line(f"Invalid user {user} from 222.210.35.197 port 46162", 3000 + n, minute=n * 8))
        log.append(vm_line(f"Connection closed by invalid user {user} 222.210.35.197 port 46162 [preauth]",
                           3000 + n, minute=n * 8, second=1))
    summary, findings = analyze_text("\n".join(log))
    assert summary["failed_attempts"] == 5
    assert keys(findings) == ["log.ssh_username_scan"]  # too slow for spraying (10 min) or a burst (60 s)
    assert findings[0]["severity"] == "medium"
    assert findings[0]["details"] == {"ip": "222.210.35.197", "invalid_usernames_in_1_hour": 5}
    # Existing users ("authenticating user") don't count towards a username scan.
    existing = "\n".join(vm_line(f"Connection closed by authenticating user {user} 192.0.2.9 port 1 [preauth]",
                                 4000 + n, minute=n * 8) for n, user in enumerate(["a", "b", "c", "d", "e"]))
    assert analyze_text(existing)[1] == []
