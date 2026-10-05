# Tasks

Fill in the **Owner** column with your name and update **Status** (To do / In progress / In review / Done) as you go. Each role works only on its own branch and its own files (see README, "Team roles").

## Foundation (shared wiring)

| Task | Role | Owner | Branch | Status |
|---|---|---|---|---|
| Remove the old enterprise stack | All | Member 1 | `simplify` | Done |
| Settings, SQLite models, login, create-admin CLI | 1 | Member 1 | `simplify` | Done |
| App shell, route stubs with final request schemas, knowledge.json keys | All | Member 1 | `simplify` | Done |
| Frontend shell: login, layout, navigation, stub pages | 3 | Member 3 | `simplify` | Done |
| `run.py` launcher, basic CI, README, this file | 4 | Member 4 | `simplify` | Done |

## Role 1: Backend & Security Lead

| Task | Role | Owner | Branch | Status |
|---|---|---|---|---|
| `guard.check_target`: allowlist lookup, block private/loopback/own IP in prod | 1 | Member 1 | `role-1-backend` | To do |
| `guard.check_rate_limit`: 10 scans per minute per user; login limit 5 per minute per IP | 1 | Member 1 | `role-1-backend` | To do |
| `guard.log_activity` and log logins, scans and admin changes | 1 | Member 1 | `role-1-backend` | To do |
| `admin.py`: users (list, create, change role, deactivate, reset password) | 1 | Member 1 | `role-1-backend` | To do |
| `admin.py`: allowed targets (list, add, remove) and activity log | 1 | Member 1 | `role-1-backend` | To do |
| Tests: `test_guard.py`, `test_admin.py` | 1 | Member 1 | `role-1-backend` | To do |

**Owner tasks (do these yourself, before opening your PR):**

1. **Three more tests** in `tests/test_admin.py`:
   - creating a user whose username already exists returns 409;
   - a username with a space in it (`"bad name"`) returns 422;
   - after an admin deactivates a user, that user's next request to `/api/auth/me` returns 401.
2. **One small improvement:** when the scan rate limit is hit, make the 429 message say how many seconds to wait (e.g. "Too many scans. Try again in 42 seconds."). Change only `guard.py` and update the matching test.
3. **Write `docs/roles/role-1.md`** (about one page, in your own words): what happens step by step when someone logs in; how `check_target` decides whether a scan may run; why the session cookie is httpOnly, Secure and SameSite=Lax. Then check that your row in the README "Team roles" table is accurate.

## Role 2: Network Security Tools

| Task | Role | Owner | Branch | Status |
|---|---|---|---|---|
| `dns_check.py`: A, MX, TXT lookups; SPF and DMARC checks | 2 | Member 2 | `role-2-network-tools` | To do |
| `port_scan.py`: async TCP connect scan, common ports list, one finding per open port | 2 | Member 2 | `role-2-network-tools` | To do |
| `web_check.py`: HTTPS, HTTP→HTTPS redirect, certificate expiry, 6 headers | 2 | Member 2 | `role-2-network-tools` | To do |
| Tests: `test_dns_check.py`, `test_port_scan.py`, `test_web_check.py` | 2 | Member 2 | `role-2-network-tools` | To do |

**Owner tasks (do these yourself, before opening your PR):**

1. **Three more tests**, using the existing helper functions (no network needed):
   - an SPF record ending in `-all` gives no SPF finding (`tests/test_dns_check.py`);
   - a DMARC record with `p=reject` gives no DMARC finding (`tests/test_dns_check.py`);
   - header names in lower case (e.g. `strict-transport-security`) still count as present (`tests/test_web_check.py`).
2. **One small improvement:** add port **5900 (VNC)** to the common ports list in `port_scan.py` with the right category (`remote_desktop`), and add a test that it is classified correctly.
3. **Write `docs/roles/role-2.md`** (about one page, in your own words): how a TCP connect scan decides "open" vs "closed"; what SPF and DMARC protect against; why each of the 6 headers matters. Then check that your row in the README "Team roles" table is accurate.

## Role 3: Frontend & UX

| Task | Role | Owner | Branch | Status |
|---|---|---|---|---|
| `FindingsList` with severity badges, explanation and fix | 3 | Member 3 | `role-3-frontend` | To do |
| Tool pages: DNS check, port scan, website check, log analyzer | 3 | Member 3 | `role-3-frontend` | To do |
| Browser-only tools: password strength, hash generator, encoder (with "never sent" notice) | 3 | Member 3 | `role-3-frontend` | To do |
| History list, scan detail page with CSV / print links | 3 | Member 3 | `role-3-frontend` | To do |
| Admin page: users, targets, activity | 3 | Member 3 | `role-3-frontend` | To do |

**Owner tasks (do these yourself, before opening your PR):**

1. **Three test cases, checked by hand** in the browser and written down in `docs/roles/role-3.md` (input, expected result, actual result):
   - the password `password123` is rated weak and shows at least one tip;
   - encoding `hello world` as URL gives `hello%20world`, and decoding it gives back `hello world`;
   - the SHA-256 of `abc` starts with `ba7816bf`.
2. **One small improvement:** add a **Copy** button next to the output of the hash generator and the encoder (use `navigator.clipboard.writeText`), showing "Copied!" for two seconds after a click.
3. **Write the rest of `docs/roles/role-3.md`** (about one page, in your own words): how a page talks to the backend through `api.js`; how the app knows whether you are logged in; why the browser-only tools never import `api.js`. Then check that your row in the README "Team roles" table is accurate.

## Role 4: Log Analysis, Reports, Testing & Deployment

| Task | Role | Owner | Branch | Status |
|---|---|---|---|---|
| `log_analyzer.py`: parse sshd auth and nginx logs, failed-login bursts, top IPs | 4 | Member 4 | `role-4-logs-reports-deploy` | To do |
| `reports.py`: history, scan detail, CSV export, print-friendly HTML report | 4 | Member 4 | `role-4-logs-reports-deploy` | To do |
| `knowledge.json`: explanation and fix for every finding | 4 | Member 4 | `role-4-logs-reports-deploy` | To do |
| `deploy/`: Caddyfile, systemd unit, `setup.sh`; `DEPLOY.md` | 4 | Member 4 | `role-4-logs-reports-deploy` | To do |
| Tests: `test_log_analyzer.py`, `test_reports.py`, `test_knowledge.py` | 4 | Member 4 | `role-4-logs-reports-deploy` | To do |

**Owner tasks (do these yourself, before opening your PR):**

1. **Three more tests** in `tests/test_log_analyzer.py`:
   - 4 failed logins from one IP (one below the threshold) give **no** burst finding;
   - 404 responses from two different IPs are counted separately;
   - an empty file gives the `log.no_lines_recognized` finding.
2. **One small improvement:** rewrite the explanation of **one** finding in `knowledge.json` so a first-year student would understand it, and read `DEPLOY.md` from start to finish, fixing anything that is unclear to you.
3. **Write `docs/roles/role-4.md`** (about one page, in your own words): how the analyzer decides that a group of failed logins is a "burst"; why uploaded logs are never saved to disk; what Caddy and systemd each do on the server. Then check that your row in the README "Team roles" table is accurate.
