# Sentinel Lite

A small **defensive** security toolkit for learning. It runs simple checks on systems you are allowed to test, then explains every finding in plain language: what was found, how serious it is, and how to fix it.

4th-year CSE capstone project by a team of four.

## Features

| Tool | What it does | Where it runs |
|---|---|---|
| DNS & email check | A, MX and TXT records; are SPF and DMARC present and valid? | Server |
| Port scanner | TCP connect scan of common ports or your own list (max 100). Admin-approved targets only. | Server |
| Website check | HTTPS, certificate expiry and 6 security headers. Admin-approved targets only. | Server |
| Log analyzer | Upload an auth or nginx log (max 5 MB); finds failed-login bursts and the most suspicious IPs. The file is never saved. | Server |
| Password strength, hash generator, Base64/URL encoder | Handy helpers whose input never leaves your browser | Browser only |

Every finding has a **title**, a **severity** (low / medium / high), an **explanation** and a **fix**, all taken from one file: `backend/knowledge.json`.

You can also see your scan history, export a scan as CSV or a print-friendly page ("Save as PDF"), and admins can manage users, approved targets and the activity log.

## Quick start

You need **Python 3.11+** and, the first time only, **Node.js 20+** (to build the frontend).

```bash
git clone <this repo>
cd sentinel-lite
python run.py
```

`run.py` creates `.env` with a random secret, sets up `.venv`, installs packages, builds the frontend, asks you to create the first admin, starts the server and opens http://127.0.0.1:8000. Run it again any time; steps that are already done are skipped.

To put it on a real server with a domain name, see [DEPLOY.md](DEPLOY.md) (Ubuntu VPS) or [DEPLOY-CPANEL.md](DEPLOY-CPANEL.md) (cPanel shared hosting).

## Team roles

Each member owns one area and can explain every file in it. The live task list is in [docs/TASKS.md](docs/TASKS.md).

| Role | Owner | Files |
|---|---|---|
| **1. Backend & Security Lead** | Nilaang Nambiar | `backend/app.py`, `config.py`, `db.py`, `models.py`, `auth.py`, `cli.py`, `validation.py`, `admin.py`, `guard.py` (allowlist, rate limit, activity log), `tests/test_auth.py`, `test_guard.py`, `test_admin.py` |
| **2. Network Security Tools** | Chaitanya Goel | `backend/tools/dns_check.py`, `port_scan.py`, `web_check.py`, `tests/test_dns_check.py`, `test_port_scan.py`, `test_web_check.py` |
| **3. Frontend & UX** | Anshuman Singh | everything in `frontend/` (pages, layout, browser-only tools, findings display) |
| **4. Log Analysis, Reports, Testing & Deployment** | Atharva Kumar Yadav | `backend/tools/log_analyzer.py`, `reports.py`, `results.py`, `knowledge.json`, `tests/test_log_analyzer.py`, `test_reports.py`, `test_knowledge.py`, `.github/workflows/ci.yml`, `deploy/`, `DEPLOY.md`, `run.py` |

Each role works on its own branch (`role-1-backend`, `role-2-network-tools`, `role-3-frontend`, `role-4-logs-reports-deploy`) and only edits its own files. Shared wiring (router registration, frontend routes, navigation, the list of finding keys) was set up first, so the branches don't conflict.

## How it works

```
Browser (React)  ──fetch /api/...──▶  FastAPI (backend/app.py)
                                          │
                     auth.py: who is logged in? (signed session cookie)
                     guard.py: is this target approved? too many scans?
                                          │
                     tools/*.py: run the check, report finding keys
                     results.py: look up each key in knowledge.json, save the scan
                                          │
                                       SQLite (sentinel.db)
```

1. The user logs in. The password is checked against a bcrypt hash and the user id goes into a signed, httpOnly session cookie.
2. A tool page sends a request such as `POST /api/tools/port-scan`. Pydantic validates the input first.
3. Active tools call `guard.check_target()`: the target must be on the admin's approved list, and in production localhost, private IPs and the server itself are always refused.
4. The tool does its network work with strict timeouts and returns finding **keys** (e.g. `port.database_exposed`).
5. `results.py` turns each key into a full explained finding from `knowledge.json` and saves the scan to the user's history.

## API

All routes need a logged-in session except `/api/auth/login` and `/api/health`. A **scan** response looks like:

```json
{
  "id": 1, "tool": "port_scan", "target": "example.com", "created_at": "2026-10-05T10:00:00+00:00",
  "summary": { "...": "tool-specific facts, e.g. open ports" },
  "findings": [
    { "key": "port.ssh", "title": "SSH is open", "severity": "low",
      "explanation": "...", "fix": "...", "details": { "port": 22 } }
  ]
}
```

| Method & path | Body | Returns |
|---|---|---|
| `POST /api/auth/login` | `{username, password}` | user `{id, username, role, is_active}` |
| `POST /api/auth/logout` | none | `{ok: true}` |
| `GET /api/auth/me` | none | user, or 401 |
| `POST /api/tools/dns-check` | `{domain}` | scan |
| `POST /api/tools/port-scan` | `{target, ports: [int] or null}` (null = common ports) | scan |
| `POST /api/tools/web-check` | `{target}` | scan |
| `POST /api/tools/log-analyzer` | multipart form, field `file` | scan |
| `GET /api/scans` | none | your scans, newest first |
| `GET /api/scans/{id}` | none | scan |
| `GET /api/scans/{id}/export.csv` | none | CSV file |
| `GET /api/scans/{id}/report` | none | print-friendly HTML page |
| `GET/POST /api/admin/users` | POST: `{username, password, role}` | users / new user |
| `PATCH /api/admin/users/{id}` | `{role?, is_active?, password?}` | user |
| `GET/POST /api/admin/targets` | POST: `{host, note}` | targets / new target |
| `DELETE /api/admin/targets/{id}` | none | `{ok: true}` |
| `GET /api/admin/activity` | none | latest activity entries |

Errors come back as `{"detail": "message"}` with a matching HTTP status (400, 401, 403, 404, 413, 422, 429). In development the interactive docs are at http://127.0.0.1:8000/api/docs.

## Security design

- **No shell commands.** The tools use Python's `socket`, `ssl`, `dnspython` and `httpx` directly. Only `run.py`, `deploy/cpanel_bundle.py` and `deploy/setup.sh` start other programs.
- **Passwords** are hashed with bcrypt. There is no public sign-up; admins create accounts.
- **Sessions** use a signed cookie that JavaScript can't read (httpOnly), is only sent over HTTPS in production (Secure), and is not sent on cross-site form posts (SameSite=Lax). That last part is what protects against CSRF.
- **Input validation** with Pydantic on every request: hostnames, ports, usernames, passwords.
- **Active scans need approval.** The port scan and website check only run against targets an admin has approved. In production localhost, private networks and the server's own IP are always blocked.
- **Limits everywhere:** 2-second socket timeouts, at most 100 ports, 50 connections at a time, 10 scans per minute per user, 5 MB uploads.
- **Uploaded logs** are processed in memory and never written to disk.
- **Browser-only tools** never send your input to the server.
- **Secrets** live in `.env`, which is not committed to git.

Known limitations (fine for a student project, worth knowing):

- The rate limit lives in memory, so it resets on restart and assumes a single server process (which is how the systemd service runs it).
- The website check resolves the hostname again when it connects, so a target whose DNS changes between the check and the request (DNS rebinding) could slip past the private-IP block.

## Development

```bash
.venv/Scripts/activate            # Windows (on macOS/Linux: source .venv/bin/activate)
python -m pytest                  # backend tests
python -m backend.cli create-admin
uvicorn backend.app:app --reload  # backend with auto-reload on :8000

cd frontend
npm run dev                       # frontend with hot reload on :5173 (calls the backend on :8000)
npm run lint
```

GitHub Actions runs `pytest` and `eslint` (plus a frontend build) on every pull request.

## License

MIT, see [LICENSE](LICENSE).
