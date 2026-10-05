# CLAUDE.md — Sentinel Lite

Sentinel Lite is a 3rd-year CSE capstone built by a team of 4: a small **defensive** security toolkit that explains every finding in plain language. Keep it student-scale. Every file should be one a team member can explain to the evaluation panel. Never add offensive or exploitation features.

## Rules

1. **No shell execution in the app.** Never use `subprocess`, `os.system`, `eval` or `exec` in `backend/`. Use `socket`, `asyncio`, `dnspython`, `httpx` and `ssl`. The only files allowed to start processes are the launcher `run.py` (pip, npm; argument lists only, never `shell=True`) and `deploy/setup.sh`.
2. **Validate inputs with Pydantic.** Every request body and query has a schema: hostnames, ports, port lists, usernames.
3. **Every network call has a timeout.** Sockets, DNS and HTTP alike. Scans also have hard limits: at most 100 ports and 50 concurrent connections.
4. **Active scans only run against admin-approved targets.** The port scan and website check go through `guard.check_target()`. In production, localhost, private IPs and the server's own IP are always blocked.
5. **No secrets in git.** Settings come from `.env`, which is gitignored. `.env.example` lists every setting with a safe placeholder.

## Team areas

Each role owns its files; see `README.md` ("Team roles") and `docs/TASKS.md`. On a role branch, only edit that role's files.

## Commands

```bash
python run.py                         # venv + deps + frontend build + server + browser
python -m backend.cli create-admin    # create an admin user (inside the venv)
python -m pytest                      # backend tests
cd frontend && npm run lint           # frontend lint
cd frontend && npm run dev            # frontend dev server (proxies /api to :8000)
```
