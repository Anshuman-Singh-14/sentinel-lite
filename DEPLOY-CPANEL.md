# Deploying Sentinel Lite on cPanel shared hosting

This guide puts Sentinel Lite on cPanel hosting that has **Setup Python App** (CloudLinux + Phusion Passenger), for example GoDaddy. For your own Ubuntu server, use [DEPLOY.md](DEPLOY.md) instead.

**How it fits together:** Apache hands each request to **Passenger**, which loads `passenger_wsgi.py`. Passenger only speaks WSGI and our app is ASGI (FastAPI), so `passenger_wsgi.py` wraps it with **a2wsgi**. It also creates the database tables (and optionally the first admin) on startup, because a2wsgi doesn't run FastAPI's startup events. The server has no Node.js, so the frontend is built on your computer and uploaded inside the zip.

The examples use the cPanel user `zj6e7hikkqc8` and the domain `sentinellite.com`. Replace them with yours.

## 1. Build the upload (on your computer)

You need Python 3.11+ and Node.js 20+.

```bash
python deploy/cpanel_bundle.py
```

This builds `frontend/dist` and creates `sentinel-lite-cpanel.zip` in the repo root. The zip never contains `.env`, databases, `.venv`, `node_modules` or tests.

## 2. Create the Python app

In cPanel open **Setup Python App** → **Create Application** and fill in:

| Field | Value |
|---|---|
| Python version | **3.11** |
| Application root | `sentinel-lite` (becomes `/home/zj6e7hikkqc8/sentinel-lite`) |
| Application URL | `sentinellite.com`, path left empty |
| Application startup file | `passenger_wsgi.py` |
| Application Entry point | `application` |
| Passenger log file | `/home/zj6e7hikkqc8/logs/sentinel-lite.log` |

Click **Create**. cPanel makes the folder and a placeholder `passenger_wsgi.py`; the zip replaces it in the next step.

## 3. Upload and extract

1. **File Manager** → open `/home/zj6e7hikkqc8/sentinel-lite`.
2. **Upload** `sentinel-lite-cpanel.zip`.
3. Right-click the zip → **Extract** into `/home/zj6e7hikkqc8/sentinel-lite`. Allow it to overwrite `passenger_wsgi.py`.
4. Check that `passenger_wsgi.py`, `backend/` and `frontend/dist/index.html` are directly inside `sentinel-lite/` (not in a nested folder). Then delete the zip.

## 4. Create `.env`

In File Manager click **Settings** → tick **Show Hidden Files**. In `/home/zj6e7hikkqc8/sentinel-lite` create a file named `.env`:

```ini
APP_ENV=prod
SECRET_KEY=paste-a-long-random-string-here
DOMAIN=sentinellite.com
DATABASE_PATH=data/sentinel.db
```

Make `SECRET_KEY` at least 32 random characters, e.g. run `python -c "import secrets; print(secrets.token_urlsafe(48))"` on your computer. Right-click `.env` → **Permissions** → `600`.

`DATABASE_PATH` is relative to the app folder, so the database ends up in `/home/zj6e7hikkqc8/sentinel-lite/data/`, outside the public web folder. The `data` folder is created automatically.

## 5. Install the Python packages

Back in **Setup Python App**, edit the app. Under **Configuration files** type `requirements.txt`, click **Add**, then **Run Pip Install**.

If your plan has **Terminal**, you can instead copy the "enter the virtual environment" command shown at the top of the app page, then run `pip install -r requirements.txt`.

## 6. First admin

There's usually no terminal for `python -m backend.cli create-admin`, so the app can create the first admin itself. In the app's **Environment variables** section add:

| Name | Value |
|---|---|
| `ADMIN_USERNAME` | 3–32 letters, digits, `_ . -` |
| `ADMIN_PASSWORD` | at least 8 characters |

(You can put the same two lines in `.env` instead.) It only runs while the database has **no users at all**, and writes one line to the log when it creates the admin. After you have logged in, **delete both variables** and restart.

## 7. HTTPS (AutoSSL)

In production the login cookie is only sent over HTTPS, so logging in won't work on plain `http://`.

1. Make sure `sentinellite.com` points at this hosting account (cPanel's DNS or your registrar's A record).
2. **SSL/TLS Status** → select the domain → **Run AutoSSL**. Wait until it shows a valid certificate.
3. **Domains** → turn on **Force HTTPS Redirect** for `sentinellite.com`.

## 8. Restart and test

Click **Restart** in Setup Python App (or create/touch `tmp/restart.txt` in the app folder). Then open:

- `https://sentinellite.com/api/health` → `{"status":"ok"}`
- `https://sentinellite.com` → the login page. Log in with the admin from step 6.

## Logs and troubleshooting

- **App log:** the Passenger log file from step 2, `/home/zj6e7hikkqc8/logs/sentinel-lite.log`. Python errors, startup failures and the admin-bootstrap line appear here. If you left that field empty, look for `stderr.log` in the app folder.
- **"Frontend not built yet"**: `frontend/dist` is missing. Re-run step 1 and upload again.
- **Settings errors at startup** (e.g. `SECRET_KEY`): check `.env` from step 4.
- **Login works but you're logged straight out:** you're on `http://`. See step 7.
- **Port scans time out:** shared hosts often block outgoing connections to unusual ports. DNS and website checks still work.

## Updating

Build a new zip (step 1), upload and extract it over the old files (your `.env` and `data/` aren't in the zip, so they're kept), click **Run Pip Install** if `requirements.txt` changed, then **Restart**.
