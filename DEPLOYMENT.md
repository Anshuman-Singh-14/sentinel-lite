# Deploying Sentinel Lite with Docker and a Cloudflare Tunnel

This runs Sentinel Lite in Docker on any computer with internet access (a home server, a laptop, later a VPS) and publishes it through a **Cloudflare Tunnel**. You don't need a public IP, open ports or your own HTTPS certificate: `cloudflared` connects **out** to Cloudflare, and Cloudflare serves the site over HTTPS. (For a VPS without Docker and with Caddy, see [DEPLOY.md](DEPLOY.md). For cPanel shared hosting, see the cPanel guide.)

**How it fits together**

| Address | Cloudflare sends it to | Container |
|---|---|---|
| `https://sentinellite.com` | `http://frontend:80` | nginx serving the built React app |
| `https://www.sentinellite.com` | `http://frontend:80` | the same |
| `https://api.sentinellite.com` | `http://backend:8000` | FastAPI (uvicorn) |

All three containers share the compose network `sentinel`, so `cloudflared` reaches the others by service name. The frontend calls the API at `VITE_API_URL` (baked in at build time). The backend allows exactly the origins in `ALLOWED_ORIGINS` (CORS with credentials). The session cookie is `Secure` and `SameSite=Lax`. `sentinellite.com` and `api.sentinellite.com` count as the same site, so the browser sends the cookie to the API.

## 1. What you need

- **Docker** with the compose plugin (Docker Desktop on Windows/macOS, or `docker.io` + `docker-compose-plugin` on Linux). Check with `docker compose version`.
- A free **Cloudflare** account, with `sentinellite.com` added to it. Cloudflare must be the domain's DNS: at your registrar (GoDaddy), change the nameservers to the two that Cloudflare shows you. Before switching, copy any existing DNS records you still need (email MX records etc.) into Cloudflare.

## 2. Create the tunnel (Cloudflare dashboard)

1. Open **Zero Trust** → **Networks** → **Tunnels** → **Create a tunnel** → **Cloudflared**. Name it `sentinel`.
2. On "Install and run a connector", choose **Docker**. The command shown ends with `--token eyJ...`. Copy only that token. Don't run the command; docker compose runs the connector.
3. Put the token in `.env` in the project folder:
   ```ini
   CF_TUNNEL_TOKEN=eyJ...your token...
   ```
   The token is a secret: anyone who has it can serve pages as your site. `.env` is gitignored. Never commit it, paste it in chat or put it in an issue.
4. **Public Hostnames** (in newer dashboards: **Routes** → **Published application**). Add three entries, each with service type **HTTP**:

   | Subdomain | Domain | Path | Service |
   |---|---|---|---|
   | *(empty)* | `sentinellite.com` | *(empty)* | `frontend:80` |
   | `www` | `sentinellite.com` | *(empty)* | `frontend:80` |
   | `api` | `sentinellite.com` | *(empty)* | `backend:8000` |

   Cloudflare creates the DNS records (proxied CNAMEs to the tunnel) itself. If it complains that a record already exists, delete the old A or CNAME record for that name under **DNS** first.
5. Under **SSL/TLS** → **Edge Certificates**, turn on **Always Use HTTPS**.

## 3. Settings (`.env`)

Copy `.env.example` to `.env` (or let `python run.py` create it) and fill in:

| Key | Value |
|---|---|
| `SECRET_KEY` | at least 32 random characters: `python -c "import secrets; print(secrets.token_urlsafe(48))"` |
| `DOMAIN` | `sentinellite.com` |
| `CF_TUNNEL_TOKEN` | the token from step 2 |
| `ALLOWED_ORIGINS` | `https://sentinellite.com,https://www.sentinellite.com` |
| `VITE_API_URL` | `https://api.sentinellite.com` |

`APP_ENV=prod` and the database location (`/data/sentinel.db` in the `sentinel-data` volume) are set in `docker-compose.yml` for the backend. The `APP_ENV` and `DATABASE_PATH` lines in `.env` only affect `python run.py`. Each container receives only the variables it needs: the backend never sees the tunnel token.

## 4. Run it

From the project folder:

```bash
# With the tunnel (the real deployment)
docker compose --profile tunnel up -d --build

# Create the first admin (asks for a username and password)
docker compose exec backend python -m backend.cli create-admin
```

Then open `https://sentinellite.com` and log in. Check `https://api.sentinellite.com/api/health` → `{"status":"ok"}`.

Everyday commands:

```bash
docker compose --profile tunnel ps          # what is running (all should be "running"/"healthy")
docker compose --profile tunnel logs -f     # follow all logs (Ctrl+C to stop following)
docker compose logs backend --tail 100      # recent backend log: tracebacks of any 500 are here
docker compose --profile tunnel down        # stop everything (the database volume is kept)
```

All three services have `restart: unless-stopped`, so they come back after a reboot as long as Docker itself starts at boot.

### Try it locally without the tunnel

Without `--profile tunnel` only the backend and frontend start. They are published on this computer only (`127.0.0.1`). For this test the frontend must call the local API, so override the two URLs on the command line. They win over `.env` and leave the file unchanged:

```bash
VITE_API_URL=http://localhost:8000 ALLOWED_ORIGINS=http://localhost:8080 docker compose up -d --build
docker compose exec backend python -m backend.cli create-admin
```

Open http://localhost:8080 (the frontend) and http://localhost:8000/api/health (the backend). On Windows PowerShell, set the variables first: `$env:VITE_API_URL="http://localhost:8000"; $env:ALLOWED_ORIGINS="http://localhost:8080"`.

Before starting with the tunnel again, rebuild without the overrides (`docker compose --profile tunnel up -d --build` in a fresh terminal), so the frontend points at `https://api.sentinellite.com` again.

## 5. Updating

```bash
git pull
docker compose --profile tunnel up -d --build
```

Changing `VITE_API_URL` always needs `--build`, because it is compiled into the frontend.

## 6. Backups

All data (users, approved targets, scan history, activity log) is one SQLite file in the `sentinel-data` volume:

```bash
docker compose cp backend:/data/sentinel.db ./sentinel-backup.db
```

## 7. Moving to a VPS later

The tunnel isn't tied to a machine: whichever computer runs `cloudflared` with the token serves the site. Moving takes no DNS changes.

1. On the VPS: install Docker, then `git clone` the repository.
2. Copy `.env` from the old machine to the VPS with `scp` (it isn't in git). Copy a fresh backup too (step 6).
3. **Stop the old machine first**: `docker compose --profile tunnel down`. If both connectors run at once, Cloudflare splits visitors between two servers with two different databases.
4. On the VPS, start everything, then put the database back and restart the backend:
   ```bash
   docker compose --profile tunnel up -d --build
   docker compose cp ./sentinel-backup.db backend:/data/sentinel.db
   docker compose restart backend
   ```
5. A VPS has a firewall: you don't need to open any port for the tunnel. Ports 8000 and 8080 are bound to `127.0.0.1` and stay private.

Port scans and website checks are sent **from the machine running Docker**. Read your provider's terms, and only approve targets you own or have written permission to test.

## When something goes wrong

| Problem | What to check |
|---|---|
| Cloudflare "Error 1033" / tunnel shows **Down** | `docker compose --profile tunnel logs cloudflared`. Usually a wrong or missing `CF_TUNNEL_TOKEN` in `.env`; fix it and run the up command again. |
| Cloudflare "502 Bad Gateway" | A public hostname points at the wrong service or port. It must be `frontend:80` or `backend:8000`, type HTTP (not HTTPS, not `localhost`). |
| Page loads, but login says "Failed to fetch" | The frontend was built with the wrong `VITE_API_URL`, or the page's address isn't listed in `ALLOWED_ORIGINS`. Fix `.env`, then `up -d --build`. |
| Login returns 500 | `docker compose logs backend --tail 100` shows the traceback. A bad `SECRET_KEY` stops the backend from starting at all; the same command shows the reason. |
| Logged in, but straight back to the login page | The site was opened over `http://`. The cookie is HTTPS-only, so turn on **Always Use HTTPS** (step 2). |
