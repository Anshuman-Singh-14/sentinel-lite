# Deploying Sentinel Lite

This guide puts Sentinel Lite on a small Ubuntu server with your own domain name and HTTPS. It takes about 30 minutes. No Docker is needed.

**How it fits together:** the browser talks to **Caddy** over HTTPS. Caddy gets a free certificate from Let's Encrypt and forwards each request to **uvicorn** (our FastAPI app) running on `127.0.0.1:8000`. **systemd** starts uvicorn at boot and restarts it if it crashes.

## 1. Get a server

Rent a small VPS with **Ubuntu 24.04** (1 GB RAM is plenty) from any provider, such as DigitalOcean, Hetzner, Linode or AWS Lightsail. Many offer student credit, for example through the [GitHub Student Developer Pack](https://education.github.com/pack).

Write down the server's **public IPv4 address** (for example `203.0.113.10`).

> Port scans are sent **from this server**. Read your provider's terms, and only approve targets you own or have written permission to test.

## 2. Buy a domain

Buy a domain from a registrar such as Namecheap, Porkbun or Cloudflare (often about $10 a year; the GitHub Student Pack includes a free one). You can use the domain itself (`example.com`) or a subdomain of it (`sentinel.example.com`).

## 3. Point the domain at the server

In your registrar's **DNS settings**, add an **A record**:

| Type | Name / Host | Value | TTL |
|---|---|---|---|
| A | `sentinel` (for sentinel.example.com) or `@` (for example.com itself) | your server's IPv4 address | Auto or 300 |

Wait a few minutes, then check it from your own computer:

```bash
nslookup sentinel.example.com
```

It should print your server's IP. Don't continue until it does: Caddy can only get a certificate once the domain points at the server.

## 4. Log in to the server

```bash
ssh root@203.0.113.10
```

(Use the user name your provider gave you, for example `ubuntu`, and put `sudo` in front of the commands below if you are not root.)

Update the system first:

```bash
sudo apt update && sudo apt upgrade -y
```

## 5. Install Sentinel Lite

```bash
sudo apt install -y git
sudo git clone https://github.com/<your-account>/sentinel-lite.git /opt/sentinel-lite
cd /opt/sentinel-lite
sudo bash deploy/setup.sh sentinel.example.com
```

`setup.sh` does the following:

1. Installs Python, Caddy, Node.js 22 and the `ufw` firewall.
2. Creates a `sentinel` system user (no login shell) for the app to run as.
3. Writes `.env` with `APP_ENV=prod`, a random `SECRET_KEY`, your `DOMAIN` and `DATABASE_PATH=data/sentinel.db`.
4. Installs the Python packages into `.venv` and builds the frontend.
5. Configures Caddy for your domain and installs the `sentinel` systemd service.
6. Opens only ports 22 (SSH), 80 and 443 in the firewall.

## 6. Create the first admin

```bash
cd /opt/sentinel-lite
sudo -u sentinel .venv/bin/python -m backend.cli create-admin
```

Then open `https://sentinel.example.com` and log in. Under **Admin**, create accounts for your team and approve the targets you are allowed to scan.

In production the app also:

- sends the session cookie only over HTTPS (Secure flag);
- turns off the `/api/docs` page;
- refuses to scan localhost, private IP ranges and the server's own IP, even if approved;
- limits each user to 10 scans per minute.

## 7. Updating to a new version

```bash
cd /opt/sentinel-lite
sudo git pull
sudo .venv/bin/pip install -r requirements.txt
(cd frontend && sudo npm ci && sudo npm run build)
sudo systemctl restart sentinel
```

## Backups

All data (users, approved targets, scan history, activity log) is in one file. Copy it to your computer now and then:

```bash
scp root@203.0.113.10:/opt/sentinel-lite/data/sentinel.db ./sentinel-backup.db
```

## When something goes wrong

| Problem | What to check |
|---|---|
| The site doesn't load at all | `sudo systemctl status caddy sentinel` (both should say "active (running)") |
| "502 Bad Gateway" | The app isn't running: `sudo journalctl -u sentinel -n 50` shows its last errors |
| Browser shows a certificate error | The A record must point at this server; then `sudo journalctl -u caddy -n 50` |
| Settings error on start | Look at `/opt/sentinel-lite/.env`: `SECRET_KEY` must be at least 32 characters |
| Forgot the admin password | Create a second admin with the command in step 6, then reset the first one under Admin |
