#!/usr/bin/env bash
# First-time setup of Sentinel Lite on a fresh Ubuntu 24.04 server.
#
#   sudo git clone <repo url> /opt/sentinel-lite
#   cd /opt/sentinel-lite
#   sudo bash deploy/setup.sh your-domain.com
#
# Safe to run again: steps that are already done are skipped or repeated harmlessly.
set -euo pipefail

DOMAIN="${1:?Usage: sudo bash deploy/setup.sh your-domain.com}"
APP_DIR=/opt/sentinel-lite

if [[ ! "$DOMAIN" =~ ^[A-Za-z0-9.-]+$ ]]; then
  echo "That doesn't look like a domain name: $DOMAIN" >&2
  exit 1
fi
if [ "$(id -u)" -ne 0 ]; then
  echo "Please run with sudo." >&2
  exit 1
fi
if [ "$(pwd)" != "$APP_DIR" ]; then
  echo "Clone the repository to $APP_DIR and run this script from there." >&2
  exit 1
fi

echo "==> Installing system packages"
apt-get update
apt-get install -y python3 python3-venv caddy ufw curl ca-certificates
if ! command -v node >/dev/null || [ "$(node -p 'process.versions.node.split(".")[0]')" -lt 20 ]; then
  # Ubuntu's own Node.js is too old for Vite, so use NodeSource's Node 22 package.
  curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
  apt-get install -y nodejs
fi

echo "==> Creating the 'sentinel' system user"
id sentinel >/dev/null 2>&1 || useradd --system --home-dir "$APP_DIR" --shell /usr/sbin/nologin sentinel
mkdir -p "$APP_DIR/data"
chown sentinel:sentinel "$APP_DIR/data"

echo "==> Writing .env (only if it doesn't exist yet)"
if [ ! -f .env ]; then
  SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
  cat > .env <<EOF
APP_ENV=prod
SECRET_KEY=$SECRET_KEY
DOMAIN=$DOMAIN
DATABASE_PATH=data/sentinel.db
EOF
fi
chown root:sentinel .env
chmod 640 .env  # readable by the app, not by other users

echo "==> Installing Python packages"
python3 -m venv .venv
.venv/bin/pip install --disable-pip-version-check -q -r requirements.txt

echo "==> Building the frontend"
(cd frontend && npm ci --no-audit --no-fund && npm run build)

echo "==> Configuring Caddy for $DOMAIN"
sed "s/{\$DOMAIN}/$DOMAIN/" deploy/Caddyfile > /etc/caddy/Caddyfile
systemctl reload caddy || systemctl restart caddy

echo "==> Starting the Sentinel Lite service"
cp deploy/sentinel.service /etc/systemd/system/sentinel.service
systemctl daemon-reload
systemctl enable --now sentinel
systemctl restart sentinel

echo "==> Firewall: allow SSH, HTTP and HTTPS only"
ufw allow OpenSSH
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable

echo
echo "Done. Next, create the first admin:"
echo "  cd $APP_DIR && sudo -u sentinel .venv/bin/python -m backend.cli create-admin"
echo "Then open https://$DOMAIN"
