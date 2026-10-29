#!/usr/bin/env bash
# Set up the honeypot on a fresh Ubuntu 24.04 server. Run as root from the honeypot folder:
#
#   sudo bash deploy/setup.sh DOMAIN ACME_EMAIL CONTACT_EMAIL "SITE NAME"
#
# DOMAIN        the domain whose DNS A record already points at this server
# ACME_EMAIL    email for Let's Encrypt certificate notices (not shown on the site)
# CONTACT_EMAIL email shown in the site's privacy notice
# SITE NAME     the name shown at the top of each page
#
# Safe to run again: it overwrites the config and app files and restarts the services.
# It does not touch existing logs or seals.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then echo "Run as root (sudo)." >&2; exit 1; fi
if [[ $# -ne 4 ]]; then sed -n '2,12p' "$0"; exit 1; fi
DOMAIN="$1"; ACME_EMAIL="$2"; CONTACT_EMAIL="$3"; SITE_NAME="$4"
HERE="$(cd "$(dirname "$0")/.." && pwd)"

echo "== Swap"
# Small servers (512 MB) have no swap by default; package installs can briefly need more memory.
if ! swapon --show | grep -q .; then
  fallocate -l 1G /swapfile
  chmod 600 /swapfile
  mkswap /swapfile
  swapon /swapfile
  grep -q '^/swapfile ' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi

echo "== Packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q python3-venv ufw unattended-upgrades debian-keyring debian-archive-keyring apt-transport-https curl gnupg
if ! command -v caddy >/dev/null; then
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor --yes -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' > /etc/apt/sources.list.d/caddy-stable.list
  chmod o+r /usr/share/keyrings/caddy-stable-archive-keyring.gpg /etc/apt/sources.list.d/caddy-stable.list
  apt-get update -q
  apt-get install -y -q caddy
fi
dpkg-reconfigure -f noninteractive unattended-upgrades

echo "== User and folders"
id hp >/dev/null 2>&1 || useradd --system --home /var/lib/honeypot --shell /usr/sbin/nologin hp
install -d -o hp -g hp -m 750 /var/lib/honeypot /var/lib/honeypot/logs
install -d -m 755 /opt/honeypot
rm -rf /opt/honeypot/app /opt/honeypot/tools /opt/honeypot/lures
cp -r "$HERE/app" "$HERE/tools" "$HERE/lures" "$HERE/requirements.txt" /opt/honeypot/
find /opt/honeypot -name __pycache__ -prune -exec rm -rf {} +
# Copies can arrive readable by their owner only (e.g. from a Mac folder with 600 files).
# The app and the seal job run as user hp, so everyone must be able to read the code.
chmod -R u=rwX,go=rX /opt/honeypot/app /opt/honeypot/tools /opt/honeypot/lures /opt/honeypot/requirements.txt

echo "== Python environment"
[[ -d /opt/honeypot/venv ]] || python3 -m venv /opt/honeypot/venv
/opt/honeypot/venv/bin/pip install -q --upgrade pip
/opt/honeypot/venv/bin/pip install -q -r /opt/honeypot/requirements.txt

echo "== Settings"
umask 077
cat > /etc/honeypot.env <<EOF
HP_DOMAIN=$DOMAIN
HP_SITE_NAME=$SITE_NAME
HP_CONTACT_EMAIL=$CONTACT_EMAIL
HP_RETAIN_UNTIL=31 January 2027
HP_LOG_DIR=/var/lib/honeypot/logs
EOF
chmod 644 /etc/honeypot.env
umask 022

echo "== Caddy"
sed -e "s/__DOMAIN__/$DOMAIN/g" -e "s/__ACME_EMAIL__/$ACME_EMAIL/g" \
  "$HERE/deploy/Caddyfile.template" > /etc/caddy/Caddyfile
install -d -o caddy -g caddy -m 750 /var/log/caddy
caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
# validate runs as root and can create the log files owned by root; Caddy runs as user caddy.
chown -R caddy:caddy /var/log/caddy

echo "== Services"
cp "$HERE/deploy/honeypot.service" "$HERE/deploy/honeypot-seal.service" "$HERE/deploy/honeypot-seal.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now honeypot.service
systemctl restart honeypot.service
systemctl enable --now honeypot-seal.timer
systemctl restart caddy
sleep 2
if ! systemctl is-active --quiet caddy; then
  echo "Caddy did not start. Last log lines:" >&2
  journalctl -u caddy --no-pager -n 30 >&2
  exit 1
fi
# "active" can be a brief moment between crash-restarts, so ask the app itself to answer.
app_ok=0
for i in 1 2 3 4 5 6 7 8 9 10; do
  if [[ "$(curl -s -o /dev/null -w '%{http_code}' -A 'HP-SMOKE-TEST/1 (setup check)' http://127.0.0.1:8080/)" == "200" ]]; then
    app_ok=1; break
  fi
  sleep 1
done
if [[ $app_ok -ne 1 ]]; then
  echo "The logging app is not answering on 127.0.0.1:8080. Last log lines:" >&2
  journalctl -u honeypot --no-pager -n 30 >&2
  exit 1
fi
echo "Logging app answers on 127.0.0.1:8080"

echo "== Firewall"
ufw allow OpenSSH
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 443/udp   # HTTP/3
ufw --force enable

echo
echo "Done. Next: bash deploy/smoke_test.sh $DOMAIN"
