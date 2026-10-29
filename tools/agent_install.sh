#!/usr/bin/env bash
# Install the own agent loop on the server. Run as root from /root/honeypot AFTER setup.sh:
#   bash tools/agent_install.sh
# Asks for the OpenAI API key (not shown as you type), stores it readable by root only,
# makes one tiny test call, and enables the timer (which fires only 22-31 October 2026).
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Run as root." >&2; exit 1; }
HERE="$(cd "$(dirname "$0")/.." && pwd)"

if [[ ! -s /etc/honeypot-agent.env ]]; then
  read -r -s -p "OpenAI API key: " KEY; echo
  [[ -n "$KEY" ]] || { echo "No key given." >&2; exit 1; }
  read -r -p "Model [gpt-4o-mini]: " MODEL; MODEL="${MODEL:-gpt-4o-mini}"
  umask 077
  printf "OPENAI_API_KEY=%s\nHP_AGENT_MODEL=%s\n" "$KEY" "$MODEL" > /etc/honeypot-agent.env
  umask 022
  chmod 600 /etc/honeypot-agent.env
fi

# Own system user for the agent, separate from the website user (hp).
id hpagent >/dev/null 2>&1 || useradd --system --home /var/lib/honeypot-agent --shell /usr/sbin/nologin hpagent
install -d -o hpagent -g hpagent -m 750 /var/lib/honeypot-agent
cp "$HERE/tools/agent_loop.py" "$HERE/tools/runs.py" /opt/honeypot/tools/
chmod 755 /opt/honeypot/tools/agent_loop.py /opt/honeypot/tools/runs.py

echo "== Test call (one tiny request, no site visit)"
# Run it the way the timer will: as hpagent, with systemd reading the settings files.
# (The files are not loaded with bash: values such as the site name contain unquoted spaces,
# which systemd accepts but bash would try to run as commands.)
systemd-run --quiet --wait --pipe --collect \
  -p User=hpagent -p Group=hpagent \
  -p EnvironmentFile=/etc/honeypot.env -p EnvironmentFile=/etc/honeypot-agent.env \
  -p Environment=HP_LOOP_DIR=/var/lib/honeypot-agent \
  /usr/bin/python3 /opt/honeypot/tools/agent_loop.py test

cp "$HERE/deploy/honeypot-agent.service" "$HERE/deploy/honeypot-agent.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now honeypot-agent.timer
echo
echo "== When the timer will fire"
systemd-analyze calendar --iterations=4 "2026-10-22..31 03,15:17:00 UTC" | sed -n 1,12p
systemctl list-timers honeypot-agent.timer --no-pager
echo
echo "== Separation check"
if runuser -u hp -- test -r /etc/honeypot-agent.env 2>/dev/null; then echo "FAIL: the website user can read the key file" >&2; exit 1; else echo "ok    the website user cannot read the key file"; fi
if runuser -u hp -- test -r /var/lib/honeypot-agent 2>/dev/null && runuser -u hp -- ls /var/lib/honeypot-agent >/dev/null 2>&1; then echo "FAIL: the website user can read the agent folder" >&2; exit 1; else echo "ok    the website user cannot read the agent folder"; fi
echo
echo "Done. Sessions start on 22 October. Each run is logged in /var/lib/honeypot-agent/runs.csv."
