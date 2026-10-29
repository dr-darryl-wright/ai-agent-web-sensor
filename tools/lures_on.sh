#!/usr/bin/env bash
# Switch the on-site lures (P1-P5) on, and print the UTC time to record as the lure go-live.
# Run on the server as root, from the honeypot folder, ONLY after the pre-registration is frozen:
#   bash tools/lures_on.sh DOMAIN
set -euo pipefail
DOMAIN="${1:?usage: bash tools/lures_on.sh DOMAIN}"
echo "HP_LURES=1" > /etc/honeypot-lures.env
chmod 644 /etc/honeypot-lures.env
systemctl restart honeypot
sleep 2
NOW="$(date -u '+%Y-%m-%d %H:%M:%S UTC')"
P1="$(python3 -c "import csv;print([r['code'] for r in csv.DictReader(open('/opt/honeypot/lures/placements.csv')) if r['placement']=='P1'][0])")"
if curl -s -A 'HP-SMOKE-TEST/1 (lure check)' "https://$DOMAIN/" | grep -q "/v/$P1/"; then
  echo "Lures are ON. Record this as the lure go-live: $NOW"
else
  echo "FAIL: the home page does not show the P1 lure. Check: journalctl -u honeypot -n 30" >&2
  exit 1
fi
