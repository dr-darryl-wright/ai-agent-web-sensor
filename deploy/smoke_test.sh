#!/usr/bin/env bash
# Check a deployed honeypot end to end. Run on the server as root after setup.sh:
#   sudo bash deploy/smoke_test.sh DOMAIN
# Each test request carries "HP-SMOKE-TEST" in its user agent so it can be excluded later.
set -uo pipefail
DOMAIN="$1"
UA="HP-SMOKE-TEST/1 (operator check)"
fail=0
check() { # name expected actual
  if [[ "$2" == "$3" ]]; then echo "ok    $1 ($3)"; else echo "FAIL  $1: expected $2, got $3"; fail=1; fi
}

check "https home page"   200 "$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" "https://$DOMAIN/")"
check "https robots.txt"  200 "$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" "https://$DOMAIN/robots.txt")"
check "beacon"            204 "$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" -X POST --data '{"e":"smoke"}' "https://$DOMAIN/api/b")"
check "unknown path"      404 "$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" "https://$DOMAIN/smoke-404")"
check "http -> https"     301 "$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" "http://$DOMAIN/")"
check "no Server header"  0   "$(curl -s -I -A "$UA" "https://$DOMAIN/" | grep -ci '^server:')"

sleep 1
LOG="/var/lib/honeypot/logs/requests-$(date -u +%F).jsonl"
echo
echo "Last smoke-test lines in $LOG:"
/opt/honeypot/venv/bin/python - "$LOG" <<'EOF'
import json, sys
import os
if not os.path.exists(sys.argv[1]):
    print("FAIL  no log file yet: no request reached the logging app (check Caddy and DNS first)")
    sys.exit(1)
recs = [json.loads(l) for l in open(sys.argv[1])]
recs = [r for r in recs if any(h[0].lower() == "user-agent" and "HP-SMOKE-TEST" in h[1] for h in r["headers"])][-5:]
for r in recs:
    e = r["edge"]
    print(f'{r["status"]} {r["method"]} {r["path"]:<14} ip={e.get("client_ip")} edge={e.get("edge_name")} '
          f'http={e.get("http_version")} tls={e.get("tls_version")} alpn={e.get("tls_alpn")}')
problems = [r for r in recs if "client_ip" not in r["edge"]]
https = [r for r in recs if r["edge"].get("edge_name") == "https"]
if problems: print("FAIL  some lines have no client_ip: Caddy headers are not arriving"); sys.exit(1)
if https and not all("tls_version" in r["edge"] for r in https): print("FAIL  HTTPS lines have no tls_version"); sys.exit(1)
print("ok    log lines carry client IP and TLS details")
EOF
[[ $? -eq 0 ]] || fail=1

echo
systemctl is-active --quiet honeypot-seal.timer && echo "ok    seal timer active" || { echo "FAIL  seal timer not active"; fail=1; }
exit $fail
