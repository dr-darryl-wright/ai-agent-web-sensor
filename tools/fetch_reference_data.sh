#!/usr/bin/env bash
# Download the reference data the pre-registration freezes, into a dated folder, and check it.
# Run on the server as root, from the honeypot folder:
#
#   bash tools/fetch_reference_data.sh
#
# Saves into a new folder /var/lib/honeypot/reference/YYYY-MM-DDTHHMMZ/ (never into an existing
# one, so an earlier, frozen set is not overwritten):
#   ip2asn-combined.tsv.gz      IPtoASN snapshot (public domain), IPv4 and IPv6
#   <vendor list>.json          AI vendor IP lists (S2)
#   manifest.tsv                one line per file: name, URL, HTTP status, bytes, SHA-256
#   asn_check.txt               output of tools/check_hosting_asns.py
#
# Where a vendor's exact URL was uncertain, several candidates are tried and every attempt is
# recorded in the manifest; the first that returns valid JSON is kept.
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
STAMP="$(date -u +%Y-%m-%dT%H%MZ)"
OUT="/var/lib/honeypot/reference/$STAMP"
[[ ! -e "$OUT" ]] || { echo "$OUT already exists; wait a minute and run again." >&2; exit 1; }
mkdir -p "$OUT"
MAN="$OUT/manifest.tsv"
printf "name\turl\thttp_status\tbytes\tsha256\tnote\n" > "$MAN"
UA="HP-SMOKE-TEST/1 (reference data fetch; operator)"

fetch() { # name url -> 0 if saved as valid file
  local name="$1" url="$2" tmp code bytes sha note=""
  tmp="$(mktemp)"
  code="$(curl -sS -L -A "$UA" -m 120 -o "$tmp" -w '%{http_code}' "$url" 2>/dev/null)" || true
  [[ -z "$code" ]] && code=000
  bytes="$(stat -c %s "$tmp" 2>/dev/null || echo 0)"
  if [[ "$code" == "200" && "$name" == *.json ]]; then
    python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$tmp" 2>/dev/null || { note="not valid JSON"; code="${code}-badjson"; }
  fi
  if [[ "$code" == "200" ]]; then
    mv "$tmp" "$OUT/$name"; chmod 644 "$OUT/$name"
    sha="$(sha256sum "$OUT/$name" | cut -d' ' -f1)"
    printf "%s\t%s\t%s\t%s\t%s\t%s\n" "$name" "$url" "$code" "$bytes" "$sha" "kept" >> "$MAN"
    echo "ok      $name  <- $url"
    return 0
  fi
  rm -f "$tmp"
  printf "%s\t%s\t%s\t%s\t\t%s\n" "$name" "$url" "$code" "$bytes" "${note:-not kept}" >> "$MAN"
  echo "miss    $name  <- $url  (HTTP $code)"
  return 1
}

first_of() { # name url1 url2 ... -> keep the first that works
  local name="$1"; shift
  for u in "$@"; do fetch "$name" "$u" && return 0; done
  echo "FAILED  $name: no candidate URL worked. Find the current URL in the vendor's documentation."
  return 1
}

echo "== IPtoASN"
fetch ip2asn-combined.tsv.gz https://iptoasn.com/data/ip2asn-combined.tsv.gz

echo "== OpenAI"
fetch openai-gptbot.json      https://openai.com/gptbot.json
fetch openai-searchbot.json   https://openai.com/searchbot.json
fetch openai-chatgpt-user.json https://openai.com/chatgpt-user.json

echo "== Perplexity"
first_of perplexity-perplexitybot.json \
  https://www.perplexity.com/perplexitybot.json \
  https://www.perplexity.ai/perplexitybot.json
first_of perplexity-user.json \
  https://www.perplexity.com/perplexity-user.json \
  https://www.perplexity.ai/perplexity-user.json \
  https://www.perplexity.com/perplex-user.json \
  https://www.perplexity.ai/perplex-user.json

echo "== Google"
first_of google-googlebot.json \
  https://developers.google.com/static/search/apis/ipranges/googlebot.json \
  https://developers.google.com/static/crawling/ipranges/common-crawlers.json
fetch google-user-triggered-agents.json https://developers.google.com/static/crawling/ipranges/user-triggered-agents.json

echo "== Anthropic"
fetch anthropic-bots.json https://claude.com/crawling/bots.json

echo "== Hosting network check"
if [[ -f "$OUT/ip2asn-combined.tsv.gz" ]]; then
  python3 "$HERE/tools/check_hosting_asns.py" "$HERE/signals/hosting_asns.txt" "$OUT/ip2asn-combined.tsv.gz" | tee "$OUT/asn_check.txt"
else
  echo "skipped: no IPtoASN snapshot"
fi

chmod 755 "$OUT"; chmod 644 "$MAN"
echo
echo "Saved in $OUT"
echo "Manifest (name, URL, HTTP status, bytes, SHA-256, note):"; cat "$MAN"
