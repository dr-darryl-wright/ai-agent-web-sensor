#!/usr/bin/env bash
# Freeze: hash the pre-registration and everything it depends on, into one manifest and one
# combined hash. Run on the server as root, from the honeypot folder, AFTER
# tools/fetch_reference_data.sh and after any fixes to signals/ have been copied over:
#
#   bash tools/freeze_manifest.sh
#
# Then post the combined hash it prints somewhere dated and outside your control (a public
# commit, or an email to yourself), copy FREEZE-*.txt back to your computer, and only then
# switch the lures on.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
REF="$(ls -d /var/lib/honeypot/reference/*/ 2>/dev/null | sort | tail -1)"
[[ -n "$REF" ]] || { echo "No reference data yet: run tools/fetch_reference_data.sh first." >&2; exit 1; }
if grep -n "TO DECIDE" "$HERE/PREREGISTRATION.md" | grep -v "Freezing means" >/dev/null; then
  echo "PREREGISTRATION.md still has TO DECIDE items:" >&2
  grep -n "TO DECIDE" "$HERE/PREREGISTRATION.md" >&2
  exit 1
fi
NOW="$(date -u '+%Y-%m-%dT%H%M%SZ')"
OUT="$HERE/FREEZE-$NOW.txt"
{
  echo "# Freeze manifest, $NOW"
  echo "# sha256  file"
  cd "$HERE"
  sha256sum PREREGISTRATION.md signals/ai_user_agents.txt signals/hosting_asns.txt \
            lures/placements.csv app/lures.py app/app.py app/reqlog.py analysis/hpa.py
  # Earlier freezes, so this one also commits to the record of what it replaced.
  for f in $(ls FREEZE-*.txt checks/PREREGISTRATION.frozen-*.md 2>/dev/null | grep -v "^$(basename "$OUT")$" | sort); do sha256sum "$f"; done
  cd "$REF"
  for f in $(ls | sort); do sha256sum "$f" | sed "s#  #  reference/$(basename "$REF")/#"; done
} > "$OUT"
COMBINED="$(grep -v '^#' "$OUT" | sha256sum | cut -d' ' -f1)"
echo "# combined: $COMBINED" >> "$OUT"
cat "$OUT"
echo
echo "Combined hash to post: $COMBINED"
echo "Manifest saved as $OUT"
