#!/usr/bin/env bash
# Switch the on-site lures off (back to the baseline site). Record the time as a deviation if
# this happens during the lure period.
set -euo pipefail
rm -f /etc/honeypot-lures.env
systemctl restart honeypot
echo "Lures are OFF as of $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
