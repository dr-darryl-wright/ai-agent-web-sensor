#!/usr/bin/env bash
# Own agent loop with a local model via Ollama, on the operator's computer (deviation D7).
# Started by cron twice a day; do not run it by hand for study runs (a hand start is a person's
# request, not a schedule). For a one-off connection test use:  bash tools/agent_local.sh test
#
# Settings: HP_AGENT_MODEL (default gpt-oss:20b), HP_AGENT_MAX_OUT (default 2000: gpt-oss writes
# reasoning before its answer). Records go to data/loop-local/.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
export HP_AGENT_API_URL="http://localhost:11434/v1/chat/completions"
export HP_AGENT_MODEL="${HP_AGENT_MODEL:-gpt-oss:20b}"
export HP_AGENT_MAX_OUT="${HP_AGENT_MAX_OUT:-2000}"
export HP_LOOP_CONFIG="own-loop-local"
export HP_LOOP_DIR="$HERE/data/loop-local"
export HP_DOMAIN="webplumbingnotes.net"
mkdir -p "$HP_LOOP_DIR"
cd "$HERE"
exec /usr/bin/env python3 tools/agent_loop.py "${1:-run}" >> "$HP_LOOP_DIR/cron.log" 2>&1
