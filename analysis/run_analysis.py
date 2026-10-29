#!/usr/bin/env python3
"""Run the session and signal analysis on downloaded logs.

Run on your computer from the honeypot folder:
    python3 analysis/run_analysis.py

Defaults match this project's layout and frozen dates; override with the options below.
Writes data/analysis/sessions.csv (contains IP addresses: keep private) and prints a summary
with counts only.
"""

from __future__ import annotations

import argparse
import csv
import os
import sys
from datetime import datetime, timedelta

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import hpa  # noqa: E402

ROOT = os.path.dirname(HERE)


def latest_reference(base: str) -> str | None:
    if not os.path.isdir(base):
        return None
    dirs = sorted(d for d in os.listdir(base) if os.path.isdir(os.path.join(base, d)))
    return os.path.join(base, dirs[-1]) if dirs else None


def freeze_time(root: str) -> str | None:
    """Time of the newest freeze (from its FREEZE-YYYY-MM-DDTHHMMSSZ.txt name), as ISO UTC.
    Pre-registration v2 section 2: the baseline period starts at the v2 freeze."""
    names = sorted(n for n in os.listdir(root) if n.startswith("FREEZE-") and n.endswith("Z.txt"))
    if not names:
        return None
    t = datetime.strptime(names[-1][len("FREEZE-"):-len(".txt")], "%Y-%m-%dT%H%M%SZ")
    return t.strftime("%Y-%m-%dT%H:%M:%S+00:00")


def read_run_windows(path: str) -> list:
    """data/runs.csv rows with start_utc and end_utc (ISO times)."""
    out = []
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            for row in csv.DictReader(f):
                # Scheduled tasks run on the vendors' servers, never from the operator's addresses,
                # and stay open for days; their window must not stop the operator-address exclusion.
                if (row.get("config") or "").endswith("-scheduled"):
                    continue
                try:
                    a = datetime.fromisoformat(row["start_utc"])
                    b = datetime.fromisoformat(row["end_utc"]) if row.get("end_utc") else None
                except (KeyError, ValueError):
                    continue
                if b:
                    # CHOICE: run times are logged to the second, so widen each window by 10 s
                    # before and 2 min after, to keep the run's own requests.
                    out.append((a - timedelta(seconds=10), b + timedelta(minutes=2)))
    return out


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--logs", default=os.path.join(ROOT, "data", "logs"))
    p.add_argument("--reference", default=None, help="reference data folder (default: newest in data/reference)")
    p.add_argument("--operator-ips", default=os.path.join(ROOT, "data", "operator_ips.txt"))
    p.add_argument("--runs", default=",".join([os.path.join(ROOT, "data", "runs.csv"),
                                                 os.path.join(ROOT, "data", "loop", "runs.csv"),
                                                 os.path.join(ROOT, "data", "loop-local", "runs.csv")]),
                   help="comma-separated run logs (default: data/runs.csv, data/loop/runs.csv, data/loop-local/runs.csv)")
    p.add_argument("--baseline-start", default=None,
                   help="default: the time of the newest freeze (FREEZE-*.txt in the project folder); "
                        "earlier log lines are the pilot and are excluded and counted")
    p.add_argument("--lure-start", default=None, help="UTC time lures went on, e.g. 2026-10-22T09:00:00+00:00")
    p.add_argument("--cutoff", default="2026-10-31T23:59:59+00:00")
    p.add_argument("--out", default=os.path.join(ROOT, "data", "analysis"))
    a = p.parse_args(argv)

    if a.baseline_start is None:
        a.baseline_start = freeze_time(ROOT)
        if a.baseline_start is None:
            raise SystemExit("No FREEZE-*.txt found: give --baseline-start.")
    print(f"Baseline starts: {a.baseline_start} (earlier lines are the pilot: excluded and counted)")
    ref = a.reference or latest_reference(os.path.join(ROOT, "data", "reference"))
    asn_path = os.path.join(ref, "ip2asn-combined.tsv.gz") if ref else None
    ctx = hpa.Context(
        ua_tokens=hpa.read_ua_tokens(os.path.join(ROOT, "signals", "ai_user_agents.txt")),
        vendors=hpa.VendorLists(ref),
        asn=hpa.AsnTable(asn_path),
        hosting=hpa.read_hosting_list(os.path.join(ROOT, "signals", "hosting_asns.txt")),
        placements=hpa.read_placements(os.path.join(ROOT, "lures", "placements.csv")),
        baseline_start=datetime.fromisoformat(a.baseline_start),
        lure_start=datetime.fromisoformat(a.lure_start) if a.lure_start else None,
        cutoff=datetime.fromisoformat(a.cutoff) if a.cutoff else None,
    )
    if not ref:
        print("NOTE: no reference data found in data/reference/: S2 and S3 will be empty (missing).")
    elif not ctx.asn.loaded:
        print(f"NOTE: no IPtoASN file in {ref}: S3 will be empty (missing).")
    ops = hpa.read_operator_ips(a.operator_ips)
    if not ops:
        print("NOTE: data/operator_ips.txt is empty or missing: your own visits are not excluded.")
    windows = [w for path in a.runs.split(",") if path for w in read_run_windows(path)]
    rows, rep = hpa.analyse(a.logs, ctx, ops, windows)
    out_csv = os.path.join(a.out, "sessions.csv")
    hpa.write_csv(rows, out_csv)
    print(hpa.summary(rows, rep))
    print(f"\nSession table: {out_csv} (contains IP addresses: keep private)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
