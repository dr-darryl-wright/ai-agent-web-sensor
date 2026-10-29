#!/usr/bin/env python3
"""Check signals/hosting_asns.txt against an IPtoASN snapshot before freezing.

Usage:
    python3 tools/check_hosting_asns.py signals/hosting_asns.txt ip2asn-v4.tsv.gz

IPtoASN rows are tab-separated: range_start, range_end, AS number, country code, AS name.
For each listed ASN this prints the name(s) IPtoASN gives and marks the row:
    ok       the expected keyword appears in the name
    CHECK    the ASN exists but the keyword does not appear (wrong number, or renamed)
    MISSING  the ASN does not appear in the snapshot
Exit code 1 if any row is CHECK or MISSING.
"""

from __future__ import annotations

import gzip
import sys
from collections import defaultdict


def read_list(path: str) -> list[dict]:
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            if not line.strip() or line.startswith("#"):
                continue
            parts = line.rstrip("\n").split("\t")
            rows.append({"asn": int(parts[0]), "category": parts[1], "keyword": parts[2],
                         "operator": parts[3] if len(parts) > 3 else ""})
    return rows


def read_names(path: str) -> dict[int, set[str]]:
    names: dict[int, set[str]] = defaultdict(set)
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8", errors="replace") as f:
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 5:
                continue
            try:
                asn = int(parts[2])
            except ValueError:
                continue
            names[asn].add(parts[4])
    return names


def check(rows: list[dict], names: dict[int, set[str]]) -> list[tuple[str, dict, str]]:
    out = []
    for r in rows:
        found = names.get(r["asn"])
        if not found:
            out.append(("MISSING", r, ""))
            continue
        joined = " | ".join(sorted(found))
        status = "ok" if r["keyword"].lower() in joined.lower() else "CHECK"
        out.append((status, r, joined))
    return out


def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if len(argv) != 2:
        print(__doc__)
        return 2
    results = check(read_list(argv[0]), read_names(argv[1]))
    bad = 0
    for status, r, joined in results:
        print(f"{status:<8} AS{r['asn']:<7} {r['category']:<11} expected {r['keyword']!r:<16} IPtoASN: {joined}")
        bad += status != "ok"
    print(f"\n{len(results) - bad} ok, {bad} to fix")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
