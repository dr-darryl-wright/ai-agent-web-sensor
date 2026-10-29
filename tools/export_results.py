#!/usr/bin/env python3
"""Copy the publishable analysis outputs from data/analysis/ into results/, after `evaluate`.
From the honeypot folder:

    python3 tools/export_results.py

Only outputs that hold counts and rates are copied. Absolute file paths are cut to the file or
folder name. Any file that would still contain an IP address, or a string from
data/operator_ips.txt or data/prepublish_blocklist.txt, is refused and not written.
"""

from __future__ import annotations

import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "data", "analysis")
DST = os.path.join(ROOT, "results")
FILES = ["rules_freeze.json", "heldout_result.json", "heldout_opened.log", "A1_A6.json",
         "report_numbers.json"]
PACKET_FILES = ["BRIEF.md", "MANIFEST.txt", "NOTES.md", "configurations.md"]
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6 = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){3,7}[0-9a-fA-F]{1,4}\b")
ABS_PATH = re.compile(r'(?:/Users|/home|/var|/root|/tmp)/[^"\s,]*/([^"/\s,]+)')


def read_lines(path: str) -> list[str]:
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]


def clean(text: str) -> str:
    return ABS_PATH.sub(r"\1", text)


def problems(text: str, blocked: list[str]) -> list[str]:
    out = []
    if IPV4.search(text) or IPV6.search(text):
        out.append("contains an IP address")
    low = text.lower()
    if any(s.lower() in low for s in blocked):
        out.append("contains a blocklisted string")
    return out


def export(src: str = SRC, dst: str = DST, root: str = ROOT) -> tuple[list[str], list[str]]:
    blocked = read_lines(os.path.join(root, "data", "operator_ips.txt")) + \
        read_lines(os.path.join(root, "data", "prepublish_blocklist.txt"))
    jobs = [(os.path.join(src, f), os.path.join(dst, f)) for f in FILES]
    jobs += [(os.path.join(src, "rule_packet", f), os.path.join(dst, "rule_writer", f)) for f in PACKET_FILES]
    written, refused = [], []
    for s, d in jobs:
        if not os.path.exists(s):
            refused.append(f"{os.path.relpath(s, root)}: not found (skipped)")
            continue
        with open(s, encoding="utf-8") as f:
            text = clean(f.read())
        bad = problems(text, blocked)
        if bad:
            refused.append(f"{os.path.relpath(s, root)}: {', '.join(bad)} (not written)")
            continue
        os.makedirs(os.path.dirname(d), exist_ok=True)
        with open(d, "w", encoding="utf-8") as f:
            f.write(text)
        written.append(os.path.relpath(d, root))
    return written, refused


def main() -> int:
    written, refused = export()
    print("Written:")
    for w in written:
        print(f"  {w}")
    if refused:
        print("Not written:")
        for r in refused:
            print(f"  {r}")
    return 1 if any("not written" in r for r in refused) else 0


if __name__ == "__main__":
    sys.exit(main())
