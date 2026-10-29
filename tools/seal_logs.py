#!/usr/bin/env python3
"""Seal finished days of request logs into a hash chain.

For each complete UTC day not yet sealed (in date order, up to yesterday), append one line
to the seals file:

    {"date", "file", "missing", "bytes", "lines", "file_sha256", "prev_chain", "chain", "sealed_at"}

chain = sha256("<prev_chain>\\n<date>\\n<file_sha256>\\n<bytes>\\n<lines>")

A day with no log file is sealed as missing (hash of empty input), so the chain has no gaps.
Editing, adding or removing any line of a sealed day breaks every later chain value.

The chain shows tampering only relative to a copy of the chain held elsewhere. Post the
latest chain value somewhere public or dated (a commit, an email to yourself) from time to time.

Usage: seal_logs.py --log-dir /var/lib/honeypot/logs --seals /var/lib/honeypot/seals.jsonl
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import date, datetime, timedelta, timezone

GENESIS = "0" * 64
NAME_RE = re.compile(r"^requests-(\d{4}-\d{2}-\d{2})\.jsonl$")


def file_facts(path: str) -> tuple[bool, int, int, str]:
    if not os.path.exists(path):
        return True, 0, 0, hashlib.sha256(b"").hexdigest()
    h = hashlib.sha256()
    size = lines = 0
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
            size += len(chunk)
            lines += chunk.count(b"\n")
    return False, size, lines, h.hexdigest()


def chain_value(prev: str, day: str, sha: str, size: int, lines: int) -> str:
    return hashlib.sha256(f"{prev}\n{day}\n{sha}\n{size}\n{lines}".encode()).hexdigest()


def read_seals(path: str) -> list[dict]:
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def log_days(log_dir: str) -> list[date]:
    days = []
    for name in os.listdir(log_dir) if os.path.isdir(log_dir) else []:
        m = NAME_RE.match(name)
        if m:
            days.append(date.fromisoformat(m.group(1)))
    return sorted(days)


def seal(log_dir: str, seals_path: str, today: date | None = None) -> list[dict]:
    today = today or datetime.now(timezone.utc).date()
    last_complete = today - timedelta(days=1)
    seals = read_seals(seals_path)
    if seals:
        start = date.fromisoformat(seals[-1]["date"]) + timedelta(days=1)
        prev = seals[-1]["chain"]
    else:
        days = log_days(log_dir)
        if not days:
            return []
        start, prev = days[0], GENESIS
    new = []
    d = start
    while d <= last_complete:
        name = f"requests-{d.isoformat()}.jsonl"
        missing, size, lines, sha = file_facts(os.path.join(log_dir, name))
        chain = chain_value(prev, d.isoformat(), sha, size, lines)
        rec = {
            "date": d.isoformat(), "file": name, "missing": missing, "bytes": size, "lines": lines,
            "file_sha256": sha, "prev_chain": prev, "chain": chain,
            "sealed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        new.append(rec)
        prev = chain
        d += timedelta(days=1)
    if new:
        os.makedirs(os.path.dirname(os.path.abspath(seals_path)), exist_ok=True)
        with open(seals_path, "a", encoding="utf-8") as f:
            for rec in new:
                f.write(json.dumps(rec, separators=(",", ":")) + "\n")
            f.flush()
            os.fsync(f.fileno())
    return new


def verify(log_dir: str, seals_path: str) -> list[str]:
    """Return a list of problems; empty means the logs match the chain."""
    problems = []
    prev = GENESIS
    for i, rec in enumerate(read_seals(seals_path)):
        if rec["prev_chain"] != prev:
            problems.append(f"{rec['date']}: chain link broken (seal line {i + 1})")
        missing, size, lines, sha = file_facts(os.path.join(log_dir, rec["file"]))
        if (missing, size, lines, sha) != (rec["missing"], rec["bytes"], rec["lines"], rec["file_sha256"]):
            problems.append(f"{rec['date']}: log file differs from its seal")
        if chain_value(rec["prev_chain"], rec["date"], rec["file_sha256"], rec["bytes"], rec["lines"]) != rec["chain"]:
            problems.append(f"{rec['date']}: chain value does not match its own inputs")
        prev = rec["chain"]
    return problems


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--log-dir", required=True)
    p.add_argument("--seals", required=True)
    p.add_argument("--verify", action="store_true", help="check logs against the chain instead of sealing")
    a = p.parse_args(argv)
    if a.verify:
        problems = verify(a.log_dir, a.seals)
        seals = read_seals(a.seals)
        if problems:
            print("\n".join(problems))
            return 1
        last = seals[-1] if seals else None
        print(f"OK: {len(seals)} day(s) verified" + (f"; latest {last['date']} chain {last['chain']}" if last else ""))
        return 0
    for rec in seal(a.log_dir, a.seals):
        print(f"sealed {rec['date']}: {rec['lines']} lines, chain {rec['chain']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
