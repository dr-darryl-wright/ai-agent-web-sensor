#!/usr/bin/env python3
"""Check what git would publish, before the first push. From the honeypot folder, in a git
repository (run `git init` first if needed):

    python3 tools/prepublish_check.py

It lists every file git would include (tracked, plus untracked files not ignored) and fails if:
- any file is under a `data/` folder, is a log or key file, or is larger than 5 MB;
- any file contains a secret (API key, token, private key);
- any file contains an address from `data/operator_ips.txt` or a string from
  `data/prepublish_blocklist.txt` (one per line: hijacked sites' names, scanner addresses and
  anything else that must never be published; the list itself stays private in `data/`).
It also prints, for review, other IP addresses, email addresses and home-folder paths outside
`tests/`. Exit code 0 means no failures.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAX_BYTES = 5 * 1024 * 1024
BAD_SUFFIXES = (".jsonl", ".jsonl.gz", ".tsv.gz", ".env", ".pem", ".key", ".sqlite", ".db")
CSV_ALLOWED = ("lures/", "results/")

SECRETS = {
    "OpenAI-style key": re.compile(r"\bsk-[A-Za-z0-9_-]{20,}"),
    "OpenAI key marker": re.compile("T3Blbk" + "FJ"),   # split so this file does not match itself
    "AWS access key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "GitHub token": re.compile(r"\b(ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{20,})"),
    "Slack token": re.compile(r"\bxox[abpr]-[A-Za-z0-9-]{10,}"),
    "private key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "SSH public key": re.compile(r"\bssh-(rsa|ed25519|dss) AAAA"),
}
IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
HOME_PATH = re.compile(r"/(Users|home)/[A-Za-z0-9._-]+/")
SAFE_IP_PREFIXES = ("127.", "0.0.0.0", "10.", "192.168.", "192.0.2.", "198.51.100.", "203.0.113.")


def git_files(root: str) -> list[str]:
    out = subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
                         cwd=root, capture_output=True, text=True)
    if out.returncode != 0:
        raise SystemExit("Not a git repository. Run `git init` in the honeypot folder first.")
    return sorted(p for p in out.stdout.split("\0") if p)


def read_lines(path: str) -> list[str]:
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]


def check(root: str = ROOT) -> tuple[list[str], list[str], list[str]]:
    files = git_files(root)
    blocked = read_lines(os.path.join(root, "data", "operator_ips.txt")) + \
        read_lines(os.path.join(root, "data", "prepublish_blocklist.txt"))
    fails, reviews = [], []
    for rel in files:
        path = os.path.join(root, rel)
        parts = rel.split("/")
        if "data" in parts[:-1]:
            fails.append(f"{rel}: inside a data/ folder")
            continue
        if rel.endswith(BAD_SUFFIXES):
            fails.append(f"{rel}: log, key or database file")
            continue
        if rel.endswith(".csv") and not rel.startswith(CSV_ALLOWED):
            fails.append(f"{rel}: CSV outside lures/ or results/")
        size = os.path.getsize(path)
        if size > MAX_BYTES:
            fails.append(f"{rel}: {size // 1024} KB, larger than 5 MB")
            continue
        try:
            with open(path, encoding="utf-8") as f:
                text = f.read()
        except (UnicodeDecodeError, OSError):
            continue   # binary file (image): no text to scan
        for name, rx in SECRETS.items():
            if rx.search(text):
                fails.append(f"{rel}: contains a {name}")
        low = text.lower()
        for s in blocked:
            if s.lower() in low:
                fails.append(f"{rel}: contains a blocklisted string (from data/; not shown)")
                break
        if not rel.startswith("tests/"):
            ips = sorted({m.group(0) for m in IPV4.finditer(text)
                          if not m.group(0).startswith(SAFE_IP_PREFIXES)})
            if ips:
                reviews.append(f"{rel}: IP addresses {', '.join(ips[:8])}{' ...' if len(ips) > 8 else ''}")
            emails = sorted({m.group(0) for m in EMAIL.finditer(text)})
            if emails:
                reviews.append(f"{rel}: email addresses {', '.join(emails[:5])}")
            if HOME_PATH.search(text):
                reviews.append(f"{rel}: contains a home-folder path")
    return files, fails, reviews


def main() -> int:
    files, fails, reviews = check()
    print(f"Files git would publish: {len(files)}")
    for rel in files:
        print(f"  {rel}")
    print(f"\nFor review ({len(reviews)}): confirm each is meant to be public")
    for r in reviews:
        print(f"  {r}")
    print(f"\nFailures ({len(fails)}):")
    for r in fails:
        print(f"  {r}")
    if not os.path.exists(os.path.join(ROOT, "data", "prepublish_blocklist.txt")):
        print("\nWarning: data/prepublish_blocklist.txt not found, so blocklisted names were not checked.")
    print("\nBefore pushing, also confirm: lures switched off on the server (tools/lures_off.sh); "
          "results/ exported with tools/export_results.py; the licence chosen.")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
