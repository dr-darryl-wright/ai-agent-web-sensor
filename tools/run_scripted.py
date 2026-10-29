#!/usr/bin/env python3
"""Automated controlled runs, run from your computer (pre-registration section 7).

    python3 tools/run_scripted.py once      one run each of: curl-fetch, scraper, false-ua-script
    python3 tools/run_scripted.py series    five rounds of the above, 40 minutes apart (~3 hours;
                                            leave the terminal open)

Each run is logged in data/runs.csv before it starts and closed when it finishes.
  curl-fetch       the real curl program fetches the home page once                  (H3)
  scraper          a Python scraper fetches the home page and follows every
                   on-site link, up to 10 pages                                    (H3)
  false-ua-script  a Python client claiming to be ChatGPT-User fetches two pages     (false declaration tag)
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
import urllib.request
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import runs  # noqa: E402

FALSE_UA = "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ChatGPT-User/1.0; +https://openai.com/bot"
SCRAPER_UA = f"Python-urllib/{sys.version_info.major}.{sys.version_info.minor}"
ROUND_GAP_SECONDS = 40 * 60


class Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            for k, v in attrs:
                if k == "href" and v:
                    self.links.append(v)


def get(url: str, ua: str) -> tuple[int, str]:
    req = urllib.request.Request(url, headers={"User-Agent": ua})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, ""


def curl_fetch() -> str:
    row = runs.start("curl-fetch")
    url = runs.url_for(row["run_id"])
    out = subprocess.run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", url],
                         capture_output=True, text=True, timeout=60)
    runs.end(row["run_id"], note=f"curl status {out.stdout.strip()}")
    return f"curl-fetch   {row['run_id']}  status {out.stdout.strip()}"


def scraper(max_pages: int = 10) -> str:
    row = runs.start("scraper")
    start = runs.url_for(row["run_id"])
    host = urlparse(start).netloc
    seen, queue, fetched = set(), [start], 0
    while queue and fetched < max_pages:
        u = queue.pop(0)
        key = urlparse(u)._replace(query="", fragment="").geturl()
        if key in seen:
            continue
        seen.add(key)
        status, body = get(u, SCRAPER_UA)
        fetched += 1
        if status == 200 and body:
            p = Links()
            p.feed(body)
            for h in p.links:
                v = urljoin(u, h)
                if urlparse(v).netloc == host:
                    queue.append(v)
        time.sleep(0.2)
    runs.end(row["run_id"], note=f"scraper fetched {fetched} pages")
    return f"scraper      {row['run_id']}  {fetched} pages"


def false_ua() -> str:
    row = runs.start("false-ua-script")
    s1, _ = get(runs.url_for(row["run_id"]), FALSE_UA)
    time.sleep(2)
    s2, _ = get(runs.url_for(row["run_id"], "/notes/http-caching"), FALSE_UA)
    runs.end(row["run_id"], note=f"statuses {s1},{s2}")
    return f"false-ua     {row['run_id']}  statuses {s1},{s2}"


def one_round() -> None:
    for f in (curl_fetch, scraper, false_ua):
        try:
            print(f())
        except SystemExit as e:  # spacing rule or other refusal from runs.py
            print(f"skipped {f.__name__}: {e}")


def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if argv[:1] == ["once"]:
        one_round()
    elif argv[:1] == ["series"]:
        for i in range(5):
            print(f"== round {i + 1} of 5")
            one_round()
            if i < 4:
                print(f"waiting {ROUND_GAP_SECONDS // 60} minutes (spacing rule)...", flush=True)
                time.sleep(ROUND_GAP_SECONDS)
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
