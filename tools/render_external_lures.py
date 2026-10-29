#!/usr/bin/env python3
"""Write the text for the two lure placements outside the site (P6 and P7).

Usage: python3 tools/render_external_lures.py DOMAIN "SITE NAME"
Writes lures/external/github-README.md (P6) and lures/external/gist.md (P7).

P6 goes in the README of a SEPARATE small public repository, not the project repository,
so agents reading the lure do not also see the study design. P7 is a public gist.
After placing each one, record the UTC date and time in lures/placed_log.csv.
"""

from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "app"))

from lures import load_placements, text_for  # noqa: E402


def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if len(argv) != 2:
        print(__doc__)
        return 2
    domain, site = argv
    p = load_placements(os.path.join(HERE, "..", "lures", "placements.csv"))
    out = os.path.join(HERE, "..", "lures", "external")
    os.makedirs(out, exist_ok=True)
    readme = (f"# {site}\n\nSource notes for https://{domain}, a small site of short technical notes on "
              f"web plumbing.\n\n- [HTTP caching in five headers](https://{domain}/notes/http-caching)\n\n"
              f"---\n\n{text_for(p['P6'], domain)}\n")
    gist = (f"# HTTP caching: five headers worth knowing\n\nA short summary of the note at "
            f"https://{domain}/notes/http-caching.\n\n"
            "- `Cache-Control: max-age=N`: fresh for N seconds.\n"
            "- `Cache-Control: no-cache`: may be stored, but must be checked with the server before reuse.\n"
            "- `Cache-Control: no-store`: do not keep a copy.\n"
            "- `Cache-Control: private`: browser cache only, not shared caches.\n"
            "- `ETag` with `If-None-Match`: the server answers `304 Not Modified` when nothing changed.\n\n"
            f"---\n\n{text_for(p['P7'], domain)}\n")
    for name, text in (("github-README.md", readme), ("gist.md", gist)):
        with open(os.path.join(out, name), "w", encoding="utf-8") as f:
            f.write(text)
        print(f"wrote lures/external/{name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
