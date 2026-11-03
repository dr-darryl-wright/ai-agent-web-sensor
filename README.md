# AI agent web sensor

A small website built to answer two questions from the server side:

1. Can a website tell when an AI model is acting during a visit, as opposed to a person or an
   ordinary script?
2. Can it tell an AI agent working for a person right now from one acting on a schedule or a
   standing goal?

Data collection ran from 18 to 31 October 2026 on `webplumbingnotes.net`; lures were live from 22 October.

**Report:** [REPORT.md](REPORT.md) gives the findings, guidance for analysts reading server logs, and lessons for
building a similar sensor. Screenshots of the site and its lures are in [`docs/screenshots/`](docs/screenshots/).

## Results

Tested once on 47 labelled sessions held back for the purpose, with rules fixed beforehand
(SHA-256 of `analysis/rules.py`: `69b7db41d9400de9e3a646ecf9bf0da96e52f5274d35e64874ccb83a47649f19`,
[posted publicly](https://gist.github.com/dr-darryl-wright/d311041f80e554f5dd127e1f2e50e4da) on 1 November 2026):

- **AI acting during the visit, or not:** the rules answered for 26 of 47 test sessions, and 21
  of those answers were right (balanced accuracy 0.81). Counting "cannot tell" as wrong: 0.52.
- **Working for a person, or on a schedule:** the server could not tell; 93% "cannot tell".
- **Lures:** no AI product or agent followed any lure, in any mode; only people did, by hand. Most
  products' saved answers show they saw the lures and chose not to act on them.
- **Wild traffic:** 23 unknown sessions requested a lure link. All were automated crawlers
  or link collectors; no wild AI agent was found.

Numbers are in `results/`.

## How it works

- **The site.** A few plain pages of notes on web plumbing (HTTP caching and similar), on a
  server that does nothing else. Every request is logged in full, and each day's log is sealed
  into a hash chain so later changes would show.
- **Lures.** Openly labelled notes addressed to AI agents, placed in the page text, the page
  source, an image description, `llms.txt`, `robots.txt`, a separate GitHub README and a gist.
  Each placement has its own code, so a request shows which lure was followed. The lures ask
  only for harmless requests back to this site: answer a simple question, say whether a person
  asked for the visit, and check with that person first.
- **Labelled visits.** About 60 one-off visits from known sources: people browsing (some
  following lures by hand), a browser's built-in AI summary, `curl` and scraper scripts (some
  sending a false AI user agent), and ChatGPT and Claude in search, web fetch and browsing-agent
  modes. Added to these are daily visits from scheduled tasks in ChatGPT and Claude, and from
  two agent loops of my own on timers, one using a hosted model and one a local model.
- **Analysis.** Requests are grouped into sessions (same address and user agent, no gap over 30
  minutes) and each session gets 13 signals: declared identity, whether the address is on the
  vendor's published list, network type, page script and input events, lure responses, timing
  and return visits. Detection rules are written on half of the labelled visits by a separate AI
  agent that sees only that half, frozen by hash, and then tested once on the other half.

The study protocol, fixed before data collection, is in `PREREGISTRATION.md`; changes made
during collection are listed at its end.

## What is in this repository

| Path | What it is |
| --- | --- |
| `app/` | The website (Starlette): pages, lures, and the request logger |
| `deploy/` | Server set-up for Ubuntu 24.04 (Caddy for HTTPS), service files, smoke test |
| `tools/` | Daily log sealing, reference-data download, lure switches, the run log (`runs.py`), scripted runs, the agent loop, the pre-publish check |
| `signals/` | The list of AI user-agent tokens and the list of hosting networks used by the signals |
| `lures/` | Lure placements and when each was placed |
| `analysis/` | Session building and signals (`hpa.py`), labelling, split and scoring (`study.py`), the detection rules (`rules.py`), the runner (`run_study.py`), and the brief given to the rule writer (`rule_writer/`) |
| `results/` | Published outputs, counts only |
| `REPORT.md` | The report on the findings |
| `docs/screenshots/` | The site's pages, page source, `robots.txt` and `llms.txt` as served with the lures on, lure text highlighted |
| `checks/`, `FREEZE-*.txt` | The record that the protocol and code were fixed before data collection |
| `tests/` | Automated tests |
| `CONTROLLED_RUNS.md` | How the labelled visits were run |

## Running it

Tests:

```
pip install -r requirements.txt pytest httpx
python3 -m pytest -q tests
```

Deploying the site: see the comments at the top of `deploy/setup.sh` and `deploy/smoke_test.sh`.

The analysis (`python3 analysis/run_study.py prepare | train | freeze | evaluate | describe |
report`) needs the request logs, which are not published.

## How it was built

Designed and run by Darryl Wright. Claude (Anthropic) was used as an engineering assistant for
code and documents; design decisions and checks were mine.

## Licence

MIT (see `LICENSE`), covering the code and the documents in this repository.
