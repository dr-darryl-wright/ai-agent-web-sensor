# AI agent web sensor

A small website built to answer two questions from the server side:

1. Can a website tell when an AI model is acting during a visit, as opposed to a person or an
   ordinary script?
2. Can it tell an AI agent working for a person right now from one acting on a schedule or a
   standing goal?

Data collection ran from 22 to 31 October 2026 on `webplumbingnotes.net`.

## Results

*To be added after the held-out test (November 2026): accuracy on both questions, the hash of
the rules that were tested, and what the signals could and could not separate.*

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

*To confirm: MIT for the code, CC BY 4.0 for the documents.*
