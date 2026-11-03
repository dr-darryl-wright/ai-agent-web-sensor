"""Study analysis (pre-registration sections 7 and 8), built on the frozen signal code in hpa.py.

hpa.py computes sessions and signals S1-S13 and is part of the version 2 freeze; it is used here
unchanged. This module adds what the freeze left to later code:

- run labels, including the logged deviations D2/D5 (setup visits), D4 (voided run) and D6
  (a session holding two run tokens is split where the second token first appears);
- the 50/50 split of labelled runs (A3), by run (scheduled tasks by day, D8), stratified by
  configuration, seed 20261016;
- scoring: confusion tables and balanced accuracy for T1 and T2, with abstentions counted
  both ways (section 4);
- A1 description, A2 signal rates, A6 wild candidates, and the P1-P6 predictions.

The detection rules themselves live in rules.py and are written on the training half only.
"""

from __future__ import annotations

import csv
import math
import os
import random
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from urllib.parse import parse_qs

import hpa

SEED = 20261016
SETUP_WINDOW = timedelta(minutes=30)          # D2, D5
WINDOW_PAD_BEFORE = timedelta(seconds=10)     # same padding as run_analysis.read_run_windows
WINDOW_PAD_AFTER = timedelta(minutes=2)

# D5: operator approvals of a scheduled task's access to the site (run id -> approval times, UTC).
APPROVALS = {
    "1022e6fd": ["2026-10-23T19:35:00+00:00"],
}

# True class of each configuration (section 7). The false-declaration runs are a tag on top of an
# ordinary class: a script (H3) or a person's browser (H1).
CONFIG_CLASS = {
    "human-browse": "H1", "human-lure": "H1", "false-ua-browser": "H1",
    "browser-ai-summary": "H2",
    "curl-fetch": "H3", "scraper": "H3", "false-ua-script": "H3",
    "chatgpt-search": "H5", "chatgpt-agent": "H5", "claude-web-fetch": "H5", "claude-browser-agent": "H5",
    "chatgpt-scheduled": "H6", "claude-scheduled": "H6", "own-loop": "H6", "own-loop-local": "H6",
}
FALSE_DECLARATION_CONFIGS = {"false-ua-browser", "false-ua-script"}
SCHEDULED_CONFIGS = {"chatgpt-scheduled", "claude-scheduled"}

T1_POSITIVE = {"H2", "H5", "H6", "agent_unknown"}   # an LLM acting during the visit
T1_NEGATIVE = {"H1", "H3", "H4"}
T2_CLASSES = ("H5", "H6")


# ------------------------------------------------------------------------------------- runs

def parse_dt(s: str | None) -> datetime | None:
    return datetime.fromisoformat(s) if s else None


def read_runs(paths: list[str]) -> dict[str, dict]:
    """All logged runs from the run logs that exist. Notes starting 'VOID' mark voided runs (D4)."""
    runs: dict[str, dict] = {}
    for p in paths:
        if not p or not os.path.exists(p):
            continue
        with open(p, encoding="utf-8") as f:
            for r in csv.DictReader(f):
                runs[r["run_id"]] = {
                    "run_id": r["run_id"], "config": r["config"], "hypothesis": r.get("hypothesis"),
                    "start": parse_dt(r.get("start_utc")), "end": parse_dt(r.get("end_utc")),
                    "notes": r.get("notes") or "",
                    "void": (r.get("notes") or "").startswith("VOID"),
                }
    return runs


# ------------------------------------------------------------------------------ sessions (D6)

def request_token(req: dict) -> str | None:
    vals = parse_qs(req.get("query") or "").get("r")
    return vals[0] if vals else None


def split_on_tokens(sessions: list[hpa.Session], known: set[str]) -> tuple[list[hpa.Session], int]:
    """D6: split a session where a second, different known run token first appears."""
    out, n_split = [], 0
    for s in sessions:
        parts = [hpa.Session(s.ip, s.ua)]
        current = None
        for req in s.requests:
            tok = request_token(req)
            if tok in known and current is not None and tok != current and parts[-1].requests:
                parts.append(hpa.Session(s.ip, s.ua))
            if tok in known:
                current = tok
            parts[-1].requests.append(req)
        n_split += len(parts) - 1
        out.extend(parts)
    return out, n_split


IP_REPAIR_GAP = timedelta(seconds=60)


def repair_missing_ip(reqs: list[dict], rep) -> list[dict]:
    """D10 (a). Some requests reached the site through the edge server without the client-address
    header (all were a browser's first `GET /` sent as TLS early data), so the logger fell back to
    the local socket address 127.0.0.1. Each such request takes the address of the nearest request
    within 60 seconds that has the same exact user agent and a real address (later one preferred).
    Without this, the first request of a visit, which carries the run token, forms a session of its
    own, split from the rest of the visit. Requests with no match keep 127.0.0.1 and are counted."""
    rep.ip_repaired = 0
    rep.ip_unrepaired = 0
    reqs = sorted(reqs, key=lambda r: r["_ts"])
    by_ua: dict[str, list[dict]] = {}
    for r in reqs:
        if not str(r["_ip"]).startswith("127."):
            by_ua.setdefault(r["_ua"], []).append(r)
    for r in reqs:
        edge = r.get("edge") or {}
        if str(r["_ip"]).startswith("127.") and not edge.get("client_ip") and edge.get("tls_version"):
            near = [x for x in by_ua.get(r["_ua"], []) if abs(x["_ts"] - r["_ts"]) <= IP_REPAIR_GAP]
            if near:
                near.sort(key=lambda x: (x["_ts"] < r["_ts"], abs(x["_ts"] - r["_ts"])))
                r["_ip"] = near[0]["_ip"]
                r["_ip_repaired"] = True
                rep.ip_repaired += 1
            else:
                rep.ip_unrepaired += 1
    return reqs


def drop_operator_sessions(sessions: list[hpa.Session], operator_ips: set[str], windows: list,
                           known: set[str], rep) -> list[hpa.Session]:
    """Section 3 exclusion of the operator's own visits, applied per session (D10 (c)). A session
    from an operator address is kept if it carries a logged run token or overlaps a run window
    (D1: scheduled-task windows are not used); otherwise all its requests are excluded and counted.
    Applied after sessions are built so that a visit made from the operator's computer by an agent
    (ChatGPT's scheduled task runs in a browser on that computer) stays whole."""
    out = []
    for s in sessions:
        if s.ip in operator_ips:
            has_token = any(request_token(q) in known for q in s.requests)
            overlaps = any(a <= s.end and s.start <= b for a, b in windows)
            if not (has_token or overlaps):
                rep.operator += len(s.requests)
                rep.kept -= len(s.requests)
                continue
        out.append(s)
    return out


def build_rows(log_dir: str, ctx: hpa.Context, operator_ips: set[str], windows: list,
               known_tokens: set[str]) -> tuple[list[dict], hpa.LoadReport, int]:
    """hpa.analyse, with the D6 split between building sessions and computing signals."""
    rep = hpa.LoadReport()
    reqs = hpa.load_requests(log_dir, ctx.baseline_start, set(), rep, windows)   # operator: below
    reqs = repair_missing_ip(reqs, rep)
    sessions, n_split = split_on_tokens(hpa.build_sessions(reqs), known_tokens)
    sessions = drop_operator_sessions(sessions, operator_ips, windows, known_tokens, rep)
    rows = [hpa.session_signals(s, ctx) for s in sessions]
    hpa.add_return_visits(rows)
    return rows, rep, n_split


# ---------------------------------------------------------------------------------- labelling

def label_rows(rows: list[dict], runs: dict[str, dict]) -> Counter:
    """Give each session a label. Adds keys: label_run, label_config, true_class, label_status.

    label_status: 'labelled', 'setup' (D2/D5), 'void' (D4), 'ambiguous' (two tokens left after
    D6, or a time-window match with more than one candidate), or 'unlabelled' (wild traffic).
    """
    counts = Counter()
    for r in rows:
        r.update(label_run=None, label_config=None, true_class=None, label_status="unlabelled",
                 label_method=None)
        toks = [t for t in (r.get("run_id") or "").split(";") if t in runs]
        if len(toks) > 1:
            r["label_status"] = "ambiguous"
        elif toks:
            _assign(r, runs[toks[0]], "token")
    # Section 7 fallback: a run whose token reached no session is matched by its time window
    # when exactly one new unlabelled session starts in that window.
    seen = {r["label_run"] for r in rows if r["label_run"]}
    for run in runs.values():
        if run["run_id"] in seen or run["void"] or not run["end"] or run["config"] in SCHEDULED_CONFIGS:
            continue
        a, b = run["start"] - WINDOW_PAD_BEFORE, run["end"] + WINDOW_PAD_AFTER
        cands = [r for r in rows if r["label_status"] == "unlabelled"
                 and a <= datetime.fromisoformat(r["start"]) <= b]
        if len(cands) == 1:
            _assign(cands[0], run, "window")
        elif len(cands) > 1:
            counts["window_ambiguous_runs"] += 1
    for r in rows:
        counts[r["label_status"]] += 1
    return counts


def _assign(r: dict, run: dict, method: str) -> None:
    r["label_run"], r["label_config"], r["label_method"] = run["run_id"], run["config"], method
    r["true_class"] = CONFIG_CLASS.get(run["config"])
    start = datetime.fromisoformat(r["start"])
    if run["void"]:
        r["label_status"] = "void"
    elif run["config"] in SCHEDULED_CONFIGS and start - run["start"] <= SETUP_WINDOW:
        r["label_status"] = "setup"                                     # D2
    elif any(timedelta(0) <= start - datetime.fromisoformat(t) <= SETUP_WINDOW
             for t in APPROVALS.get(run["run_id"], [])):
        r["label_status"] = "setup"                                     # D5
    else:
        r["label_status"] = "labelled"


# --------------------------------------------------------------------------------- A3 split

def split_unit(r: dict) -> str:
    """The unit the 50/50 split assigns: the run, except for scheduled tasks, where each UTC day's
    visit is its own unit (deviation D8)."""
    if r.get("label_config") in SCHEDULED_CONFIGS:
        return f"{r['label_run']}:{r['start'][:10]}"
    return r["label_run"]


def split_runs(rows: list[dict]) -> dict[str, str]:
    """50/50 by unit (run; scheduled tasks by day, D8), stratified by configuration, seed 20261016.
    Returns unit -> train|heldout.

    Units are listed in sorted order within each configuration (configurations in sorted order),
    shuffled with one generator, and the first ceil(n/2) of each configuration go to training.
    """
    by_config = defaultdict(set)
    for r in rows:
        if r["label_status"] == "labelled":
            by_config[r["label_config"]].add(split_unit(r))
    rng = random.Random(SEED)
    half = {}
    for config in sorted(by_config):
        ids = sorted(by_config[config])
        rng.shuffle(ids)
        k = math.ceil(len(ids) / 2)
        for i, rid in enumerate(ids):
            half[rid] = "train" if i < k else "heldout"
    return half


def apply_split(rows: list[dict], half: dict[str, str]) -> None:
    for r in rows:
        r["half"] = half.get(split_unit(r)) if r["label_status"] == "labelled" else None


# ---------------------------------------------------------------------------------- scoring

def t1_truth(c: str) -> str | None:
    return "llm" if c in T1_POSITIVE else ("not_llm" if c in T1_NEGATIVE else None)


def t1_pred(p: str) -> str | None:
    """None = abstention (H0)."""
    return t1_truth(p)


def t2_pred(p: str) -> str | None:
    """None = abstention ('agent, direction unknown', H0, or a non-agent class)."""
    return p if p in T2_CLASSES else None


def balanced_accuracy(pairs: list[tuple[str, str | None]], classes: tuple) -> dict:
    """pairs: (truth, prediction or None). Returns accuracy with abstentions wrong and excluded."""
    per_wrong, per_excl = [], []
    n_abst = sum(1 for _, p in pairs if p is None)
    for c in classes:
        mine = [(t, p) for t, p in pairs if t == c]
        if not mine:
            continue
        per_wrong.append(sum(1 for t, p in mine if p == t) / len(mine))
        answered = [(t, p) for t, p in mine if p is not None]
        if answered:
            per_excl.append(sum(1 for t, p in answered if p == t) / len(answered))
    return {
        "n": len(pairs), "abstentions": n_abst,
        "abstention_rate": round(n_abst / len(pairs), 3) if pairs else None,
        "ba_abstain_wrong": round(sum(per_wrong) / len(per_wrong), 3) if per_wrong else None,
        "ba_abstain_excluded": round(sum(per_excl) / len(per_excl), 3) if per_excl else None,
        "classes_present": [c for c in classes if any(t == c for t, _ in pairs)],
    }


def confusion(pairs: list[tuple[str, str | None]]) -> dict:
    table = defaultdict(Counter)
    for t, p in pairs:
        table[t][p or "abstain"] += 1
    return {t: dict(c) for t, c in table.items()}


# What classify() may see: the signal columns only. Addresses, user-agent strings, run tokens, times
# and every label field are withheld, so the rules cannot read the answer or recognise a run.
RULE_FIELDS = [f for f in hpa.CSV_FIELDS if f not in
               ("start", "end", "ip", "user_agent", "run_id", "statuses", "edge")]


def rule_input(r: dict) -> dict:
    return {k: r.get(k) for k in RULE_FIELDS}


def score(rows: list[dict], classify, which_half: str) -> dict:
    """T1 and T2 on one half. Each session is one example (section 3)."""
    mine = [r for r in rows if r.get("half") == which_half]
    preds = [(r, classify(rule_input(r))) for r in mine]
    t1 = [(t1_truth(r["true_class"]), t1_pred(p)) for r, p in preds if t1_truth(r["true_class"])]
    t2 = [(r["true_class"], t2_pred(p)) for r, p in preds if r["true_class"] in T2_CLASSES]
    out = {"half": which_half, "sessions": len(mine),
           "T1": balanced_accuracy(t1, ("llm", "not_llm")), "T1_confusion": confusion(t1),
           "T2": balanced_accuracy(t2, T2_CLASSES), "T2_confusion": confusion(t2)}
    # The same, without the operator's own agent loops (section 7: rules must not pass by
    # recognising one script).
    own = {"own-loop", "own-loop-local"}
    t2b = [(r["true_class"], t2_pred(p)) for r, p in preds
           if r["true_class"] in T2_CLASSES and r["label_config"] not in own]
    out["T2_without_own_loops"] = balanced_accuracy(t2b, T2_CLASSES)
    return out


# ---------------------------------------------------------------------------------- A1, A2, A6

SIGNALS = ["S1_ai_ua", "S2_on_list", "false_declaration", "S3_network", "S4_signed", "S5_script_fetched",
           "S5_beacon_load", "S5_css", "S5_image", "S6_input_events", "S7_correct", "S8_placements",
           "S10_robots_first", "S11_self_report", "S12_pause", "S13_return"]


def _val(v):
    if v in (None, "", [], {}):
        return "none"
    if isinstance(v, (list, tuple, set)):
        return ";".join(sorted(map(str, v)))
    return str(v)


def signal_rates(rows: list[dict], key: str = "true_class") -> dict:
    """A2: for each class, the share of sessions showing each value of each signal, and S9 median."""
    groups = defaultdict(list)
    for r in rows:
        groups[r[key]].append(r)
    out = {}
    for g, rs in sorted(groups.items(), key=lambda x: str(x[0])):
        d = {"sessions": len(rs), "runs": len({r["label_run"] for r in rs})}
        for s in SIGNALS:
            c = Counter(_val(r.get(s)) for r in rs)
            d[s] = {k: round(v / len(rs), 2) for k, v in c.most_common()}
        gaps = sorted(r["S9_median_gap_s"] for r in rs if r.get("S9_median_gap_s") is not None)
        d["S9_median_gap_s"] = gaps[len(gaps) // 2] if gaps else None
        out[g] = d
    return out


def ua_family(r: dict) -> str:
    ua = (r.get("user_agent") or "").lower()
    if r.get("S1_tokens"):
        return r["S1_tokens"].split(";")[0]
    for k in ("curl", "python", "go-http", "wget", "libredtail", "zgrab", "masscan", "headless"):
        if k in ua:
            return k
    if "mozilla" in ua:
        return "browser-like"
    return "other" if ua else "empty"


def describe(rows: list[dict]) -> dict:
    """A1: wild sessions (no run label) by period: user-agent family, network type, lure hits,
    each counted per session and per distinct client address (added after the pilot)."""
    out = {}
    wild = [r for r in rows if r["label_status"] == "unlabelled"]
    for period in ("baseline", "lure"):
        rs = [r for r in wild if r["period"] == period]
        ips = defaultdict(set)
        for r in rs:
            ips[ua_family(r)].add(r["ip"])
        net_ips = defaultdict(set)
        for r in rs:
            net_ips[r.get("S3_network")].add(r["ip"])
        out[period] = {
            "sessions": len(rs), "addresses": len({r["ip"] for r in rs}),
            "ua_family_sessions": dict(Counter(ua_family(r) for r in rs).most_common()),
            "ua_family_addresses": {k: len(v) for k, v in sorted(ips.items(), key=lambda x: -len(x[1]))},
            "network_sessions": dict(Counter(str(r.get("S3_network")) for r in rs)),
            "network_addresses": {str(k): len(v) for k, v in net_ips.items()},
            "sessions_with_lure_hit": sum(1 for r in rs if r.get("S8_codes")),
            "false_declaration": sum(1 for r in rs if r.get("false_declaration")),
        }
    return out


def wild_candidates(rows: list[dict]) -> list[dict]:
    """A6: unlabelled lure-period sessions with S7 correct or any L2 / L3 response."""
    out = []
    for r in rows:
        if r["label_status"] != "unlabelled" or r["period"] != "lure":
            continue
        l2 = r.get("S11_self_report") not in (None, "none", "not_applicable")
        l3 = r.get("S12_gap_seconds") is not None
        if r.get("S7_correct") or l2 or l3:
            out.append(r)
    return out


# ------------------------------------------------------------------------------- predictions

def predictions(rows: list[dict], classify, heldout_score: dict | None) -> dict:
    """P1-P6 (section 9). P1 is reported but not counted (version 2, section 9)."""
    base = [r for r in rows if r["label_status"] == "unlabelled" and r["period"] == "baseline"]
    h3 = sum(1 for r in base if classify(rule_input(r)) == "H3")
    agent_cfgs = {c for c, k in CONFIG_CLASS.items() if k in ("H2", "H5", "H6")}
    followed = defaultdict(bool)
    present = set()
    for r in rows:
        if r["label_status"] == "labelled" and r["label_config"] in agent_cfgs:
            present.add(r["label_config"])
            followed[r["label_config"]] |= bool(r.get("S7_correct"))
    n_follow = sum(1 for c in present if followed[c])
    out = {
        "P1": {"baseline_sessions": len(base), "classified_H3": h3,
               "holds": (h3 > len(base) / 2) if base else None, "counted": False},
        "P2": {"configurations": len(present), "followed_L1": sorted(c for c in present if followed[c]),
               "holds": n_follow >= 1},
        "P3": {"holds": n_follow < len(present) / 2 if present else None},
        "P6": {"wild_candidates": len(wild_candidates(rows)), "holds": len(wild_candidates(rows)) >= 1},
    }
    if heldout_score:
        ba1 = heldout_score["T1"]["ba_abstain_wrong"]
        ba2 = heldout_score["T2"]["ba_abstain_wrong"]
        out["P4"] = {"T1_ba": ba1, "holds": (ba1 is not None and ba1 >= 0.90)}
        out["P5"] = {"T2_ba": ba2, "holds": (ba2 is not None and ba2 <= 0.65)}
    return out


# ---------------------------------------------------------------------------------- outputs

LABEL_FIELDS = ["label_status", "label_method", "label_run", "label_config", "true_class", "half"]


def write_rows(rows: list[dict], path: str) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    fields = LABEL_FIELDS + hpa.CSV_FIELDS
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow({k: (_val(v) if isinstance(v, (dict, list)) else v) for k, v in r.items()})
