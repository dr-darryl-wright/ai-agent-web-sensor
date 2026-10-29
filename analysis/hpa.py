"""Honeypot analysis: sessions and signals S1-S13, as defined in PREREGISTRATION.md.

Standard library only (runs on Python 3.10+). Input: the request logs (JSON lines), the frozen
signal lists, the reference data folder, and the lure placements. Output: one record per session.

This file implements the pre-registered definitions. Where a definition needed an operational
choice, the choice is written next to the code as "CHOICE:" so it can be reported.
"""

from __future__ import annotations

import bisect
import csv
import gzip
import ipaddress
import json
import os
import re
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs

SESSION_GAP = timedelta(minutes=30)          # section 3
PAUSE_SECONDS = 60                            # S12
SMOKE_UA = "HP-SMOKE-TEST"                    # section 3 exclusion
CORRECT_ANSWER = "42"                         # L1: seventeen plus twenty-five

PAGE_PATHS = {"/", "/notes/http-caching", "/privacy"}
LURE_RE = re.compile(r"^/(v|r|c)/([a-z0-9]{1,16})(?:/(.*))?$")
# Pages that carry L2 and L3 when lures are on (P1 home page, P4 llms.txt).
L2_L3_PAGES = {"/", "/llms.txt"}


# --------------------------------------------------------------------------------------- loading

def parse_ts(s: str) -> datetime:
    return datetime.fromisoformat(s)


def header(rec: dict, name: str) -> str | None:
    name = name.lower()
    for k, v in rec.get("headers") or []:
        if k.lower() == name:
            return v
    return None


@dataclass
class LoadReport:
    files: int = 0
    lines: int = 0
    bad_json: int = 0
    smoke: int = 0
    operator: int = 0
    before_start: int = 0
    capped: int = 0
    capped_by_day: Counter = field(default_factory=Counter)
    kept: int = 0
    paths: Counter = field(default_factory=Counter)


def load_requests(log_dir: str, start: datetime | None = None, operator_ips: set[str] | None = None,
                  report: LoadReport | None = None, run_windows: list[tuple] | None = None) -> list[dict]:
    """Read every requests-*.jsonl file; apply the section 3 exclusions; return kept records.

    run_windows: (start, end) times of logged controlled runs. Operator-IP requests inside a run
    window are kept (they are labelled data); outside, they are excluded.
    """
    rep = report if report is not None else LoadReport()
    operator_ips = operator_ips or set()
    run_windows = run_windows or []
    out = []
    for name in sorted(os.listdir(log_dir)):
        if not re.match(r"^requests-\d{4}-\d{2}-\d{2}\.jsonl$", name):
            continue
        rep.files += 1
        with open(os.path.join(log_dir, name), encoding="utf-8") as f:
            for line in f:
                rep.lines += 1
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    rep.bad_json += 1
                    continue
                ts = parse_ts(rec["ts"])
                if rec.get("capped"):
                    # Short-form lines: counted by day, recorded as missing, never as absent.
                    rep.capped += 1
                    rep.capped_by_day[ts.date().isoformat()] += 1
                    continue
                ua = header(rec, "user-agent") or ""
                if SMOKE_UA in ua:
                    rep.smoke += 1
                    continue
                if start and ts < start:
                    rep.before_start += 1
                    continue
                ip = (rec.get("edge") or {}).get("client_ip") or (rec.get("edge") or {}).get("socket_peer")
                if ip in operator_ips and not any(a <= ts <= b for a, b in run_windows):
                    rep.operator += 1
                    continue
                rec["_ts"] = ts
                rec["_ip"] = ip
                rec["_ua"] = ua
                out.append(rec)
                rep.kept += 1
                rep.paths[rec.get("path") or ""] += 1
    out.sort(key=lambda r: r["_ts"])
    return out


def read_operator_ips(path: str) -> set[str]:
    if not os.path.exists(path):
        return set()
    ips = set()
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if line:
                ips.add(line)
    return ips


# ------------------------------------------------------------------------------------- sessions

@dataclass
class Session:
    ip: str
    ua: str
    requests: list[dict] = field(default_factory=list)

    @property
    def start(self) -> datetime:
        return self.requests[0]["_ts"]

    @property
    def end(self) -> datetime:
        return self.requests[-1]["_ts"]


def build_sessions(reqs: list[dict]) -> list[Session]:
    """Section 3: same client IP and exact User-Agent, new session after a gap over 30 minutes."""
    open_by_key: dict[tuple, Session] = {}
    sessions: list[Session] = []
    for r in reqs:  # already sorted by time
        key = (r["_ip"], r["_ua"])
        s = open_by_key.get(key)
        if s is None or r["_ts"] - s.end > SESSION_GAP:
            s = Session(r["_ip"], r["_ua"])
            sessions.append(s)
            open_by_key[key] = s
        s.requests.append(r)
    return sessions


# ------------------------------------------------------------------------------ reference data

def read_ua_tokens(path: str) -> list[dict]:
    """signals/ai_user_agents.txt. Rows starting '#~' are general search crawlers (S1 = false)."""
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            general = line.startswith("#~")
            if line.startswith("#") and not general:
                continue
            parts = line.lstrip("#~").rstrip("\n").split("\t")
            if len(parts) < 5 or parts[0] == "token":
                continue
            rows.append({"token": parts[0], "operator": parts[1], "kind": parts[2],
                         "list": parts[3], "ai": not general})
    return rows


def networks_from_json(obj) -> list:
    """Collect every IP network string anywhere in a vendor list (formats differ by vendor)."""
    nets = []

    def walk(x):
        if isinstance(x, dict):
            for v in x.values():
                walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)
        elif isinstance(x, str) and ("/" in x or ":" in x or x.count(".") == 3):
            try:
                nets.append(ipaddress.ip_network(x, strict=False))
            except ValueError:
                pass

    walk(obj)
    return nets


# Which reference file verifies which user-agent tokens (S2). Googlebot is verified for context.
VENDOR_FILES = {
    "openai-gptbot.json": ["GPTBot"],
    "openai-searchbot.json": ["OAI-SearchBot"],
    "openai-chatgpt-user.json": ["ChatGPT-User"],
    "perplexity-perplexitybot.json": ["PerplexityBot"],
    "perplexity-user.json": ["Perplexity-User"],
    "google-googlebot.json": ["Googlebot"],
    "google-user-triggered-agents.json": ["Google-Agent"],
    "anthropic-bots.json": ["ClaudeBot", "Claude-SearchBot", "Claude-User"],
}


# Lists that cover a vendor's crawlers and on-request fetchers together. Under pre-registration
# section 4c (F3), a list that does not separate them cannot decide H4 against H5 by itself.
ROLE_COMBINED_FILES = {"anthropic-bots.json"}


class VendorLists:
    def __init__(self, ref_dir: str | None):
        self.lists: dict[str, list] = {}
        self.files: dict[str, list[str]] = {}   # file -> tokens it verifies, for the lists loaded
        if ref_dir:
            for fname, toks in VENDOR_FILES.items():
                self._load(os.path.join(ref_dir, fname), fname, toks)

    def _load(self, path: str, fname: str, toks: list[str]) -> bool:
        if not os.path.exists(path):
            return False
        with open(path, encoding="utf-8") as f:
            self.lists[fname] = networks_from_json(json.load(f))
        self.files[fname] = toks
        return True

    def match(self, ip: str | None) -> list[str]:
        """Names of every vendor list containing this IP."""
        if not ip:
            return []
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return []
        return [f for f, nets in self.lists.items() if any(a.version == n.version and a in n for n in nets)]

    def has_list_for(self, token: str) -> bool:
        return any(token in toks for toks in self.files.values())

    def files_for(self, token: str) -> list[str]:
        return [f for f, toks in self.files.items() if token in toks]


class AsnTable:
    """IPtoASN lookup. Rows: range_start, range_end, ASN, country, name (tab-separated)."""

    def __init__(self, path: str | None):
        self.starts = {4: [], 6: []}
        self.rows = {4: [], 6: []}
        self.loaded = False
        if path and os.path.exists(path):
            opener = gzip.open if path.endswith(".gz") else open
            tmp = {4: [], 6: []}
            with opener(path, "rt", encoding="utf-8", errors="replace") as f:
                for line in f:
                    p = line.rstrip("\n").split("\t")
                    if len(p) < 5:
                        continue
                    try:
                        a, b = ipaddress.ip_address(p[0]), ipaddress.ip_address(p[1])
                        asn = int(p[2])
                    except ValueError:
                        continue
                    tmp[a.version].append((int(a), int(b), asn, p[4]))
            for v in (4, 6):
                tmp[v].sort()
                self.rows[v] = tmp[v]
                self.starts[v] = [r[0] for r in tmp[v]]
            self.loaded = True
        self._cache: dict[str, tuple] = {}

    def lookup(self, ip: str | None) -> tuple[int, str] | None:
        if not ip or not self.loaded:
            return None
        if ip in self._cache:
            return self._cache[ip]
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return None
        n = int(a)
        i = bisect.bisect_right(self.starts[a.version], n) - 1
        res = None
        if i >= 0:
            s, e, asn, name = self.rows[a.version][i]
            if s <= n <= e and asn != 0:  # IPtoASN uses ASN 0 for "not routed"
                res = (asn, name)
        self._cache[ip] = res
        return res


def read_hosting_list(path: str) -> dict[int, str]:
    out = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            if not line.strip() or line.startswith("#"):
                continue
            p = line.rstrip("\n").split("\t")
            out[int(p[0])] = p[1]
    return out


def read_placements(path: str) -> dict[str, dict]:
    """code -> {placement, lures}"""
    out = {}
    if path and os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            for row in csv.DictReader(f):
                out[row["code"]] = {"placement": row["placement"], "lures": row["lures"].split(";")}
    return out


# --------------------------------------------------------------------------------------- signals

@dataclass
class Context:
    ua_tokens: list[dict]
    vendors: VendorLists
    asn: AsnTable
    hosting: dict[int, str]
    placements: dict[str, dict]
    baseline_start: datetime | None
    lure_start: datetime | None
    cutoff: datetime | None


def period_of(ts: datetime, ctx: Context) -> str:
    if ctx.baseline_start and ts < ctx.baseline_start:
        return "before_start"
    if ctx.lure_start is None or ts < ctx.lure_start:
        return "baseline"
    if ctx.cutoff and ts > ctx.cutoff:
        return "after_cutoff"
    return "lure"


def beacon_events(req: dict) -> list[str]:
    body = (req.get("body") or {}).get("kept_text")
    if not body:
        return []
    try:
        d = json.loads(body)
    except json.JSONDecodeError:
        return []
    e = d.get("e") if isinstance(d, dict) else None
    return [e] if isinstance(e, str) else []


def session_signals(s: Session, ctx: Context) -> dict:
    reqs = s.requests
    paths = [r.get("path") or "" for r in reqs]
    out: dict = {
        "start": s.start.isoformat(), "end": s.end.isoformat(),
        "period": period_of(s.start, ctx),
        "ip": s.ip, "user_agent": s.ua, "n_requests": len(reqs),
        "statuses": dict(Counter(str(r.get("status")) for r in reqs)),
        "edge": dict(Counter((r.get("edge") or {}).get("edge_name", "none") for r in reqs)),
    }

    # Run label: ?r=<run id> on any request (section 7).
    runs = set()
    for r in reqs:
        q = parse_qs(r.get("query") or "")
        runs.update(q.get("r", []))
    out["run_id"] = ";".join(sorted(runs)) or None

    # S1: declared AI user agent.
    hits = [t for t in ctx.ua_tokens if t["token"].lower() in s.ua.lower()]
    ai_hits = [t for t in hits if t["ai"]]
    out["S1_ai_ua"] = bool(ai_hits)
    out["S1_tokens"] = ";".join(t["token"] for t in hits) or None
    out["S1_kind"] = ";".join(sorted({t["kind"] for t in ai_hits})) or None

    # S2: IP on a vendor list.
    lists = ctx.vendors.match(s.ip)
    out["S2_vendor_lists"] = ";".join(lists) or None
    out["S2_on_list"] = bool(lists)
    # Whether the matching list(s) separate bulk crawling from on-request fetching (section 4c, F3).
    out["S2_role_separated"] = (any(f not in ROLE_COMBINED_FILES for f in lists)) if lists else None

    # False declaration tag: claims a token whose vendor publishes a list, IP not on that list.
    false_decl = []
    for t in hits:
        if ctx.vendors.has_list_for(t["token"]):
            own = ctx.vendors.files_for(t["token"])
            if not any(f in lists for f in own):
                false_decl.append(t["token"])
    out["false_declaration"] = ";".join(false_decl) or None

    # S3: network type.
    a = ctx.asn.lookup(s.ip)
    out["asn"] = a[0] if a else None
    out["asn_name"] = a[1] if a else None
    if not ctx.asn.loaded:
        out["S3_network"] = None  # missing, not "other"
    else:
        out["S3_network"] = ctx.hosting.get(a[0], "other") if a else "other"

    # S4: signed request headers.
    sig_agent = None
    signed = False
    for r in reqs:
        if header(r, "signature") or header(r, "signature-input") or header(r, "signature-agent"):
            signed = True
            sig_agent = sig_agent or header(r, "signature-agent")
    out["S4_signed"] = signed
    out["S4_signature_agent"] = sig_agent

    # S5: script and subresources.
    events = [e for r in reqs if r.get("path") == "/api/b" for e in beacon_events(r)]
    out["S5_script_fetched"] = "/static/b.js" in paths
    out["S5_beacon_load"] = "load" in events
    out["S5_css"] = "/static/site.css" in paths
    out["S5_image"] = "/static/mark.svg" in paths

    # S6: input events.
    out["S6_input_events"] = ";".join(sorted({e for e in events if e in ("scroll", "pointer", "key")})) or None

    # S7, S8, S11, S12: lure URLs.
    lure_hits = []
    for r in reqs:
        m = LURE_RE.match(r.get("path") or "")
        if m:
            lure_hits.append((r, m.group(1), m.group(2), m.group(3) or ""))
    codes = sorted({c for _, _, c, _ in lure_hits})
    out["S8_codes"] = ";".join(codes) or None
    out["S8_placements"] = ";".join(sorted({ctx.placements[c]["placement"] for c in codes if c in ctx.placements})) or None
    v = [(c, rest) for _, kind, c, rest in lure_hits if kind == "v"]
    out["S7_correct"] = any(rest.strip("/") == CORRECT_ANSWER for _, rest in v)
    out["S7_answers"] = ";".join(sorted({rest.strip("/") for _, rest in v})) or None

    # Exposure to L2/L3: loaded a page carrying them while lures were on.
    exposed_ts = [r["_ts"] for r in reqs if (r.get("path") in L2_L3_PAGES and r.get("status") == 200
                                             and period_of(r["_ts"], ctx) in ("lure", "after_cutoff"))]
    exposed = bool(exposed_ts)

    r_hits = [(r, c) for r, kind, c, _ in lure_hits if kind == "r"]
    if r_hits:
        q = parse_qs(r_hits[0][0].get("query") or "")
        out["S11_self_report"] = (q.get("for_person") or [None])[0]
        out["S11_model"] = (q.get("model") or [None])[0]
    elif exposed:
        out["S11_self_report"] = "none"
        out["S11_model"] = None
    else:
        out["S11_self_report"] = "not_applicable"
        out["S11_model"] = None

    c_hits = [r for r, kind, c, rest in lure_hits if kind == "c"]
    if c_hits:
        t_c = c_hits[0]["_ts"]
        before = [t for t in exposed_ts if t <= t_c]
        gap = (t_c - before[-1]).total_seconds() if before else None
        out["S12_gap_seconds"] = gap
        out["S12_pause"] = (gap is not None and gap > PAUSE_SECONDS)
    elif exposed:
        out["S12_gap_seconds"] = None
        out["S12_pause"] = "no_ok_request"
    else:
        out["S12_gap_seconds"] = None
        out["S12_pause"] = "not_applicable"

    # S9: median gap between page requests (pages and lure URLs only).
    page_ts = [r["_ts"] for r in reqs if (r.get("path") in PAGE_PATHS or LURE_RE.match(r.get("path") or ""))]
    gaps = [(b - a).total_seconds() for a, b in zip(page_ts, page_ts[1:])]
    out["S9_page_requests"] = len(page_ts)
    out["S9_median_gap_s"] = round(statistics.median(gaps), 3) if gaps else None

    # S10: robots.txt before the first page.
    first_page = next((i for i, p in enumerate(paths) if p in PAGE_PATHS), None)
    first_robots = next((i for i, p in enumerate(paths) if p == "/robots.txt"), None)
    out["S10_robots_first"] = (first_robots is not None and (first_page is None or first_robots < first_page))

    out["_codes"] = codes  # used for S13
    return out


def add_return_visits(rows: list[dict]) -> None:
    """S13: same IP and user agent, or same lure code, seen on 2 or more UTC days."""
    days_by_key = defaultdict(set)
    days_by_code = defaultdict(set)
    for r in rows:
        day = r["start"][:10]
        days_by_key[(r["ip"], r["user_agent"])].add(day)
        for c in r["_codes"]:
            days_by_code[c].add(day)
    for r in rows:
        n = len(days_by_key[(r["ip"], r["user_agent"])])
        nc = max([len(days_by_code[c]) for c in r["_codes"]] or [0])
        r["S13_days_seen"] = max(n, nc)
        r["S13_return"] = max(n, nc) >= 2
        del r["_codes"]


def analyse(log_dir: str, ctx: Context, operator_ips: set[str] | None = None,
            run_windows: list | None = None) -> tuple[list[dict], LoadReport]:
    rep = LoadReport()
    reqs = load_requests(log_dir, ctx.baseline_start, operator_ips, rep, run_windows)
    rows = [session_signals(s, ctx) for s in build_sessions(reqs)]
    add_return_visits(rows)
    return rows, rep


# ------------------------------------------------------------------------------------- outputs

CSV_FIELDS = ["start", "end", "period", "ip", "user_agent", "n_requests", "run_id",
              "S1_ai_ua", "S1_tokens", "S1_kind", "S2_on_list", "S2_vendor_lists", "S2_role_separated", "false_declaration",
              "asn", "asn_name", "S3_network", "S4_signed", "S4_signature_agent",
              "S5_script_fetched", "S5_beacon_load", "S5_css", "S5_image", "S6_input_events",
              "S7_correct", "S7_answers", "S8_codes", "S8_placements", "S9_page_requests",
              "S9_median_gap_s", "S10_robots_first", "S11_self_report", "S11_model",
              "S12_gap_seconds", "S12_pause", "S13_days_seen", "S13_return", "statuses", "edge"]


def write_csv(rows: list[dict], path: str) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=CSV_FIELDS, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            r2 = dict(r)
            r2["statuses"] = json.dumps(r["statuses"], sort_keys=True)
            r2["edge"] = json.dumps(r["edge"], sort_keys=True)
            w.writerow(r2)


def summary(rows: list[dict], rep: LoadReport, top: int = 12) -> str:
    """Counts only: no IP addresses."""
    lines = []
    add = lines.append
    add(f"Log lines: {rep.lines} in {rep.files} files; kept {rep.kept}. Excluded: smoke tests {rep.smoke}, "
        f"operator {rep.operator}, before baseline start (pilot) {rep.before_start}, short-form (capped) {rep.capped}, "
        f"unreadable {rep.bad_json}.")
    by_period = Counter(r["period"] for r in rows)
    add(f"Sessions: {len(rows)} " + str(dict(by_period)))
    add(f"Distinct client IPs: {len({r['ip'] for r in rows})}; distinct user agents: {len({r['user_agent'] for r in rows})}")
    add("")
    add("Network type (S3): " + str(dict(Counter(str(r['S3_network']) for r in rows))))
    add("Top networks by sessions:")
    for (asn, name), n in Counter((r["asn"], r["asn_name"]) for r in rows).most_common(top):
        add(f"  {n:5d}  AS{asn}  {name}")
    add("")
    add(f"S1 declared AI user agent: {sum(r['S1_ai_ua'] for r in rows)} sessions; tokens: "
        + str(dict(Counter(r['S1_tokens'] for r in rows if r['S1_tokens']))))
    add(f"S2 on a vendor list: {sum(r['S2_on_list'] for r in rows)}; "
        + str(dict(Counter(r['S2_vendor_lists'] for r in rows if r['S2_vendor_lists']))))
    add(f"False declaration tag: {sum(1 for r in rows if r['false_declaration'])}; "
        + str(dict(Counter(r['false_declaration'] for r in rows if r['false_declaration']))))
    add(f"S4 signed requests: {sum(r['S4_signed'] for r in rows)}; agents: "
        + str(dict(Counter(r['S4_signature_agent'] for r in rows if r['S4_signature_agent']))))
    add(f"S5 script fetched: {sum(r['S5_script_fetched'] for r in rows)}; beacon load fired: "
        f"{sum(r['S5_beacon_load'] for r in rows)}; CSS: {sum(r['S5_css'] for r in rows)}; image: {sum(r['S5_image'] for r in rows)}")
    add(f"S6 input events: {sum(1 for r in rows if r['S6_input_events'])}")
    add(f"S7 correct reasoning-lure answer: {sum(r['S7_correct'] for r in rows)}; any lure URL (S8): "
        f"{sum(1 for r in rows if r['S8_codes'])}")
    add(f"S10 robots.txt before first page: {sum(r['S10_robots_first'] for r in rows)}")
    add("S11: " + str(dict(Counter(str(r['S11_self_report']) for r in rows))))
    add("S12: " + str(dict(Counter(str(r['S12_pause']) for r in rows))))
    add(f"S13 seen on 2+ days: {sum(r['S13_return'] for r in rows)}")
    add(f"Sessions that requested at least one real page: {sum(1 for r in rows if r['S9_page_requests'])}")
    add("")
    add("Most common user agents (sessions):")
    for ua, n in Counter(r["user_agent"] for r in rows).most_common(top):
        add(f"  {n:5d}  {ua[:110] or '(none)'}")
    add("")
    add("Status mix (requests): " + str(dict(sum((Counter(r['statuses']) for r in rows), Counter()))))
    add("Most requested paths (requests):")
    for pth, n in rep.paths.most_common(top):
        add(f"  {n:5d}  {pth[:100]}")
    return "\n".join(lines)
