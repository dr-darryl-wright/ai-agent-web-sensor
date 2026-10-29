import gzip
import json
import os
import sys
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, "..", "analysis"))

import hpa  # noqa: E402

ROOT = os.path.join(HERE, "..")
T0 = datetime(2026, 10, 22, 12, 0, 0, tzinfo=timezone.utc)
BASE = datetime(2026, 10, 18, 21, 37, 30, tzinfo=timezone.utc)
LURE = datetime(2026, 10, 22, 9, 0, 0, tzinfo=timezone.utc)


def rec(ts, path, ip="198.51.100.5", ua="Mozilla/5.0 Test", status=200, query="", body=None, headers=None, capped=False):
    if capped:
        return {"v": 1, "ts": ts.isoformat(), "capped": True, "edge": {"client_ip": ip}, "method": "GET",
                "path": path, "status": status}
    h = [["user-agent", ua]] + (headers or [])
    r = {"v": 1, "ts": ts.isoformat(timespec="microseconds"), "id": "x", "edge": {"client_ip": ip, "edge_name": "https"},
         "method": "POST" if path == "/api/b" else "GET", "path": path, "raw_path": path, "query": query,
         "headers": h, "body": None, "status": status, "resp_bytes": 10}
    if body is not None:
        r["body"] = {"kept_text": json.dumps(body), "length": 10}
    return r


def write_logs(d, records):
    by_day = {}
    for r in records:
        by_day.setdefault(r["ts"][:10], []).append(r)
    for day, rs in by_day.items():
        with open(os.path.join(d, f"requests-{day}.jsonl"), "w") as f:
            for r in rs:
                f.write(json.dumps(r) + "\n")


def make_ctx(tmp_path, with_ref=True):
    ref = tmp_path / "ref"
    ref.mkdir()
    if with_ref:
        (ref / "openai-chatgpt-user.json").write_text(json.dumps({"prefixes": [{"ipv4Prefix": "20.1.0.0/16"}]}))
        (ref / "openai-gptbot.json").write_text(json.dumps({"prefixes": [{"ipv4Prefix": "20.2.0.0/16"}]}))
        with gzip.open(ref / "ip2asn-combined.tsv.gz", "wt") as f:
            f.write("20.0.0.0\t20.255.255.255\t8075\tUS\tMICROSOFT-CORP\n")
            f.write("104.16.0.0\t104.31.255.255\t13335\tUS\tCLOUDFLARENET\n")
            f.write("198.51.100.0\t198.51.100.255\t64500\tGB\tHOME-ISP\n")
            f.write("203.0.113.0\t203.0.113.255\t0\tNone\tNot routed\n")
    return hpa.Context(
        ua_tokens=hpa.read_ua_tokens(os.path.join(ROOT, "signals", "ai_user_agents.txt")),
        vendors=hpa.VendorLists(str(ref)),
        asn=hpa.AsnTable(str(ref / "ip2asn-combined.tsv.gz") if with_ref else None),
        hosting=hpa.read_hosting_list(os.path.join(ROOT, "signals", "hosting_asns.txt")),
        placements=hpa.read_placements(os.path.join(ROOT, "lures", "placements.csv")),
        baseline_start=BASE, lure_start=LURE, cutoff=datetime(2026, 10, 31, 23, 59, 59, tzinfo=timezone.utc))


def run(tmp_path, records, ops=None, windows=None, with_ref=True):
    logs = tmp_path / "logs"
    logs.mkdir()
    write_logs(str(logs), records)
    return hpa.analyse(str(logs), make_ctx(tmp_path, with_ref), ops or set(), windows or [])


def code(p):
    return {v["placement"]: k for k, v in hpa.read_placements(os.path.join(ROOT, "lures", "placements.csv")).items()}[p]


def test_exclusions_and_capped(tmp_path):
    recs = [rec(T0, "/", ua="HP-SMOKE-TEST/1"),
            rec(BASE - timedelta(minutes=5), "/"),
            rec(T0, "/", ip="192.0.2.9"),                                  # operator, outside run
            rec(T0 + timedelta(hours=1), "/", ip="192.0.2.9", ua="agent"),  # operator, inside run
            rec(T0, "/x", capped=True),
            rec(T0, "/")]
    rows, rep = run(tmp_path, recs, ops={"192.0.2.9"},
                    windows=[(T0 + timedelta(minutes=50), T0 + timedelta(minutes=70))])
    assert (rep.smoke, rep.before_start, rep.operator, rep.capped, rep.kept) == (1, 1, 1, 1, 2)
    assert rep.capped_by_day["2026-10-22"] == 1
    assert len(rows) == 2


def test_sessions_split_on_gap_and_key(tmp_path):
    recs = [rec(T0, "/"), rec(T0 + timedelta(minutes=29), "/privacy"),
            rec(T0 + timedelta(minutes=29 + 31), "/"),             # gap over 30 min -> new session
            rec(T0, "/", ua="Other")]                              # different UA -> own session
    rows, _ = run(tmp_path, recs)
    assert sorted(r["n_requests"] for r in rows) == [1, 1, 2]


def test_s1_s2_false_declaration(tmp_path):
    recs = [rec(T0, "/", ip="20.1.5.5", ua="Mozilla/5.0; compatible; ChatGPT-User/1.0"),      # genuine
            rec(T0, "/", ip="198.51.100.7", ua="Mozilla/5.0; compatible; ChatGPT-User/1.0"),  # false
            rec(T0, "/", ip="198.51.100.8", ua="ClaudeBot/1.0"),                               # no list
            rec(T0, "/", ip="198.51.100.9", ua="Googlebot/2.1")]                               # general search
    rows = {r["ip"]: r for r in run(tmp_path, recs)[0]}
    g = rows["20.1.5.5"]
    assert g["S1_ai_ua"] and g["S1_kind"] == "user_fetch" and g["S2_on_list"] and g["false_declaration"] is None
    f = rows["198.51.100.7"]
    assert f["S1_ai_ua"] and not f["S2_on_list"] and f["false_declaration"] == "ChatGPT-User"
    c = rows["198.51.100.8"]
    assert c["S1_ai_ua"] and c["false_declaration"] is None   # no Anthropic list in this reference set: no tag
    gb = rows["198.51.100.9"]
    assert gb["S1_ai_ua"] is False and gb["S1_tokens"] == "Googlebot"


def test_s3_network_types(tmp_path):
    recs = [rec(T0, "/", ip="20.9.9.9"), rec(T0, "/", ip="104.16.1.1"),
            rec(T0, "/", ip="198.51.100.5"), rec(T0, "/", ip="203.0.113.5"), rec(T0, "/", ip="2001:db8::1")]
    rows = {r["ip"]: r for r in run(tmp_path, recs)[0]}
    assert rows["20.9.9.9"]["S3_network"] == "hosting" and rows["20.9.9.9"]["asn"] == 8075
    assert rows["104.16.1.1"]["S3_network"] == "edge_proxy"
    assert rows["198.51.100.5"]["S3_network"] == "other"
    assert rows["203.0.113.5"]["asn"] is None and rows["203.0.113.5"]["S3_network"] == "other"
    assert rows["2001:db8::1"]["S3_network"] == "other"


def test_s3_missing_without_reference(tmp_path):
    rows, _ = run(tmp_path, [rec(T0, "/")], with_ref=False)
    assert rows[0]["S3_network"] is None and rows[0]["S2_on_list"] is False


def test_s4_s5_s6(tmp_path):
    sig = [["signature-agent", '"https://chatgpt.com"'], ["signature-input", "sig1=..."]]
    recs = [rec(T0, "/", headers=sig), rec(T0 + timedelta(seconds=1), "/static/site.css"),
            rec(T0 + timedelta(seconds=1), "/static/b.js"),
            rec(T0 + timedelta(seconds=2), "/api/b", body={"e": "load"}),
            rec(T0 + timedelta(seconds=5), "/api/b", body={"e": "scroll"}),
            rec(T0 + timedelta(seconds=6), "/api/b", body={"e": "hidden"})]
    r = run(tmp_path, recs)[0][0]
    assert r["S4_signed"] and r["S4_signature_agent"] == '"https://chatgpt.com"'
    assert r["S5_script_fetched"] and r["S5_beacon_load"] and r["S5_css"] and not r["S5_image"]
    assert r["S6_input_events"] == "scroll"


def test_s7_s8_reasoning_lure(tmp_path):
    c1 = code("P1")
    recs = [rec(T0, "/"), rec(T0 + timedelta(seconds=4), f"/v/{c1}/42"),
            rec(T0, "/", ua="B"), rec(T0 + timedelta(seconds=3), f"/v/{c1}/41", ua="B")]
    rows = {r["user_agent"]: r for r in run(tmp_path, recs)[0]}
    a = rows["Mozilla/5.0 Test"]
    assert a["S7_correct"] and a["S8_placements"] == "P1" and a["S7_answers"] == "42"
    assert not rows["B"]["S7_correct"] and rows["B"]["S7_answers"] == "41"


def test_s11_s12_not_applicable_in_baseline(tmp_path):
    r = run(tmp_path, [rec(LURE - timedelta(hours=1), "/")])[0][0]
    assert r["period"] == "baseline"
    assert r["S11_self_report"] == "not_applicable" and r["S12_pause"] == "not_applicable"


def test_s11_s12_in_lure_period(tmp_path):
    c1 = code("P1")
    recs = [rec(T0, "/"), rec(T0 + timedelta(seconds=90), f"/c/{c1}/ok"),
            rec(T0 + timedelta(seconds=95), f"/r/{c1}", query="for_person=yes&model=test-model"),
            rec(T0, "/", ua="C"),                                   # exposed, did nothing
            rec(T0, "/privacy", ua="D")]                            # not exposed
    rows = {r["user_agent"]: r for r in run(tmp_path, recs)[0]}
    a = rows["Mozilla/5.0 Test"]
    assert a["S12_gap_seconds"] == 90 and a["S12_pause"] is True
    assert a["S11_self_report"] == "yes" and a["S11_model"] == "test-model"
    assert rows["C"]["S11_self_report"] == "none" and rows["C"]["S12_pause"] == "no_ok_request"
    assert rows["D"]["S11_self_report"] == "not_applicable"


def test_s9_s10_s13_and_run_label(tmp_path):
    recs = [rec(T0, "/robots.txt"), rec(T0 + timedelta(seconds=1), "/", query="r=run-007"),
            rec(T0 + timedelta(seconds=4), "/privacy"), rec(T0 + timedelta(seconds=10), "/notes/http-caching"),
            rec(T0 + timedelta(days=1), "/")]
    rows = sorted(run(tmp_path, recs)[0], key=lambda r: r["start"])
    first = rows[0]
    assert first["S10_robots_first"] is True
    assert first["S9_page_requests"] == 3 and first["S9_median_gap_s"] == 4.5
    assert first["run_id"] == "run-007"
    assert first["S13_return"] is True and rows[1]["S13_days_seen"] == 2


def test_csv_and_summary(tmp_path):
    rows, rep = run(tmp_path, [rec(T0, "/"), rec(T0, "/.env", ua="scanner", status=404)])
    out = tmp_path / "out" / "sessions.csv"
    hpa.write_csv(rows, str(out))
    text = out.read_text()
    assert text.splitlines()[0].startswith("start,end,period,ip")
    s = hpa.summary(rows, rep)
    assert "198.51.100.5" not in s   # summary carries no IP addresses
    assert "Sessions: 2" in s



def test_anthropic_list_verifies_and_is_role_combined(tmp_path):
    recs = [rec(T0, "/", ip="203.0.113.5", ua="ClaudeBot/1.0"),     # on Anthropic's list
            rec(T0, "/", ip="198.51.100.8", ua="Claude-User/1.0"),  # not on it
            rec(T0, "/", ip="20.1.5.5", ua="ChatGPT-User/1.0")]     # role-specific list
    logs = tmp_path / "logs"
    logs.mkdir()
    write_logs(str(logs), recs)
    ctx = make_ctx(tmp_path)
    (tmp_path / "ref" / "anthropic-bots.json").write_text(json.dumps(
        {"creationTime": "2026-08-18T23:56:36Z", "prefixes": [{"ipv4Prefix": "203.0.113.0/28"}]}))
    ctx.vendors = hpa.VendorLists(str(tmp_path / "ref"))
    rows = {r["ip"]: r for r in hpa.analyse(str(logs), ctx, set(), [])[0]}
    v = rows["203.0.113.5"]
    assert v["S2_on_list"] and v["S2_vendor_lists"] == "anthropic-bots.json" and v["S2_role_separated"] is False
    assert v["false_declaration"] is None
    assert rows["198.51.100.8"]["false_declaration"] == "Claude-User"
    assert rows["20.1.5.5"]["S2_role_separated"] is True
