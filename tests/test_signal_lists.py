import gzip
import os
import sys

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, "..", "tools"))

import check_hosting_asns as c  # noqa: E402

LIST = os.path.join(HERE, "..", "signals", "hosting_asns.txt")
UA = os.path.join(HERE, "..", "signals", "ai_user_agents.txt")


def test_hosting_list_parses_and_has_valid_categories():
    rows = c.read_list(LIST)
    assert len(rows) >= 20
    assert {r["category"] for r in rows} <= {"hosting", "edge_proxy"}
    assert len({r["asn"] for r in rows}) == len(rows), "duplicate ASN"


def test_check_flags_ok_check_missing(tmp_path):
    snap = tmp_path / "ip2asn.tsv.gz"
    with gzip.open(snap, "wt") as f:
        f.write("1.0.0.0\t1.0.0.255\t16509\tUS\tAMAZON-02\n")
        f.write("2.0.0.0\t2.0.0.255\t14061\tUS\tSOME-OTHER-NAME\n")
    rows = [{"asn": 16509, "category": "hosting", "keyword": "AMAZON", "operator": ""},
            {"asn": 14061, "category": "hosting", "keyword": "DIGITALOCEAN", "operator": ""},
            {"asn": 24940, "category": "hosting", "keyword": "HETZNER", "operator": ""}]
    got = [s for s, _, _ in c.check(rows, c.read_names(str(snap)))]
    assert got == ["ok", "CHECK", "MISSING"]


def test_ua_list_rows_well_formed():
    kinds = {"training", "search_index", "user_fetch", "user_agent", "other_use"}
    tokens = []
    with open(UA, encoding="utf-8") as f:
        for line in f:
            if not line.strip() or line.startswith("#"):
                continue
            parts = line.rstrip("\n").split("\t")
            assert len(parts) == 5, line
            assert parts[2] in kinds, line
            tokens.append(parts[0].lower())
    assert len(tokens) == len(set(tokens))
    assert "chatgpt-user" in tokens and "claude-user" in tokens
