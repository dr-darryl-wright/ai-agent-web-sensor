import json
import os
import re
import sys

from starlette.testclient import TestClient

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, "..", "app"))

import app as site  # noqa: E402
from lures import LureConfig, load_placements  # noqa: E402

PLACEMENTS = os.path.join(HERE, "..", "lures", "placements.csv")
FIXTURE = os.path.join(HERE, "fixtures", "baseline_pages.json")


def lures_on():
    return LureConfig(True, load_placements(PLACEMENTS), "example.test")


def codes():
    return {k: v["code"] for k, v in load_placements(PLACEMENTS).items()}


def test_lures_off_is_byte_identical_to_baseline(tmp_path):
    c = TestClient(site.create_app(str(tmp_path), lures=LureConfig(False, {}, "x")))
    saved = json.load(open(FIXTURE))
    for path, want in saved.items():
        r = c.get(path)
        assert r.status_code == want["status"], path
        assert r.headers["content-type"] == want["ctype"], path
        assert r.text == want["body"], f"{path} changed with lures off"


def test_lure_urls_are_404_when_off(tmp_path):
    c = TestClient(site.create_app(str(tmp_path), lures=LureConfig(False, {}, "x")))
    assert c.get("/v/abcdef/42").status_code == 404
    assert c.get("/r/abcdef?for_person=yes").status_code == 404


def test_placements_file():
    p = load_placements(PLACEMENTS)
    assert sorted(p) == [f"P{i}" for i in range(1, 8)]
    cs = [v["code"] for v in p.values()]
    assert len(set(cs)) == 7 and all(re.fullmatch(r"[a-z2-9]{6}", c) for c in cs)
    assert p["P1"]["lures"] == ["L1", "L2", "L3"] and p["P4"]["lures"] == ["L1", "L2", "L3"]
    assert all(p[k]["lures"] == ["L1"] for k in ("P2", "P3", "P5", "P6", "P7"))


def test_home_page_carries_p1_hidden_and_p2_comment(tmp_path):
    c = TestClient(site.create_app(str(tmp_path), lures=lures_on()))
    body = c.get("/").text
    k = codes()
    hidden = re.search(r'<div style="position:absolute;left:-10000px[^"]*">(.*?)</div>', body, re.S)
    assert hidden, "P1 block missing"
    h = hidden.group(1)
    assert f"https://example.test/v/{k['P1']}/" in h
    assert f"https://example.test/r/{k['P1']}?for_person=yes" in h
    assert f"https://example.test/c/{k['P1']}/ok" in h
    assert "seventeen and twenty-five" in h and "research study" in h
    comment = re.search(r"<!-- (.*?) -->", body, re.S)
    assert comment and f"/v/{k['P2']}/" in comment.group(1)
    assert "--" not in comment.group(1)
    assert f"/r/{k['P2']}" not in body  # P2 carries L1 only


def test_note_page_carries_p3_in_alt_only(tmp_path):
    c = TestClient(site.create_app(str(tmp_path), lures=lures_on()))
    body = c.get("/notes/http-caching").text
    alt = re.search(r'<img src="/static/mark.svg" alt="([^"]*)">', body).group(1)
    assert f"/v/{codes()['P3']}/" in alt
    assert "position:absolute" not in body and "<!--" not in body


def test_other_pages_have_no_lures(tmp_path):
    c = TestClient(site.create_app(str(tmp_path), lures=lures_on()))
    saved = json.load(open(FIXTURE))
    for path in ("/privacy", "/sitemap.xml", "/static/site.css", "/static/mark.svg", "/static/b.js"):
        assert c.get(path).text == saved[path]["body"], path


def test_llms_and_robots(tmp_path):
    c = TestClient(site.create_app(str(tmp_path), lures=lures_on()))
    k = codes()
    llms = c.get("/llms.txt").text
    assert f"/v/{k['P4']}/" in llms and f"/r/{k['P4']}" in llms and f"/c/{k['P4']}/ok" in llms
    robots = c.get("/robots.txt").text
    assert f"/v/{k['P5']}/" in robots
    for line in robots.splitlines():
        assert line == "" or line.startswith("#") or ":" in line, f"bad robots line: {line!r}"


def test_lure_endpoints_answer_and_are_logged(tmp_path):
    c = TestClient(site.create_app(str(tmp_path), lures=lures_on()))
    k = codes()
    for path in (f"/v/{k['P1']}/42", f"/v/{k['P1']}/41", f"/v/{k['P1']}/",
                 f"/r/{k['P1']}?for_person=no&model=test", f"/c/{k['P1']}/ok", "/v/zzzzzz/42"):
        r = c.get(path)
        assert r.status_code == 200 and "Thank you" in r.text, path
        assert r.headers["cache-control"] == "no-store"
    lines = [json.loads(l) for f in os.listdir(tmp_path) for l in open(tmp_path / f)]
    assert [l["path"] for l in lines][:2] == [f"/v/{k['P1']}/42", f"/v/{k['P1']}/41"]
    assert lines[3]["query"] == "for_person=no&model=test"
