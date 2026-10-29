import json
import os
import sys

import pytest
from starlette.applications import Starlette
from starlette.routing import Route
from starlette.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

import app as site  # noqa: E402
from reqlog import BODY_KEEP, BODY_READ_LIMIT, HEADER_VALUE_LIMIT, LoggingMiddleware, RequestLogger  # noqa: E402

EDGE = {
    "X-HP-Client-IP": "203.0.113.7",
    "X-HP-Client-Port": "51234",
    "X-HP-Proto": "HTTP/2.0",
    "X-HP-TLS-Version": "tls1.3",
    "X-HP-TLS-SNI": "example.test",
}


def read_lines(log_dir):
    out = []
    for name in sorted(os.listdir(log_dir)):
        with open(os.path.join(log_dir, name), encoding="utf-8") as f:
            out += [json.loads(line) for line in f]
    return out


@pytest.fixture
def client(tmp_path):
    return TestClient(site.create_app(str(tmp_path))), tmp_path


def test_index_logged_with_edge_facts(client):
    c, d = client
    r = c.get("/", headers={**EDGE, "User-Agent": "TestAgent/1.0"})
    assert r.status_code == 200
    assert r.headers["cache-control"] == "no-store"
    assert "Short technical notes" in r.text
    [rec] = read_lines(d)
    assert rec["v"] == 1
    assert rec["method"] == "GET" and rec["path"] == "/" and rec["status"] == 200
    assert rec["edge"]["client_ip"] == "203.0.113.7"
    assert rec["edge"]["tls_version"] == "tls1.3"
    assert rec["edge"]["http_version"] == "HTTP/2.0"
    names = [h[0].lower() for h in rec["headers"]]
    assert "user-agent" in names
    assert not any(n.startswith("x-hp-") for n in names)
    assert rec["resp_bytes"] == len(r.content)
    assert rec["body"] is None


def test_day_file_name(client):
    c, d = client
    c.get("/")
    [name] = os.listdir(d)
    rec = read_lines(d)[0]
    assert name == f"requests-{rec['ts'][:10]}.jsonl"


def test_proxy_headers_dropped_but_client_xff_kept(client):
    c, d = client
    c.get("/", headers={"X-Forwarded-For": "10.0.0.1", "X-HP-Orig-XFF": "1.2.3.4, 5.6.7.8"})
    [rec] = read_lines(d)
    assert rec["edge"]["orig_x_forwarded_for"] == "1.2.3.4, 5.6.7.8"
    assert "x-forwarded-for" not in [h[0].lower() for h in rec["headers"]]


def test_unknown_internal_header_not_logged_as_client(client):
    c, d = client
    c.get("/", headers={"X-HP-Something": "spoof"})
    [rec] = read_lines(d)
    assert all(not h[0].lower().startswith("x-hp-") for h in rec["headers"])


def test_header_order_preserved(client):
    c, d = client
    c.get("/", headers=[("X-Zeta", "1"), ("X-Alpha", "2"), ("X-Mid", "3")])
    [rec] = read_lines(d)
    names = [h[0].lower() for h in rec["headers"] if h[0].lower().startswith("x-")]
    assert names == ["x-zeta", "x-alpha", "x-mid"]


def test_long_header_truncated(client):
    c, d = client
    c.get("/", headers={"X-Long": "a" * (HEADER_VALUE_LIMIT + 100)})
    [rec] = read_lines(d)
    val = dict((k.lower(), v) for k, v in rec["headers"])["x-long"]
    assert len(val) == HEADER_VALUE_LIMIT
    assert rec["headers_truncated"] is True


def test_beacon_body_logged(client):
    c, d = client
    r = c.post("/api/b", content='{"e":"load","p":"/","ms":12}', headers={"Content-Type": "text/plain"})
    assert r.status_code == 204
    [rec] = read_lines(d)
    assert rec["body"]["kept_text"] == '{"e":"load","p":"/","ms":12}'
    assert rec["body"]["length"] == 28


def test_large_body_bounded(client):
    c, d = client
    big = b"x" * (BODY_READ_LIMIT + 5000)
    c.post("/api/b", content=big)
    [rec] = read_lines(d)
    b = rec["body"]
    assert b["length"] == len(big)
    assert b["read_bytes"] == BODY_READ_LIMIT
    assert b["read_truncated"] is True
    assert b["kept_truncated"] is True
    import base64
    assert len(base64.b64decode(b["kept_b64"])) == BODY_KEEP


def test_binary_body_has_no_text(client):
    c, d = client
    c.post("/api/b", content=b"\xff\xfe\x00bad")
    [rec] = read_lines(d)
    assert "kept_text" not in rec["body"]


def test_404_and_405_logged(client):
    c, d = client
    assert c.get("/wp-login.php").status_code == 404
    assert c.get("/api/b").status_code == 405
    recs = read_lines(d)
    assert [r["status"] for r in recs] == [404, 405]
    assert recs[0]["path"] == "/wp-login.php"


def test_query_and_raw_path_logged(client):
    c, d = client
    c.get("/notes/http-caching?x=1&y=%2F")
    [rec] = read_lines(d)
    assert rec["query"] == "x=1&y=%2F"
    assert rec["status"] == 200


def test_head_works(client):
    c, d = client
    r = c.head("/")
    assert r.status_code == 200
    assert read_lines(d)[0]["method"] == "HEAD"


@pytest.mark.parametrize("path,ctype", [
    ("/robots.txt", "text/plain"),
    ("/sitemap.xml", "application/xml"),
    ("/llms.txt", "text/plain"),
    ("/static/site.css", "text/css"),
    ("/static/mark.svg", "image/svg+xml"),
    ("/static/b.js", "text/javascript"),
    ("/privacy", "text/html"),
])
def test_all_files_served(client, path, ctype):
    c, _ = client
    r = c.get(path)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith(ctype)


def test_port80_redirects_own_domain_and_is_logged(tmp_path):
    c = TestClient(site.create_app(str(tmp_path), domain="example.test"))
    r = c.get("/notes/http-caching?a=1", headers={"Host": "example.test", "X-HP-Edge": "http80"},
              follow_redirects=False)
    assert r.status_code == 301
    assert r.headers["location"] == "https://example.test/notes/http-caching?a=1"
    [rec] = read_lines(tmp_path)
    assert rec["status"] == 301 and rec["edge"]["edge_name"] == "http80"


def test_port80_other_host_gets_404(tmp_path):
    c = TestClient(site.create_app(str(tmp_path), domain="example.test"))
    r = c.get("/", headers={"Host": "192.0.2.10", "X-HP-Edge": "http80"}, follow_redirects=False)
    assert r.status_code == 404
    assert read_lines(tmp_path)[0]["status"] == 404


def test_daily_cap_shortens_lines(tmp_path):
    c = TestClient(LoggingMiddleware(site.create_app(str(tmp_path)).app,
                                     RequestLogger(str(tmp_path), daily_cap=1)))
    c.get("/", headers={**EDGE, "User-Agent": "first"})
    c.get("/robots.txt", headers={**EDGE, "User-Agent": "second"})
    first, second = read_lines(tmp_path)
    assert "capped" not in first and first["headers"]
    assert second["capped"] is True
    assert "headers" not in second and "body" not in second
    assert second["edge"]["client_ip"] == "203.0.113.7"
    assert second["path"] == "/robots.txt" and second["status"] == 200


def test_logging_failure_does_not_break_response(tmp_path):
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("x")
    c = TestClient(site.create_app(str(blocker)))
    assert c.get("/").status_code == 200


def test_handler_exception_is_logged(tmp_path):
    async def boom(request):
        raise RuntimeError("boom")

    inner = Starlette(routes=[Route("/x", boom)])
    c = TestClient(LoggingMiddleware(inner, RequestLogger(str(tmp_path))), raise_server_exceptions=False)
    r = c.get("/x")
    assert r.status_code == 500
    [rec] = read_lines(tmp_path)
    assert "boom" in rec["error"]
