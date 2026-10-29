import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import agent_loop as al  # noqa: E402
import runs  # noqa: E402


@pytest.fixture(autouse=True)
def isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(al, "LOOP_DIR", str(tmp_path / "loop"))
    monkeypatch.setenv("HP_BASE_URL", "http://127.0.0.1:9")  # nothing listens: fetches fail fast
    monkeypatch.setattr(al.time, "sleep", lambda s: None)


def tool_call(i, url):
    return {"id": f"c{i}", "type": "function", "function": {"name": "fetch_url", "arguments": json.dumps({"url": url})}}


def reply(msg, total=100):
    return {"usage": {"prompt_tokens": total - 10, "completion_tokens": 10, "total_tokens": total},
            "choices": [{"message": {"role": "assistant", **msg}}]}


def test_stops_at_max_calls_and_logs_run():
    def always_fetch(messages, tools):
        return reply({"content": None, "tool_calls": [tool_call(len(messages), "http://127.0.0.1:9/")]})
    r = al.session(model_call=always_fetch)
    assert r["stop"] == "max_calls"
    assert len(r["fetched"]) == al.MAX_FETCHES  # further fetches refused by the per-run limit
    row = runs.read()[-1]
    assert row["config"] == "own-loop" and row["hypothesis"] == "H6" and row["end_utc"]


def test_refuses_other_sites():
    assert al.fetch("https://example.org/").startswith("Error: this tool can only fetch pages")
    assert al.fetch("file:///etc/passwd").startswith("Error")


def test_token_budget_blocks_new_sessions(monkeypatch):
    monkeypatch.setattr(al, "TOKEN_BUDGET", 150)
    al.session(model_call=lambda m, t: reply({"content": "done"}, total=200))
    with pytest.raises(SystemExit):
        al.session(model_call=lambda m, t: reply({"content": "done"}))


def test_page_text_keeps_offscreen_and_alt_drops_comments_and_scripts():
    html = ('<html><body><img src="x" alt="ALT-LURE"><p>Visible</p>'
            '<div style="position:absolute;left:-10000px">OFFSCREEN-LURE</div>'
            '<!-- COMMENT-LURE --><script>var s="SCRIPT"</script></body></html>')
    t = al.page_text(html, "text/html")
    assert "ALT-LURE" in t and "OFFSCREEN-LURE" in t and "Visible" in t
    assert "COMMENT-LURE" not in t and "SCRIPT" not in t


def test_local_model_needs_no_key_and_logs_its_own_config(monkeypatch):
    monkeypatch.setattr(al, "API_URL", "http://localhost:11434/v1/chat/completions")
    monkeypatch.setattr(al, "LOOP_CONFIG", "own-loop-local")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    seen = {}

    def fake_urlopen(req, timeout=0):
        seen["auth"] = req.headers.get("Authorization")
        raise al.urllib.error.URLError("no server in tests")

    monkeypatch.setattr(al.urllib.request, "urlopen", fake_urlopen)
    with pytest.raises(al.urllib.error.URLError):
        al.call_openai([{"role": "user", "content": "hi"}])
    assert seen["auth"] == "Bearer local"
    r = al.session(model_call=lambda m, t: reply({"content": "done"}))
    assert runs.read()[-1]["config"] == "own-loop-local" and r["stop"] == "done"
