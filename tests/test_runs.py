import os
import sys
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import runs  # noqa: E402

T = datetime(2026, 10, 22, 9, 0, 0, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def tmp_runs(tmp_path, monkeypatch):
    monkeypatch.setattr(runs, "RUNS", str(tmp_path / "runs.csv"))
    monkeypatch.delenv("HP_BASE_URL", raising=False)


def test_start_logs_before_and_end_closes():
    r = runs.start("chatgpt-search", at=T)
    assert r["hypothesis"] == "H5" and r["task_id"] == "A"
    assert r["task_text"].endswith(f"?r={r['run_id']}") and "https://" in r["task_text"]
    assert runs.read()[0]["end_utc"] == ""
    runs.end(r["run_id"], note="ok", at=T + timedelta(minutes=3))
    row = runs.read()[0]
    assert row["end_utc"] == (T + timedelta(minutes=3)).isoformat() and row["notes"] == "ok"


def test_spacing_rule_and_alternating_tasks():
    runs.start("claude-web-fetch", at=T)
    with pytest.raises(SystemExit):
        runs.start("claude-web-fetch", at=T + timedelta(minutes=20))
    r2 = runs.start("claude-web-fetch", at=T + timedelta(minutes=36))
    assert r2["task_id"] == "B"
    runs.start("chatgpt-agent", at=T + timedelta(minutes=1))  # other configurations are not blocked


def test_unknown_config_and_double_end():
    with pytest.raises(SystemExit):
        runs.start("nonsense", at=T)
    r = runs.start("human-browse", at=T)
    runs.end(r["run_id"], at=T)
    with pytest.raises(SystemExit):
        runs.end(r["run_id"], at=T)


def test_status_lists_every_config():
    s = runs.status()
    for c in runs.CONFIGS:
        assert c in s
