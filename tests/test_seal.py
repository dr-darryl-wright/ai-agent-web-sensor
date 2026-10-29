import os
import sys
from datetime import date

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

import seal_logs as s  # noqa: E402


def write(d, day, text):
    (d / f"requests-{day}.jsonl").write_text(text)


def test_seals_complete_days_in_order_and_fills_gaps(tmp_path):
    logs = tmp_path / "logs"
    logs.mkdir()
    write(logs, "2026-10-17", '{"a":1}\n{"a":2}\n')
    write(logs, "2026-10-19", '{"a":3}\n')
    write(logs, "2026-10-20", '{"a":4}\n')  # "today": must not be sealed
    seals = tmp_path / "seals.jsonl"
    new = s.seal(str(logs), str(seals), today=date(2026, 10, 20))
    assert [r["date"] for r in new] == ["2026-10-17", "2026-10-18", "2026-10-19"]
    assert new[1]["missing"] is True and new[1]["lines"] == 0
    assert new[0]["lines"] == 2
    assert new[0]["prev_chain"] == s.GENESIS
    assert new[1]["prev_chain"] == new[0]["chain"]
    assert s.verify(str(logs), str(seals)) == []


def test_rerun_is_idempotent_and_continues(tmp_path):
    logs = tmp_path / "logs"
    logs.mkdir()
    write(logs, "2026-10-17", "x\n")
    seals = tmp_path / "seals.jsonl"
    s.seal(str(logs), str(seals), today=date(2026, 10, 18))
    assert s.seal(str(logs), str(seals), today=date(2026, 10, 18)) == []
    write(logs, "2026-10-18", "y\n")
    new = s.seal(str(logs), str(seals), today=date(2026, 10, 19))
    assert [r["date"] for r in new] == ["2026-10-18"]
    assert s.verify(str(logs), str(seals)) == []


def test_edit_is_detected(tmp_path):
    logs = tmp_path / "logs"
    logs.mkdir()
    write(logs, "2026-10-17", '{"ip":"1.2.3.4"}\n')
    write(logs, "2026-10-18", '{"ip":"5.6.7.8"}\n')
    seals = tmp_path / "seals.jsonl"
    s.seal(str(logs), str(seals), today=date(2026, 10, 19))
    write(logs, "2026-10-17", '{"ip":"9.9.9.9"}\n')
    problems = s.verify(str(logs), str(seals))
    assert problems == ["2026-10-17: log file differs from its seal"]


def test_seal_line_edit_breaks_chain(tmp_path):
    logs = tmp_path / "logs"
    logs.mkdir()
    write(logs, "2026-10-17", "a\n")
    write(logs, "2026-10-18", "b\n")
    seals = tmp_path / "seals.jsonl"
    s.seal(str(logs), str(seals), today=date(2026, 10, 19))
    lines = seals.read_text().splitlines()
    lines[0] = lines[0].replace('"lines":1', '"lines":2')
    seals.write_text("\n".join(lines) + "\n")
    problems = s.verify(str(logs), str(seals))
    assert any("2026-10-17" in p for p in problems)


def test_no_logs_no_seals(tmp_path):
    assert s.seal(str(tmp_path / "none"), str(tmp_path / "seals.jsonl"), today=date(2026, 10, 20)) == []
