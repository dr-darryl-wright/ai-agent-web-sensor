import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "analysis"))
import run_analysis  # noqa: E402


def test_scheduled_runs_do_not_open_operator_windows(tmp_path):
    p = tmp_path / "runs.csv"
    p.write_text("run_id,hypothesis,config,task_id,task_text,operator,start_utc,end_utc,notes\n"
                 "a,H6,claude-scheduled,S,x,me,2026-10-22T09:00:00+00:00,2026-11-01T09:00:00+00:00,\n"
                 "b,H5,chatgpt-search,A,x,me,2026-10-22T10:00:00+00:00,2026-10-22T10:05:00+00:00,\n")
    w = run_analysis.read_run_windows(str(p))
    assert len(w) == 1 and w[0][0].hour == 9 and w[0][0].minute == 59
