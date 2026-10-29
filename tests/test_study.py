import json
import os
import sys
from datetime import timedelta

import pytest

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, "..", "analysis"))
sys.path.insert(0, HERE)

import hpa  # noqa: E402
import run_study  # noqa: E402
import study  # noqa: E402
from test_analysis import BASE, T0, make_ctx, rec, write_logs  # noqa: E402

OP = "192.0.2.9"
RUN_HDR = "run_id,hypothesis,config,task_id,task_text,operator,start_utc,end_utc,notes\n"


def runs_csv(path, rows):
    with open(path, "w") as f:
        f.write(RUN_HDR)
        for rid, cfg, a, b, note in rows:
            f.write(f"{rid},{study.CONFIG_CLASS.get(cfg, 'H?')},{cfg},A,x,me,{a.isoformat()},"
                    f"{b.isoformat() if b else ''},{note}\n")


def build(tmp_path, records, run_rows):
    logs = tmp_path / "logs"
    logs.mkdir()
    write_logs(str(logs), records)
    rp = tmp_path / "runs.csv"
    runs_csv(rp, run_rows)
    import run_analysis
    runs = study.read_runs([str(rp)])
    windows = run_analysis.read_run_windows(str(rp))
    rows, rep, n_split = study.build_rows(str(logs), make_ctx(tmp_path), {OP}, windows, set(runs))
    counts = study.label_rows(rows, runs)
    return rows, counts, n_split


def by_run(rows):
    return {r["label_run"]: r for r in rows if r["label_run"]}


def test_d6_split_two_runs_from_one_browser(tmp_path):
    a, b = T0, T0 + timedelta(minutes=21)
    recs = [rec(a, "/", ip=OP, ua="Safari", query="r=run00001"), rec(a + timedelta(seconds=20), "/notes/http-caching", ip=OP, ua="Safari"),
            rec(b, "/", ip=OP, ua="Safari", query="r=run00002"), rec(b + timedelta(seconds=30), "/llms.txt", ip=OP, ua="Safari")]
    rows, counts, n_split = build(tmp_path, recs, [("run00001", "human-browse", a, a + timedelta(minutes=1), "ok"),
                                                   ("run00002", "human-lure", b, b + timedelta(minutes=2), "ok")])
    assert n_split == 1
    r = by_run(rows)
    assert r["run00001"]["n_requests"] == 2 and r["run00002"]["n_requests"] == 2
    assert r["run00001"]["label_status"] == r["run00002"]["label_status"] == "labelled"


def test_setup_void_and_approval(tmp_path, monkeypatch):
    s = T0
    monkeypatch.setattr(study, "APPROVALS", {"sched002": [(s + timedelta(days=1, hours=11)).isoformat()]})
    recs = [rec(s + timedelta(minutes=1), "/", ip="20.1.5.5", ua="Claude-User", query="r=sched001"),        # D2 setup
            rec(s + timedelta(days=1), "/", ip="20.1.5.6", ua="Claude-User", query="r=sched001"),           # H6
            rec(s + timedelta(days=1, hours=11, minutes=1), "/", ip="20.1.5.7", ua="GPT", query="r=sched002"),  # D5
            rec(s + timedelta(minutes=5), "/", ip="20.1.5.8", ua="GPT", query="r=void0001")]                # D4
    rows, counts, _ = build(tmp_path, recs, [("sched001", "claude-scheduled", s, None, ""),
                                             ("sched002", "chatgpt-scheduled", s, None, ""),
                                             ("void0001", "chatgpt-scheduled", s, s + timedelta(minutes=3), "VOID: test")])
    st = sorted((r["label_run"], r["label_status"]) for r in rows if r["label_run"])
    assert st == [("sched001", "labelled"), ("sched001", "setup"), ("sched002", "setup"), ("void0001", "void")]


def test_window_fallback_only_when_unique(tmp_path):
    a = T0
    recs = [rec(a + timedelta(seconds=30), "/", ip="20.1.5.5", ua="Agent-without-token")]
    rows, _, _ = build(tmp_path, recs, [("run00003", "claude-web-fetch", a, a + timedelta(minutes=2), "")])
    assert rows[0]["label_run"] == "run00003" and rows[0]["label_method"] == "window"
    # two candidates in the window -> ambiguous, no label
    (tmp_path / "b").mkdir()
    recs2 = recs + [rec(a + timedelta(seconds=40), "/", ip="198.51.100.77", ua="Scanner")]
    rows2, counts2, _ = build(tmp_path / "b", recs2, [("run00003", "claude-web-fetch", a, a + timedelta(minutes=2), "")])
    assert not any(r["label_run"] for r in rows2) and counts2["window_ambiguous_runs"] == 1


def test_split_is_stratified_and_repeatable():
    rows = [{"label_status": "labelled", "label_config": c, "label_run": f"{c}-{i}", "start": "2026-10-22T10:00:00"}
            for c, n in (("chatgpt-search", 5), ("claude-scheduled", 1), ("scraper", 4)) for i in range(n)]
    h1, h2 = study.split_runs(rows), study.split_runs(list(reversed(rows)))
    assert h1 == h2
    count = lambda c, h: sum(1 for k, v in h1.items() if k.startswith(c) and v == h)  # noqa: E731
    assert (count("chatgpt-search", "train"), count("chatgpt-search", "heldout")) == (3, 2)
    assert (count("scraper", "train"), count("scraper", "heldout")) == (2, 2)
    assert count("claude-scheduled", "train") == 1


def test_balanced_accuracy_with_abstentions():
    pairs = [("llm", "llm"), ("llm", None), ("not_llm", "not_llm"), ("not_llm", "llm")]
    ba = study.balanced_accuracy(pairs, ("llm", "not_llm"))
    assert ba["ba_abstain_wrong"] == 0.5 and ba["ba_abstain_excluded"] == 0.75 and ba["abstentions"] == 1


def test_freeze_then_evaluate_once(tmp_path, monkeypatch):
    import rules
    monkeypatch.setattr(rules, "RULES_READY", True)
    monkeypatch.setattr(rules, "classify", lambda s: "H5" if s.get("S1_ai_ua") else "H1")
    a = T0
    recs, run_rows = [], []
    for i in range(4):
        t = a + timedelta(hours=i)
        recs.append(rec(t, "/", ip="20.1.5.5", ua="ChatGPT-User/1.0", query=f"r=agent00{i}"))
        recs.append(rec(t + timedelta(minutes=1), "/", ip=OP, ua="Safari", query=f"r=human00{i}"))
        run_rows += [(f"agent00{i}", "chatgpt-search", t, t + timedelta(minutes=1), ""),
                     (f"human00{i}", "human-browse", t + timedelta(minutes=1), t + timedelta(minutes=2), "")]
    logs = tmp_path / "logs"
    logs.mkdir()
    write_logs(str(logs), recs)
    rp = tmp_path / "runs.csv"
    runs_csv(rp, run_rows)
    (tmp_path / "ops.txt").write_text(OP + "\n")
    out = tmp_path / "out"
    args = ["--logs", str(logs), "--runs", str(rp), "--operator-ips", str(tmp_path / "ops.txt"),
            "--baseline-start", BASE.isoformat(), "--out", str(out)]
    with pytest.raises(SystemExit):
        run_study.main(["evaluate"] + args)                      # not frozen yet
    run_study.main(["prepare"] + args)
    run_study.main(["freeze"] + args)
    run_study.main(["evaluate"] + args)
    res = json.load(open(out / "heldout_result.json"))
    assert res["T1"]["ba_abstain_wrong"] == 1.0 and res["sessions"] == 4
    with pytest.raises(SystemExit):
        run_study.main(["freeze"] + args)                        # cannot re-freeze after opening
    frozen = json.load(open(out / "rules_freeze.json"))
    frozen["hashes"]["rules.py"] = "changed"
    json.dump(frozen, open(out / "rules_freeze.json", "w"))
    with pytest.raises(SystemExit):
        run_study.main(["evaluate"] + args)                      # code changed since freeze


def test_d8_scheduled_tasks_split_by_day():
    rows = [{"label_status": "labelled", "label_config": "claude-scheduled", "label_run": "sched001",
             "start": f"2026-10-2{d}T10:20:00+00:00"} for d in range(3, 9)]
    rows += [{"label_status": "labelled", "label_config": "scraper", "label_run": f"s{i}",
              "start": "2026-10-22T10:00:00+00:00"} for i in range(2)]
    half = study.split_runs(rows)
    study.apply_split(rows, half)
    days = [r["half"] for r in rows if r["label_config"] == "claude-scheduled"]
    assert days.count("train") == 3 and days.count("heldout") == 3
    assert {r["half"] for r in rows if r["label_config"] == "scraper"} == {"train", "heldout"}


def test_train_packet_is_blind_and_checker_matches(tmp_path, monkeypatch):
    import subprocess
    a = T0
    recs, run_rows = [], []
    for i in range(4):
        t = a + timedelta(hours=i)
        recs.append(rec(t, "/", ip="20.1.5.5", ua="ChatGPT-User/1.0", query=f"r=agent00{i}"))
        recs.append(rec(t + timedelta(minutes=1), "/", ip=OP, ua="Safari", query=f"r=human00{i}"))
        run_rows += [(f"agent00{i}", "chatgpt-search", t, t + timedelta(minutes=1), ""),
                     (f"human00{i}", "human-browse", t + timedelta(minutes=1), t + timedelta(minutes=2), "")]
    logs = tmp_path / "logs"
    logs.mkdir()
    write_logs(str(logs), recs)
    rp = tmp_path / "runs.csv"
    runs_csv(rp, run_rows)
    (tmp_path / "ops.txt").write_text(OP + "\n")
    out = tmp_path / "out"
    args = ["--logs", str(logs), "--runs", str(rp), "--operator-ips", str(tmp_path / "ops.txt"),
            "--baseline-start", BASE.isoformat(), "--out", str(out)]
    run_study.main(["train"] + args)
    pk = out / "rule_packet"
    text = "".join(p.read_text() for p in pk.iterdir())
    for secret in (OP, "20.1.5.5", "Safari", "agent000", "human000", '"start"', "edge"):
        assert secret not in (pk / "train_sessions.jsonl").read_text(), secret
    assert "## 5. Signals" in text and "### 4a." not in (pk / "prereg_extract.md").read_text()
    lines = [json.loads(x) for x in (pk / "train_sessions.jsonl").read_text().splitlines()]
    assert len(lines) == 4 and all(set(x) == set(study.RULE_FIELDS) | {"true_class", "label_config"} for x in lines)
    # a toy rules file: the packet checker and the study's own scoring must agree
    (pk / "rules.py").write_text("RULES_READY = True\n"
                                 "def classify(s):\n"
                                 "    assert 'true_class' not in s and 'label_config' not in s\n"
                                 "    return 'H5' if s['S1_ai_ua'] else 'H1'\n")
    res = json.loads(subprocess.run(["python3", str(pk / "check_rules.py")], capture_output=True,
                                    text=True, check=True).stdout)
    import importlib.util
    spec = importlib.util.spec_from_file_location("toy_rules", pk / "rules.py")
    toy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(toy)
    rows, _, _ = run_study.load(run_study.argparse.Namespace(
        logs=str(logs), runs=str(rp), operator_ips=str(tmp_path / "ops.txt"), baseline_start=BASE.isoformat(),
        reference=None, lure_start="2026-10-22T07:58:52+00:00", cutoff="2026-10-31T23:59:59+00:00"))
    mine = study.score(rows, toy.classify, "train")
    assert res["T1"] == {k: mine["T1"][k] for k in res["T1"]}
    assert res["sessions"] == mine["sessions"]
