#!/usr/bin/env python3
"""Run the pre-registered analysis in its fixed order. From the honeypot folder:

    python3 analysis/run_study.py prepare     sessions, labels and the 50/50 split (counts only)
    python3 analysis/run_study.py train       the rule writer's folder, from the TRAINING half only
    (a separate writer with no other context fills in rules.py there; copy it to analysis/rules.py)
    python3 analysis/run_study.py freeze      hash the rules; score the training half
    python3 analysis/run_study.py evaluate    open the held-out half ONCE and score it
    python3 analysis/run_study.py describe    A1 description and A6 wild candidates
    python3 analysis/run_study.py report      A2 on all labelled runs and P1-P6 (after evaluate)

Outputs go to data/analysis/ (session tables contain IP addresses: keep private). Printed output
gives counts and rates only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import hpa  # noqa: E402
import run_analysis  # noqa: E402
import study  # noqa: E402

ROOT = os.path.dirname(HERE)


def paths(out_dir: str) -> dict:
    return {k: os.path.join(out_dir, v) for k, v in {
        "sessions": "study_sessions.csv", "train": "A2_train.json", "packet": "rule_packet", "freeze": "rules_freeze.json",
        "heldout": "heldout_result.json", "describe": "A1_A6.json", "wild": "A6_candidates.csv",
        "report": "report_numbers.json", "opened_log": "heldout_opened.log"}.items()}


def sha256(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def code_hashes() -> dict:
    return {name: sha256(os.path.join(HERE, name)) for name in ("rules.py", "study.py", "hpa.py")}


def load(a) -> tuple[list[dict], dict, str]:
    """Build labelled sessions exactly as `prepare` does."""
    baseline = a.baseline_start or run_analysis.freeze_time(ROOT)
    ref = a.reference or run_analysis.latest_reference(os.path.join(ROOT, "data", "reference"))
    ctx = hpa.Context(
        ua_tokens=hpa.read_ua_tokens(os.path.join(ROOT, "signals", "ai_user_agents.txt")),
        vendors=hpa.VendorLists(ref),
        asn=hpa.AsnTable(os.path.join(ref, "ip2asn-combined.tsv.gz") if ref else None),
        hosting=hpa.read_hosting_list(os.path.join(ROOT, "signals", "hosting_asns.txt")),
        placements=hpa.read_placements(os.path.join(ROOT, "lures", "placements.csv")),
        baseline_start=datetime.fromisoformat(baseline),
        lure_start=datetime.fromisoformat(a.lure_start),
        cutoff=datetime.fromisoformat(a.cutoff),
    )
    run_files = [p for p in a.runs.split(",") if p]
    runs = study.read_runs(run_files)
    windows = [w for p in run_files for w in run_analysis.read_run_windows(p)]
    rows, rep, n_split = study.build_rows(a.logs, ctx, hpa.read_operator_ips(a.operator_ips), windows, set(runs))
    counts = study.label_rows(rows, runs)
    study.apply_split(rows, study.split_runs(rows))
    info = {"baseline_start": baseline, "reference": ref, "log_lines": rep.lines, "kept": rep.kept,
            "excluded": {"pilot": rep.before_start, "operator": rep.operator, "smoke": rep.smoke,
                         "capped": rep.capped, "unreadable": rep.bad_json},
            "ip_repaired_D10": getattr(rep, "ip_repaired", 0), "ip_unrepaired_D10": getattr(rep, "ip_unrepaired", 0),
            "sessions": len(rows), "d6_splits": n_split, "labels": dict(counts), "runs_logged": len(runs),
            "runs_void": sum(1 for r in runs.values() if r["void"])}
    return rows, info, runs


def cmd_prepare(a, P):
    rows, info, runs = load(a)
    study.write_rows(rows, P["sessions"])
    print(json.dumps(info, indent=1))
    by = {}
    for r in rows:
        if r["label_status"] in ("labelled", "setup", "void"):
            key = (r["label_config"], r["label_status"], r.get("half") or "-")
            by[key] = by.get(key, 0) + 1
    print("\nLabelled sessions by configuration, status and half (sessions):")
    for (c, st, h), n in sorted(by.items()):
        print(f"  {c:<22}{st:<10}{h:<9}{n:>4}")
    missing = sorted(r["run_id"] for r in runs.values()
                     if not r["void"] and r["end"] and not any(x["label_run"] == r["run_id"] for x in rows))
    if missing:
        print(f"\nRuns with no session found ({len(missing)}): {', '.join(missing)}")
    print(f"\nSession table: {P['sessions']} (contains IP addresses: keep private)")


PREREG_SECTIONS = ("## 3.", "## 4.", "### 4c.", "## 5.", "## 7.", "## 8.")


def prereg_extract(text: str) -> str:
    """The sections the rule writer needs, verbatim: 3, 4 (not the 4a/4b check history), 4c, 5, 7, 8."""
    out, keep = [], False
    for line in text.splitlines():
        if line.startswith("## ") or line.startswith("### "):
            keep = line.startswith(PREREG_SECTIONS)
        if keep:
            out.append(line)
    return "\n".join(out).rstrip() + "\n"


def write_packet(train: list[dict], pdir: str) -> list[str]:
    """Folder for the blind rule writer: brief, pre-registration extract, training half with
    signal columns only (plus the answers), A2 on the training half, rules.py template, checker."""
    import shutil
    os.makedirs(pdir, exist_ok=True)
    src = os.path.join(HERE, "rule_writer")
    shutil.copy(os.path.join(src, "BRIEF.md"), pdir)
    shutil.copy(os.path.join(src, "check_rules.py"), pdir)
    shutil.copy(os.path.join(HERE, "rules.py"), pdir)
    with open(os.path.join(ROOT, "PREREGISTRATION.md"), encoding="utf-8") as f:
        prereg = f.read()
    with open(os.path.join(pdir, "prereg_extract.md"), "w", encoding="utf-8") as f:
        f.write("# Extract from the frozen pre-registration (version 2)\n\n" + prereg_extract(prereg))
    with open(os.path.join(pdir, "configurations.md"), "w") as f:
        f.write("# Controlled-run configurations\n\n| Configuration | Counts as |\n| --- | --- |\n")
        for c, h in study.CONFIG_CLASS.items():
            note = (" (sends a false AI user agent: false declaration tag)" if c in study.FALSE_DECLARATION_CONFIGS
                    else " (scheduled task in a vendor product)" if c in study.SCHEDULED_CONFIGS
                    else " (the operator's own agent loop on a timer)" if c.startswith("own-loop") else "")
            f.write(f"| `{c}` | {h}{note} |\n")
    with open(os.path.join(pdir, "train_sessions.jsonl"), "w") as f:
        for r in train:
            d = study.rule_input(r)
            d.update(true_class=r["true_class"], label_config=r["label_config"])
            f.write(json.dumps(d, sort_keys=True) + "\n")
    with open(os.path.join(pdir, "A2_train.json"), "w") as f:
        json.dump({"A2_train": study.signal_rates(train)}, f, indent=1, default=str)
    names = sorted(n for n in os.listdir(pdir) if n not in ("MANIFEST.txt", "NOTES.md"))
    with open(os.path.join(pdir, "MANIFEST.txt"), "w") as f:
        f.write(f"created_utc {datetime.now(timezone.utc).isoformat(timespec='seconds')}\n")
        f.write(f"PREREGISTRATION.md {sha256(os.path.join(ROOT, 'PREREGISTRATION.md'))}\n")
        for n in names:
            f.write(f"{n} {sha256(os.path.join(pdir, n))}\n")
    return names


def cmd_train(a, P):
    """Build the rule writer's folder from the TRAINING half. Prints counts only, so the operator
    and the orchestrating session do not see the training data before the rule writer does."""
    if os.path.exists(P["freeze"]):
        raise SystemExit("Rules are already frozen; the packet would no longer match them.")
    rows, info, _ = load(a)
    train = [r for r in rows if r.get("half") == "train"]
    with open(P["train"], "w") as f:
        json.dump({"A2_train": study.signal_rates(train)}, f, indent=1, default=str)
    names = write_packet(train, P["packet"])
    by = {}
    for r in train:
        by[r["true_class"]] = by.get(r["true_class"], 0) + 1
    print(f"Training half: {len(train)} sessions; by class: {dict(sorted(by.items()))}")
    print(f"Rule writer's folder (contents not shown): {P['packet']}  files: {', '.join(names)}")


def cmd_freeze(a, P):
    import rules
    if not getattr(rules, "RULES_READY", False):
        raise SystemExit("rules.py is not ready (RULES_READY is False).")
    if os.path.exists(P["heldout"]):
        raise SystemExit("The held-out half has already been opened; rules cannot be re-frozen.")
    rows, info, _ = load(a)
    res = study.score(rows, rules.classify, "train")
    rec = {"frozen_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"), "hashes": code_hashes(),
           "train_score": res}
    with open(P["freeze"], "w") as f:
        json.dump(rec, f, indent=1)
    print(json.dumps(rec, indent=1))
    print(f"\nRules frozen. Post the rules.py hash ({rec['hashes']['rules.py']}) somewhere dated, then run evaluate.")


def cmd_evaluate(a, P):
    import rules
    if not os.path.exists(P["freeze"]):
        raise SystemExit("Freeze the rules first: run_study.py freeze")
    frozen = json.load(open(P["freeze"]))
    now_h = code_hashes()
    if now_h != frozen["hashes"]:
        raise SystemExit(f"Code changed since the freeze: {frozen['hashes']} vs {now_h}. Not opening.")
    if os.path.exists(P["heldout"]) and not a.reopen:
        print("The held-out half was already opened; showing the saved result (no new scoring).")
        print(open(P["heldout"]).read())
        return
    rows, info, _ = load(a)
    res = study.score(rows, rules.classify, "heldout")
    res["opened_utc"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    res["rules_hash"] = now_h["rules.py"]
    with open(P["heldout"], "w") as f:
        json.dump(res, f, indent=1)
    with open(P["opened_log"], "a") as f:
        f.write(f"{res['opened_utc']} opened{' (REOPEN)' if a.reopen else ''} rules {now_h['rules.py']}\n")
    print(json.dumps(res, indent=1))


def cmd_describe(a, P):
    rows, info, _ = load(a)
    d = study.describe(rows)
    wild = study.wild_candidates(rows)
    study.write_rows(wild, P["wild"])
    with open(P["describe"], "w") as f:
        json.dump({"info": info, "A1": d, "A6_candidates": len(wild)}, f, indent=1, default=str)
    print(json.dumps({"A1": d, "A6_candidates": len(wild)}, indent=1, default=str))
    print(f"\nA6 candidates (private, with addresses): {P['wild']}")


def cmd_report(a, P):
    import rules
    if not os.path.exists(P["heldout"]):
        raise SystemExit("Run evaluate first: A2 on all runs would otherwise show the held-out half.")
    rows, info, _ = load(a)
    labelled = [r for r in rows if r["label_status"] == "labelled"]
    out = {"info": info, "A2_all": study.signal_rates(labelled),
           "A2_by_config": study.signal_rates(labelled, key="label_config"),
           "predictions": study.predictions(rows, rules.classify, json.load(open(P["heldout"])))}
    with open(P["report"], "w") as f:
        json.dump(out, f, indent=1, default=str)
    print(json.dumps(out["predictions"], indent=1, default=str))
    print(f"\nFull numbers: {P['report']}")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("cmd", choices=["prepare", "train", "freeze", "evaluate", "describe", "report"])
    p.add_argument("--logs", default=os.path.join(ROOT, "data", "logs"))
    p.add_argument("--reference", default=None)
    p.add_argument("--operator-ips", default=os.path.join(ROOT, "data", "operator_ips.txt"))
    p.add_argument("--runs", default=",".join(os.path.join(ROOT, "data", x, "runs.csv") if x else
                                              os.path.join(ROOT, "data", "runs.csv")
                                              for x in ("", "loop", "loop-local")))
    p.add_argument("--baseline-start", default=None, help="default: time of the newest freeze")
    p.add_argument("--lure-start", default="2026-10-22T07:58:52+00:00")
    p.add_argument("--cutoff", default="2026-10-31T23:59:59+00:00")
    p.add_argument("--out", default=os.path.join(ROOT, "data", "analysis"))
    p.add_argument("--reopen", action="store_true", help="re-score the held-out half (logged; avoid)")
    a = p.parse_args(argv)
    os.makedirs(a.out, exist_ok=True)
    P = paths(a.out)
    {"prepare": cmd_prepare, "train": cmd_train, "freeze": cmd_freeze, "evaluate": cmd_evaluate,
     "describe": cmd_describe, "report": cmd_report}[a.cmd](a, P)
    return 0


if __name__ == "__main__":
    sys.exit(main())
