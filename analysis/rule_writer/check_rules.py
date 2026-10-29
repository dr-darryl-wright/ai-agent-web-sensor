#!/usr/bin/env python3
"""Score rules.py on the training half in this folder. Run: python3 check_rules.py

Uses the same definitions as the study's scoring (analysis/study.py): T1 is LLM acting against
not; T2 is H5 against H6; balanced accuracy with abstentions counted wrong and left out.
classify() is given each session without the answer columns (true_class, label_config).
"""

import importlib.util
import json
import os
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
ANSWER_COLUMNS = ("true_class", "label_config")
ALLOWED = {"H0", "H1", "H2", "H3", "H4", "H5", "H6", "agent_unknown"}
T1_POSITIVE = {"H2", "H5", "H6", "agent_unknown"}
T1_NEGATIVE = {"H1", "H3", "H4"}
T2_CLASSES = ("H5", "H6")
OWN_LOOPS = {"own-loop", "own-loop-local"}


def t1(c):
    return "llm" if c in T1_POSITIVE else ("not_llm" if c in T1_NEGATIVE else None)


def balanced_accuracy(pairs, classes):
    wrong, excl = [], []
    for c in classes:
        mine = [(t, p) for t, p in pairs if t == c]
        if not mine:
            continue
        wrong.append(sum(p == t for t, p in mine) / len(mine))
        ans = [(t, p) for t, p in mine if p is not None]
        if ans:
            excl.append(sum(p == t for t, p in ans) / len(ans))
    n_abst = sum(p is None for _, p in pairs)
    return {"n": len(pairs), "abstentions": n_abst,
            "abstention_rate": round(n_abst / len(pairs), 3) if pairs else None,
            "ba_abstain_wrong": round(sum(wrong) / len(wrong), 3) if wrong else None,
            "ba_abstain_excluded": round(sum(excl) / len(excl), 3) if excl else None}


def main():
    spec = importlib.util.spec_from_file_location("rules", os.path.join(HERE, "rules.py"))
    rules = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(rules)
    if not getattr(rules, "RULES_READY", False):
        raise SystemExit("RULES_READY is False in rules.py")
    rows = [json.loads(line) for line in open(os.path.join(HERE, "train_sessions.jsonl")) if line.strip()]
    preds = []
    for r in rows:
        p = rules.classify({k: v for k, v in r.items() if k not in ANSWER_COLUMNS})
        if p not in ALLOWED:
            raise SystemExit(f"classify returned {p!r}; allowed: {sorted(ALLOWED)}")
        preds.append((r, p))
    t1_pairs = [(t1(r["true_class"]), t1(p)) for r, p in preds if t1(r["true_class"])]
    t2_pairs = [(r["true_class"], p if p in T2_CLASSES else None) for r, p in preds if r["true_class"] in T2_CLASSES]
    t2_no_own = [(r["true_class"], p if p in T2_CLASSES else None) for r, p in preds
                 if r["true_class"] in T2_CLASSES and r["label_config"] not in OWN_LOOPS]
    by_config = defaultdict(Counter)
    for r, p in preds:
        by_config[f'{r["label_config"]} ({r["true_class"]})'][p] += 1
    out = {"sessions": len(rows),
           "T1": balanced_accuracy(t1_pairs, ("llm", "not_llm")),
           "T2": balanced_accuracy(t2_pairs, T2_CLASSES),
           "T2_without_own_loops": balanced_accuracy(t2_no_own, T2_CLASSES),
           "answers_by_configuration": {k: dict(v) for k, v in sorted(by_config.items())}}
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
