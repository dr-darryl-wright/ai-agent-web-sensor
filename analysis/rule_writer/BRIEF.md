# Brief for the rule writer

You are writing the detection rules for a pre-registered study of who visits a small website
(a honeypot) and whether an AI model is acting during the visit. The rules go in `rules.py` in
this folder. They will be frozen (hashed) and then tested once on a held-out half of the data
that you never see.

## What is in this folder, and what you may use

| File | What it is |
| --- | --- |
| `BRIEF.md` | This brief |
| `prereg_extract.md` | The parts of the frozen pre-registration that define sessions, hypotheses, signals, assignment rules, controlled runs and scoring. Where this brief and the extract differ, the extract wins |
| `configurations.md` | Each controlled-run configuration and the hypothesis it counts as |
| `train_sessions.jsonl` | The training half: one labelled session per line |
| `A2_train.json` | Signal rates by class on the training half (pre-registered analysis A2) |
| `rules.py` | The file you fill in |
| `check_rules.py` | Scores your rules on the training half: `python3 check_rules.py` |
| `MANIFEST.txt` | Hashes of the files you were given |

Use only these files. Do not read anything outside this folder, do not search the rest of the
computer, and do not use the web. You are working blind on purpose: the people running the
study have seen the data collection, so the rules are written by someone who has not.

## The task

Fill in `classify(s)` in `rules.py` and set `RULES_READY = True`.

`classify` receives one session as a dict. Its keys are exactly the signal columns in
`train_sessions.jsonl` **except** `true_class` and `label_config`, which are the answers and are
never passed to `classify`. It returns one of:

- `"H1"` … `"H6"`: the hypothesis that mainly explains the session;
- `"agent_unknown"`: an LLM acted during the visit, but nothing shows whether a person asked for
  this task or it came from a schedule or standing goal (assignment rule 1);
- `"H0"`: other, or no hypothesis leads clearly. This is an abstention.

## Rules you must follow (fixed before any data; do not change them)

1. **Rule 1.** Return `"H5"` or `"H6"` only when the session has evidence on direction: a
   self-report (`S11_self_report` is `"yes"` or `"no"`), a check-with-user result (`S12_pause`
   is `True` or `False`), or a return pattern (`S13_return`, `S13_days_seen`). Otherwise an
   LLM-acting session is `"agent_unknown"`. (The text of rule 1 names only S11, S12 and the
   run label, which you do not get; section 4c F1 and rule 6 also name S13 as evidence on
   direction. The study reads rule 1 as including S13. This reading was fixed before the
   rules were written.)
2. **F3 and rule 6.** A vendor IP list decides H4 against H5 only when the vendor separates its
   crawlers from its on-request fetchers. When `S2_role_separated` is `False`, the list match
   alone cannot give H4 or H5; the session is `"H0"` unless S7, S11, S12 or S13 decide. The
   user-agent's claimed role (`S1_kind`) is recorded but does not decide.
3. **Rule 5.** `S11_self_report == "not_applicable"` and `S12_pause == "not_applicable"` count
   neither for nor against any hypothesis.
4. **Rule 3.** Any cut-off on timing, volume or repeat visits is yours to choose from the
   training half. State each one and why.
5. **H0 margin.** When the evidence does not clearly favour one hypothesis, return `"H0"`. How
   clear is "clearly" is yours to choose from the training half (section 4c, F4). State it.

## How the rules will be scored

Each session counts once. Two tasks (section 4 of the extract):

- **T1:** LLM acting (H2, H5, H6, `agent_unknown`) against not (H1, H3, H4).
- **T2:** H5 against H6, among sessions whose true class is H5 or H6. `agent_unknown`, H0 and
  any other answer count as abstentions.

The score is balanced accuracy (the mean of per-class accuracy), given twice: with abstentions
counted wrong, and with abstentions left out (plus the abstention rate). T2 is also reported
without the operator's own agent loops (`own-loop`, `own-loop-local`), so rules that only work
by recognising those two scripts will show up as such.

## What makes good rules here

- The held-out half contains **different runs of the same configurations**. Rules that
  generalise across runs matter more than a perfect training score. Avoid rules that pick out a
  single run by an incidental detail (one ASN number, one exact request count) unless the
  pre-registered signal definition supports it.
- The training half is small. Prefer a few clear rules, each tied to a signal and its meaning
  in `prereg_extract.md`, over many narrow ones.
- Signals that share a cause count as one group, not as independent evidence: S1, S5 and S10
  ("client software"); S2 and S3 ("network").
- Training data may show that two classes cannot be told apart from the server (for example H1
  and H2). If so, say so; do not force a rule that only fits the training sessions.
- Missing values (`None`) mean "not observed or not measurable", not "absent", for sessions
  logged in short form. Treat `None` with care.

## Constraints on the code

- Python 3 standard library only. No file, network or clock access inside `classify`.
- `classify` must be a pure function of its input and must not raise on any input with these
  keys (including `None` values).
- Comment each branch with the training evidence for it (counts or rates).

## What to hand back

1. `rules.py`, filled in, with `RULES_READY = True`.
2. `NOTES.md` (in this folder), short and plain:
   - each rule and cut-off, and the training evidence for it;
   - the output of `python3 check_rules.py`;
   - anything in the definitions you found unclear and how you resolved it;
   - classes you think cannot be separated from the server, and why.

Do not try to improve the training score after you have a reasonable set of rules: stop, write
`NOTES.md`, and hand back.
