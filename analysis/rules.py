"""Detection rules (A3). Written on the TRAINING half only, then frozen.

`classify(session)` takes one session row (signals from hpa.py) and returns one of:
    "H1" ... "H6"      the hypothesis that mainly explains the session
    "agent_unknown"    an LLM acted during the visit, but nothing shows who set the task (rule 1)
    "H0"               other, or no hypothesis leads by the margin (an abstention)

Fixed parts (from the pre-registration, not from data):
- section 4 rule 1: H5 or H6 only with evidence on direction (a self-report S11, a check-with-user
  response S12, or a return pattern S13); otherwise "agent_unknown";
- section 4c F3 and rule 6: a vendor list that does not separate crawling from on-request
  fetching cannot decide H4 against H5.

Everything marked TRAINING below is chosen from the training half and must be filled in before
`run_study.py freeze`. Until then classify() refuses to run.
"""

RULES_READY = False   # set to True once the TRAINING choices below are made


def classify(s: dict) -> str:
    if not RULES_READY:
        raise RuntimeError("Detection rules not written yet: fill in rules.py from the training half.")
    raise NotImplementedError
