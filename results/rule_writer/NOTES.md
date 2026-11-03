# Notes from the rule writer

Training half only: 58 sessions, all in the lure period. Files used: only those in this folder.

## Rules, in order (training evidence)

H0 margin: a branch names a class only when that class is at least 2/3 of the training sessions
matching it, or when the pre-registered definition fixes it and no training session contradicts
it. Otherwise H0, or `agent_unknown` when LLM acting is clear but direction is not.

A. **Browser sessions** (page script fetched, S5):
   - beacon not observed (None, short-form log) -> H0. No training case.
   - scroll or key input events (S6), not a hosting IP -> **H1**. Training: 8 H1, 3 H2 (73%).
     Hosting IP with human events -> H0 (H1 evidence against; no training case).
   - beacon fired but no scroll and no key (pointer only, or no events) -> **LLM acting**:
     H5/H6 only if S11 or S12 decide, else `agent_unknown`. Training: pointer-only 6 H5 / 1 H1,
     no events 5 H6; pooled 11 LLM / 1 H1 (92%).
   - S13 is not used for direction here: "same IP and UA on 2+ days" counts the person's own
     browser returning (8/9 H1 and 6/6 in-browser H5 return), not a schedule.
B. **S7, S11 yes/no or S12 True/False outside a browser** -> LLM acting; direction S11, then S12,
   then S13. No training case (S7 and S12 occur only in human-lure H1 sessions, caught by A).
C. **Vendor IP list (S2)**:
   - role-separated crawler list (gptbot, searchbot, perplexitybot, googlebot) -> H4. No case.
   - role-separated on-request list (chatgpt-user, user-fetcher, user-triggered-agents) ->
     LLM acting; direction by S13: 1 day -> H5, 3+ days -> H6, 2 days -> `agent_unknown`.
     Training: chatgpt-user 3/3 H5 (days 1,1,2). Cut-offs pooled over all 11 vendor-list
     sessions: 1 day 3 H5/1 H6; 2 days 3 H5/2 H6 (no lead); 3+ days 0 H5/2 H6.
   - list does not separate roles (anthropic-bots.json) -> **H0** (rule 6). S1_kind does not
     decide, and S13 cannot separate a repeating bulk crawler (H4) from H5/H6. Training: 3 H5,
     5 H6.
D. **No browser, no vendor identity** (includes false AI user-agent claims): seen on 1 day ->
   **H3** (9/9: curl, scraper, false-ua-script). Seen on 2+ days -> **H0**: training 15/15 are
   own-loop / own-loop-local (H6), but a cron'd curl or uptime check (H3) repeats too, and every
   H3 training run was a one-off by design. No server signal shows an LLM acted.

Not used: S9 timing (overlaps: H1 2.7-516 s, in-browser H5 7.9-22.5 s), request counts, ASN
numbers, S10 (shared cause with S1/S5), S4 (never present).

## Output of `python3 check_rules.py`

```
{
 "sessions": 58,
 "T1": {
  "n": 58,
  "abstentions": 23,
  "abstention_rate": 0.397,
  "ba_abstain_wrong": 0.647,
  "ba_abstain_excluded": 0.884
 },
 "T2": {
  "n": 37,
  "abstentions": 35,
  "abstention_rate": 0.946,
  "ba_abstain_wrong": 0.083,
  "ba_abstain_excluded": 1.0
 },
 "T2_without_own_loops": {
  "n": 22,
  "abstentions": 20,
  "abstention_rate": 0.909,
  "ba_abstain_wrong": 0.083,
  "ba_abstain_excluded": 1.0
 },
 "answers_by_configuration": {
  "browser-ai-summary (H2)": {
   "H1": 3
  },
  "chatgpt-agent (H5)": {
   "agent_unknown": 3
  },
  "chatgpt-scheduled (H6)": {
   "agent_unknown": 5
  },
  "chatgpt-search (H5)": {
   "agent_unknown": 1,
   "H5": 2
  },
  "claude-browser-agent (H5)": {
   "agent_unknown": 3
  },
  "claude-scheduled (H6)": {
   "H0": 5
  },
  "claude-web-fetch (H5)": {
   "H0": 3
  },
  "curl-fetch (H3)": {
   "H3": 3
  },
  "false-ua-browser (H1)": {
   "H1": 2
  },
  "false-ua-script (H3)": {
   "H3": 3
  },
  "human-browse (H1)": {
   "H1": 4
  },
  "human-lure (H1)": {
   "H1": 2,
   "H5": 1
  },
  "own-loop (H6)": {
   "H0": 10
  },
  "own-loop-local (H6)": {
   "H0": 5
  },
  "scraper (H3)": {
   "H3": 3
  }
 }
}
```

## Unclear definitions and how I resolved them

1. Rule 1 vs F3: F3 says the chatgpt-user list "decides H5", rule 1 says H5/H6 need direction
   evidence. Resolved: the on-request list shows an LLM fetch (not H4); direction still comes
   from S11/S12/S13. Scheduled tasks use the same fetchers ("H5 and H6 share the same products").
2. S11 is "none" and S12 "no_ok_request" in every training session, even ones with no lure
   placement, where rule 5 says "not_applicable". Resolved: only S11 yes/no and S12 True/False
   count; every other value counts neither way.
3. S13 mixes "same lure code" with "same IP and UA". For a person's browser or a shared vendor
   IP pool, IP+UA repeats regardless of who set the task. Resolved: S13 used for direction only
   for vendor on-request fetchers and non-browser clients, with the cut-offs above.
4. Rule 6 "unless S13 decides": S13 can speak to H5 vs H6 but not to H4 vs H5/H6 (F1: H4 does not
   rest on volume). Resolved: anthropic-bots sessions are H0 unless S7/S11/S12 fire.
5. S6 None with beacon load True (chatgpt-scheduled) read as "no events reported"; S6 None with
   beacon None read as not measurable.

## Classes not separable from the server

- **H1 vs H2**: the 3 H2 sessions match an H1 false-ua-browser session in every server signal.
  Reported as the known limit; they go to H1.
- **H5 vs H6**: no training LLM session sent a self-report or a check-with-user request, so
  direction rests on S13 alone, which is confounded (above). In-browser chatgpt-agent (H5) and
  chatgpt-scheduled (H6) come from the same IP/UA with the same days seen; they differ in input
  events, which reflects the task given, not who set it.
- **H3 vs own-loop H6**: own-loop-local is identical to curl-fetch except for repeat days.
- **H4 vs H5/H6 on Anthropic's shared list** (rule 6).
- Gap: no headless-browser H3 run is in the training half, so branch A's "script, no events ->
  LLM" is untested against one.
