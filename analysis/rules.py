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

TRAINING choices (training half, 58 sessions):
- H0 margin: a branch names a class only when that class is at least 2/3 of the training
  sessions matching the branch (or the pre-registered definition fixes it and no training
  session contradicts it). Otherwise "H0", or "agent_unknown" when LLM acting is clear but
  direction is not.
- S13 cut-offs (vendor fetchers only): days_seen == 1 -> single visit (H5);
  days_seen >= 3 -> regular repeats (H6); days_seen == 2 -> no lead (agent_unknown).
- S13 is NOT used as direction evidence for sessions run in a browser (script + beacon): the
  "same IP and UA" part of S13 then counts the person's own browser returning (8/9 H1 sessions
  and 6/6 in-browser H5 sessions have S13_return True), not a schedule.
- No timing (S9) or volume cut-off is used: S9 overlaps between H1 (2.7-516 s) and in-browser
  H5 (7.9-22.5 s), and H3 is already separated by client software.
"""

RULES_READY = True

# Vendor lists for on-request fetchers (an LLM fetches because someone asked) versus crawler
# lists (H4). From the S2 definition and F3. Matched as substrings of S2_vendor_lists.
ON_REQUEST_LISTS = ("chatgpt-user", "user-fetcher", "perplexity-user", "user-triggered-agents")
# Bug fix at review (1 Nov 2026): Perplexity's on-request list is saved as perplexity-user.json,
# which "user-fetcher" did not match; added so the code does what the comment above intends.
CRAWLER_LISTS = ("gptbot", "searchbot", "perplexitybot", "googlebot")

S13_SINGLE_MAX_DAYS = 1    # TRAINING: vendor-list sessions with 1 day: 3 H5 / 1 H6 (75%)
S13_REPEAT_MIN_DAYS = 3    # TRAINING: vendor-list sessions with >=3 days: 0 H5 / 2 H6;
                           #           with 2 days: 3 H5 / 2 H6 (no lead -> agent_unknown)


def _events(s):
    ev = s.get("S6_input_events")
    if not ev:
        return set()
    return {e.strip() for e in str(ev).split(";") if e.strip()}


def _direction_reported(s):
    """Direction from S11 then S12 only. 'none', 'no_ok_request', 'not_applicable' and None
    count neither way (rule 5). Returns 'H5', 'H6' or None. No training session has S11 yes/no,
    and the one S12 True is a human following a lure by hand (handled by the human branch), so
    these are taken from the hypothesis definitions, not from data."""
    sr = s.get("S11_self_report")
    if sr == "yes":
        return "H5"          # self-report of acting for a person now
    if sr == "no":
        return "H6"          # self-report of no person
    pause = s.get("S12_pause")
    if pause is True:
        return "H5"          # pause consistent with checking with a user (> 60 s)
    if pause is False:
        return "H6"          # no pause when asked to check with the user
    return None


def _direction_from_returns(s):
    """S13 cut-offs, used only where IP+UA is not a person's own browser."""
    days = s.get("S13_days_seen")
    ret = s.get("S13_return")
    if days is None:
        if ret is False:
            days = 1
        else:
            return None
    try:
        days = int(days)
    except (TypeError, ValueError):
        return None
    if days <= S13_SINGLE_MAX_DAYS:
        return "H5"
    if days >= S13_REPEAT_MIN_DAYS:
        return "H6"
    return None


def classify(s: dict) -> str:
    if not RULES_READY:
        raise RuntimeError("Detection rules not written yet: fill in rules.py from the training half.")

    events = _events(s)
    script = s.get("S5_script_fetched") is True
    beacon = s.get("S5_beacon_load")
    hosting = s.get("S3_network") == "hosting"
    llm_sign = (s.get("S7_correct") is True or s.get("S11_self_report") in ("yes", "no")
                or s.get("S12_pause") in (True, False))

    # --- A. Browser sessions (client software group: page script fetched) -----------------
    if script:
        if beacon is None:
            # Short-form (capped) log: input events not measurable, so None is not "absent".
            # No training case. Cannot tell human from agent -> abstain.
            return "H0"
        if beacon is True and ({"scroll", "key"} & events):
            if hosting:
                # H1 evidence against: data-centre IP. No training case -> abstain.
                return "H0"
            # TRAINING: browser + scroll or key events: 8 H1, 3 H2 (H1 73% >= 2/3).
            # H2 (in-browser AI that only reads) is not separable from H1 here: the 3 H2
            # sessions match an H1 false-ua-browser session in every server signal.
            # Includes 2/2 human-lure sessions that followed S7 by hand (H1 by definition).
            return "H1"
        if beacon is True:
            # Script ran but no scroll and no key: either pointer-only or no events at all.
            # TRAINING: pointer-only 6 H5 (chatgpt-agent, claude-browser) / 1 H1 (human-lure);
            # no events at all 5 H6 (chatgpt-scheduled). Pooled 11 LLM / 1 H1 (92%).
            # Direction: S13 not usable in a browser (see module notes), so S11/S12 only.
            # Caveat: no headless-browser H3 run is in the training half.
            return _direction_reported(s) or "agent_unknown"
        # beacon False with script fetched: script blocked or not executed. No training case.
        return "H0"

    # --- B. Explicit LLM signs outside a browser (S7, S11, S12) ----------------------------
    if llm_sign:
        # No training case (S7/S12 seen only in human browser sessions). From definitions:
        # an instruction on the page was followed by a non-browser client -> LLM acted.
        d = _direction_reported(s)
        if d:
            return d
        if s.get("S2_on_list") is True and s.get("S2_role_separated") is not True:
            return "agent_unknown"   # shared vendor IP pool: S13 not direction evidence
        return _direction_from_returns(s) or "agent_unknown"

    # --- C. Verified vendor IP (network group: S2) ------------------------------------------
    if s.get("S2_on_list") is True:
        lists = str(s.get("S2_vendor_lists") or "").lower()
        if s.get("S2_role_separated") is True:
            if any(t in lists for t in CRAWLER_LISTS) and not any(t in lists for t in ON_REQUEST_LISTS):
                # F3: crawler list -> verified bulk crawler. No training case.
                return "H4"
            if any(t in lists for t in ON_REQUEST_LISTS):
                # F3: on-request fetcher list -> an LLM fetch, not H4. Direction from S13.
                # TRAINING: openai-chatgpt-user 3/3 H5 (days 1, 1, 2 -> H5, H5, agent_unknown).
                return _direction_from_returns(s) or "agent_unknown"
            return "H0"
        # Rule 6: list does not separate roles (anthropic-bots.json). S1_kind does not decide,
        # and S13 cannot separate a bulk crawler (H4, repeats) from H5/H6, so -> H0.
        # TRAINING: anthropic-bots 8 sessions = 3 H5 (claude-web-fetch) + 5 H6 (claude-scheduled).
        return "H0"

    # --- D. Non-browser, unverified network (includes false AI user-agent claims) -----------
    days = s.get("S13_days_seen")
    ret = s.get("S13_return")
    if ret is False or days == 1:
        # TRAINING: non-browser, not on a vendor list, seen on one day: 9/9 H3
        # (curl-fetch 3, scraper 3, false-ua-script 3).
        return "H3"
    # Seen on 2+ days with no browser, no vendor identity and no LLM sign: a scheduled
    # curl/uptime check (H3) and an unattended LLM loop (H6) look the same from the server.
    # TRAINING: 15/15 are H6 (own-loop 10, own-loop-local 5), but every H3 training run was a
    # one-off by design, so the repeat says nothing about an LLM. Abstain.
    return "H0"
