# Review of the rule writer's code (1 November 2026)

Checked for bugs only; no rule, cut-off or margin was changed.

- **Fixed:** `ON_REQUEST_LISTS` did not match Perplexity's on-request list, which is saved as
  `perplexity-user.json` (the code looked for "user-fetcher"). Added "perplexity-user" so the code
  does what its own comment says. No training session is on that list, so the training score is
  unchanged (T1 balanced accuracy 0.647 with abstentions wrong, 0.884 with them excluded).
- **Checked, no change:** every value type in the session table (booleans, strings, numbers,
  None) runs without error, including 20,000 random combinations and an all-None session.
- The code as first written is kept as `rules.as_written.py`.
