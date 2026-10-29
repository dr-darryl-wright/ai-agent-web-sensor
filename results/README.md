# Results

Outputs of the analysis, counts and rates only. Written by `tools/export_results.py` from the
private analysis folder after the held-out test; every file is checked for IP addresses before
it is copied here.

| File | What it holds |
| --- | --- |
| `rules_freeze.json` | Hashes of the rules and analysis code when the rules were frozen, and their score on the training half |
| `heldout_result.json` | The one held-out test: balanced accuracy and confusion tables for both questions |
| `heldout_opened.log` | When the held-out half was opened (once) |
| `A1_A6.json` | Description of all traffic by period, client type and network, and the number of wild cases |
| `report_numbers.json` | Signal rates by class and configuration, and the stated predictions checked |
| `rule_writer/` | The brief the rule writer was given, the hashes of its inputs, and its notes |
