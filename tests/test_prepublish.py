import json
import os
import subprocess
import sys

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, "..", "tools"))

import export_results  # noqa: E402
import prepublish_check  # noqa: E402


def repo(tmp_path, files):
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    return str(tmp_path)


def test_prepublish_flags_data_secrets_and_blocklist(tmp_path):
    root = repo(tmp_path, {
        ".gitignore": "data/\n",
        "data/operator_ips.txt": "81.2.69.160\n",
        "data/prepublish_blocklist.txt": "victim-site.example\n",
        "README.md": "fine text, contact me@example.org\n",
        "app/a.py": "KEY = '" + "sk-" + "a" * 24 + "'\n",
        "notes.md": "seen from 81.2.69.160 and victim-site.example\n",
        "other.md": "vendor range 216.73.216.0/22\n",
        "logs/x.jsonl": "{}\n",
        "tests/t.py": "ip = '5.6.7.8'\n",
    })
    files, fails, reviews = prepublish_check.check(root)
    assert not any(f.startswith("data/") for f in files)
    text = "\n".join(fails)
    assert "app/a.py: contains a OpenAI-style key" in text
    assert "notes.md: contains a blocklisted string" in text
    assert "logs/x.jsonl" in text
    assert not any("tests/t.py" in r for r in reviews)
    assert any("other.md: IP addresses 216.73.216.0" in r for r in reviews)
    assert any("me@example.org" in r for r in reviews)


def test_prepublish_clean_repo_passes(tmp_path):
    root = repo(tmp_path, {".gitignore": "data/\n", "README.md": "hello\n", "tests/t.py": "x = '1.2.3.4'\n"})
    _, fails, _ = prepublish_check.check(root)
    assert fails == []


def test_export_refuses_addresses_and_cuts_paths(tmp_path):
    src = tmp_path / "data" / "analysis"
    (src / "rule_packet").mkdir(parents=True)
    json.dump({"info": {"reference": "/Users/someone/proj/data/reference/2026-10-19T1845Z"}, "n": 3},
              open(src / "A1_A6.json", "w"))
    (src / "heldout_result.json").write_text('{"T1": 0.8, "seen": "203.0.113.9"}')
    (src / "rule_packet" / "BRIEF.md").write_text("brief\n")
    written, refused = export_results.export(str(src), str(tmp_path / "results"), str(tmp_path))
    assert "results/A1_A6.json" in written and "results/rule_writer/BRIEF.md" in written
    out = json.load(open(tmp_path / "results" / "A1_A6.json"))
    assert out["info"]["reference"] == "2026-10-19T1845Z"
    assert any("heldout_result.json: contains an IP address" in r for r in refused)
    assert not (tmp_path / "results" / "heldout_result.json").exists()
