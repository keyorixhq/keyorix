"""Tests for run-mutation.sh's PACKAGES table: the assignment must not run
anything (its comment lines quote code), and every entry must parse into the
fields the loop reads. The block is evaluated on its own, under the script's
own `set -euo pipefail`, in an empty directory: run-mutation.sh itself resets
KEYORIX_REPO to origin/main and cannot be run here."""
import pathlib
import re
import subprocess

SCRIPT = pathlib.Path(__file__).with_name("run-mutation.sh")
FLOOR = re.compile(r"^\d+(\.\d+)?$")


def _packages_block():
    lines = SCRIPT.read_text().splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith("PACKAGES="))
    # Ends at the heredoc's closing ")" or, for a quoted string, at the line
    # that closes the quote.
    end = next(i for i in range(start + 1, len(lines)) if lines[i] == ")" or lines[i].endswith('"'))
    return "\n".join(lines[start : end + 1])


def _evaluate(tmp_path):
    return subprocess.run(
        ["bash", "-c", "set -euo pipefail\n" + _packages_block() + '\nprintf "%s" "$PACKAGES"'],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )


def test_packages_assignment_runs_nothing(tmp_path):
    res = _evaluate(tmp_path)
    assert res.returncode == 0, res.stderr
    assert res.stderr == ""
    assert list(tmp_path.iterdir()) == [], "the assignment wrote a file"
    # The comment text comes through verbatim.
    assert "`MinLength > 0`" in res.stdout


def test_every_entry_parses(tmp_path):
    res = _evaluate(tmp_path)
    entries = [line for line in res.stdout.splitlines() if line and not line.startswith("#")]
    labels = set()
    for line in entries:
        fields = line.split("|")
        assert 2 <= len(fields) <= 5, line
        pkg, label = fields[0], fields[1]
        assert (SCRIPT.parents[2] / pkg).is_dir(), line
        assert label and label not in labels, line
        labels.add(label)
        if len(fields) > 2 and fields[2]:
            assert fields[2].isdigit(), line
        for floor in fields[3:]:
            assert floor == "" or FLOOR.match(floor), line
    assert {"serverguard", "solewriter"} <= labels
