#!/usr/bin/env python3
"""Summarize a gremlins JSON result file into a small, stable summary JSON
(counts per status + efficacy + the list of surviving-mutant locations),
used by run-mutation.sh to compare consecutive runs and by notify-summary.sh
to build notification text.

Usage: summarize.py <label>
Reads MUTATION_STATE_DIR/last-<label>.json, writes the summary to stdout as
JSON. Takes a label, not a path: see the LABEL_RE check below for why.
"""
import json
import os
import re
import sys
from collections import Counter

# run-mutation.sh only ever passes one of the fixed labels from its own
# PACKAGES list (e.g. "core", "storage-store") -- constrain to that shape
# rather than accepting an arbitrary path. This is the actual fix for
# pythonsecurity:S8707 ("agentic workflows should not be vulnerable to path
# injection attacks"): earlier revisions took a full file path as a CLI
# argument and tried to sanitize it after the fact (realpath + is-file, then
# realpath + a MUTATION_STATE_DIR containment check) -- Sonar's taint
# engine doesn't treat either as clearing the taint, because the sink
# (open()) still ultimately receives a value derived from the raw argument.
# Validating the argument against a strict allowlist regex *before* using it
# to build a path -- rather than validating the constructed path itself --
# is the pattern generally recognized as sanitization by taint analyzers.
LABEL_RE = re.compile(r"^[A-Za-z0-9_-]+$")


def main():
    if len(sys.argv) != 2:
        print("usage: summarize.py <label>", file=sys.stderr)
        sys.exit(2)
    label = sys.argv[1]

    if not LABEL_RE.fullmatch(label):
        print(f"error: {label!r} is not a valid label (expected {LABEL_RE.pattern})", file=sys.stderr)
        sys.exit(2)

    state_dir = os.environ.get("MUTATION_STATE_DIR")
    if not state_dir:
        print("error: MUTATION_STATE_DIR must be set", file=sys.stderr)
        sys.exit(2)

    result_path = os.path.join(os.path.realpath(state_dir), f"last-{label}.json")
    if not os.path.isfile(result_path):
        print(f"error: {result_path!r} is not a regular file", file=sys.stderr)
        sys.exit(2)

    with open(result_path) as fh:
        data = json.load(fh)

    counts = Counter()
    lived = []
    for file in data.get("files", []):
        for m in file.get("mutations", []):
            counts[m["status"]] += 1
            if m["status"] == "LIVED":
                lived.append(
                    {
                        "file": file["file_name"],
                        "line": m["line"],
                        "column": m["column"],
                        "type": m["type"],
                    }
                )

    killed = counts.get("KILLED", 0)
    died = counts.get("LIVED", 0)
    total_scored = killed + died
    efficacy = round((killed / total_scored * 100), 2) if total_scored else None

    summary = {
        "label": label,
        "total_mutants": sum(counts.values()),
        "counts": dict(counts),
        "test_efficacy_pct": efficacy,
        "lived": lived,
    }
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
