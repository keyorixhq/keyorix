#!/usr/bin/env python3
"""Summarize a gremlins JSON result file into a small, stable summary JSON
(counts per status + efficacy + the list of surviving-mutant locations),
used by run-mutation.sh to compare consecutive runs and by notify-summary.sh
to build notification text.

Usage: summarize.py <gremlins-result.json> <label>
Writes the summary to stdout as JSON.
"""
import json
import sys
from collections import Counter


def main():
    if len(sys.argv) != 3:
        print("usage: summarize.py <gremlins-result.json> <label>", file=sys.stderr)
        sys.exit(2)
    result_path, label = sys.argv[1], sys.argv[2]

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
