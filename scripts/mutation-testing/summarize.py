#!/usr/bin/env python3
"""Summarize a gremlins JSON result file into a small, stable summary JSON
(counts per status + efficacy + the list of surviving-mutant locations),
used by run-mutation.sh to compare consecutive runs and by notify-summary.sh
to build notification text.

Usage: summarize.py <gremlins-result.json> <label>
Writes the summary to stdout as JSON.
"""
import json
import os
import sys
from collections import Counter


def main():
    if len(sys.argv) != 3:
        print("usage: summarize.py <gremlins-result.json> <label>", file=sys.stderr)
        sys.exit(2)
    result_path, label = sys.argv[1], sys.argv[2]

    # This is only ever invoked by run-mutation.sh with a path it built
    # itself under MUTATION_STATE_DIR (see run-mutation.sh). Resolving
    # symlinks/relative segments to a canonical absolute path is not enough
    # sanitization on its own for a CLI argument (pythonsecurity:S8707,
    # "agentic workflows should not be vulnerable to path injection
    # attacks") -- confirm the resolved path is actually contained inside
    # that trusted root, not just that it names a file, before ever handing
    # it to open()/json.load(). A caller (human, script, or an LLM agent
    # driving this CLI with a hallucinated or malformed argument) can't use
    # this to read a file outside the state directory.
    state_dir = os.environ.get("MUTATION_STATE_DIR")
    if not state_dir:
        print("error: MUTATION_STATE_DIR must be set", file=sys.stderr)
        sys.exit(2)
    allowed_root = os.path.realpath(state_dir)
    resolved_path = os.path.realpath(result_path)
    if (
        os.path.commonpath([resolved_path, allowed_root]) != allowed_root
        or not os.path.isfile(resolved_path)
    ):
        print(
            f"error: {result_path!r} is not a regular file inside {allowed_root!r}",
            file=sys.stderr,
        )
        sys.exit(2)

    with open(resolved_path) as fh:
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
