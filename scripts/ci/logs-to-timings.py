#!/usr/bin/env python3
"""Turn verbose CI job logs into the timings.tsv that check-weights-drift.py reads.

    kgh run view --job <id> --log > faultops-4.log        (a leg run with -v)
    python3 scripts/ci/logs-to-timings.py --log faultops-4=faultops-4.log \\
        --log faultops-1=faultops-1.log > timings.tsv

Output rows: <package>\\t<top-level test>\\t<seconds>\\t<leg>, sorted. The package
comes from the leg name through the repo's own sharded_legs() (weights_layout.py),
and the `--- PASS|FAIL|SKIP: Name (1.23s)` parsing is gen-test-weights.py's, so
the two tools read a log the same way. A `go test -json` file is not accepted
here: gen-test-weights.py already reads those, and the nightly job writes -v.

A leg that is not a sharded leg, an unreadable log, or a log with no test lines
is an error (exit 2) rather than an empty table: an empty timings file would make
the drift check report nothing and look green.
"""
import argparse
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import weights_layout  # noqa: E402

_spec = importlib.util.spec_from_file_location("gen_test_weights", os.path.join(HERE, "gen-test-weights.py"))
gtw = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gtw)


def convert(items):
    """items: ["leg=path", ...] -> list of (package, test, seconds, leg)."""
    rows = []
    for item in items:
        leg, sep, path = item.partition("=")
        if not sep:
            raise SystemExit(f"logs-to-timings: --log wants LEG=FILE, got {item!r}")
        where = weights_layout.leg_package(leg)
        if where is None:
            raise SystemExit(f"logs-to-timings: {leg!r} is not a sharded leg of scripts/ci-test-legs.sh")
        pkg = where[0]
        elapsed = {}
        try:
            gtw.load_v([f"{pkg}={path}"], elapsed)
        except OSError as err:
            raise SystemExit(f"logs-to-timings: cannot read {path}: {err}")
        tests = elapsed.get(pkg, {})
        if not tests:
            raise SystemExit(f"logs-to-timings: {path} has no '--- PASS: Test (N.NNs)' lines: not a verbose log of {leg}?")
        print(f"logs-to-timings: {leg}: {len(tests)} top-level tests from {path}", file=sys.stderr)
        rows.extend((pkg, t, s, leg) for t, s in tests.items())
    return sorted(rows, key=lambda r: (r[0], r[3], r[1]))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--log", action="append", default=[], metavar="LEG=FILE", help="verbose job log of one leg (repeatable)")
    args = ap.parse_args()
    if not args.log:
        ap.error("give at least one --log LEG=FILE")
    print("# package\ttest\tseconds\tleg")
    for pkg, test, secs, leg in convert(args.log):
        print(f"{pkg}\t{test}\t{secs:.2f}\t{leg}")


if __name__ == "__main__":
    main()
