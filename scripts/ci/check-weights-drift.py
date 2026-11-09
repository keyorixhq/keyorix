#!/usr/bin/env python3
"""Report-only check: does scripts/ci-test-weights.tsv still balance the sharded legs?

    python3 scripts/ci/check-weights-drift.py timings.tsv [--weights scripts/ci-test-weights.tsv]
                                              [--summary $GITHUB_STEP_SUMMARY] [--strict]

timings.tsv is <package>\\t<test>\\t<seconds>\\t<leg> (scripts/ci/logs-to-timings.py
makes it from verbose job logs). Why it exists: a test that is missing from the
weights file weighs the package default (the `*` row), so a heavy new test lands
on an already full shard. That made the faultops pole of 28 Oct to 8 Nov
(TestMFAResetOpsFaultSweep, 1346 s, had no row). The leg tables only show it
after the damage; this reports it from per-test seconds.

Layout: every package of sharded_legs() (more than one shard) is placed with the
repo's own weighted_shard_assignment under --weights (weights_layout.py calls the
bash, there is no second packer). The test names are the ones in the timings.
"Measured" is the timings summed over THAT layout, not over the leg column: the
question is whether the weights file balances the measured times, so a file
regenerated after the measuring run is judged by what it would do. The leg
column is only used to say when the run used a different layout.

Rule A (per sharded package): a test measured above 60 s with no explicit row in
the weights file. Prints name, seconds, the default weight it gets, and the shard
the layout puts it on.

Rule B (per sharded package): a shard whose measured sum is above 1.30 x the
median of the package's shards. Prints predicted (weight sum, plus preload)
against measured for every shard. When the shard's heaviest test already has an
explicit weight above the package's shard target (predicted total / shards), the
file already knows it and no weight can balance it, so it prints "dominated by
<test>: split the test" instead of a drift message, and does not nag after a
regeneration.

Exit status: 0 whatever is found, and 0 on unusable input too (it is announced
loudly, and as a ::warning) -- report-only first, per docs/guard-rollout-contract.md.
--strict exits 1 on a finding and 2 on unusable input, for the later flip.
No clock is read; output depends only on the two input files and the repo.

Blind spots (also printed at the end of the report): t.Parallel tests are timed
from their resume; subtests are not shard units and are not read; a test that
did not run (a name missing from the timings) is invisible, so a shard of a leg
that crashed early reads light; a runner is noisy by +-6 min between rounds
(ci-test-legs.sh), hence a 30% margin over a median rather than over the mean.
"""
import argparse
import os
import statistics
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import weights_layout  # noqa: E402

RULE_A_SECONDS = 60.0
RULE_B_RATIO = 1.30
DEFAULT_WEIGHTS = os.path.join(weights_layout.ROOT, "scripts", "ci-test-weights.tsv")


class InputError(Exception):
    pass


def read_timings(path):
    """[(package, test, seconds, leg)]; leg is "" when the file has three columns."""
    rows = []
    try:
        fh = open(path, encoding="utf-8")
    except OSError as err:
        raise InputError(f"cannot read timings {path}: {err}")
    with fh:
        for n, line in enumerate(fh, 1):
            if line.startswith("#") or not line.strip():
                continue
            f = line.rstrip("\n").split("\t")
            if len(f) < 3:
                raise InputError(f"{path}:{n}: want package<TAB>test<TAB>seconds[<TAB>leg], got {line.strip()!r}")
            try:
                secs = float(f[2])
            except ValueError:
                raise InputError(f"{path}:{n}: seconds is not a number: {f[2]!r}")
            rows.append((f[0], f[1], secs, f[3] if len(f) > 3 else ""))
    if not rows:
        raise InputError(f"{path} has no timing rows (an empty table would read as 'no drift')")
    return rows


def preload_map(spec):
    out = {}
    if spec != "-":
        for part in spec.split(","):
            shard, _, w = part.partition(":")
            out[int(shard)] = float(w)
    return out


def analyse(rows, weights_path):
    """Findings and per-package tables. Returns (packages, findings, notes)."""
    explicit, default = weights_layout.read_weights(weights_path)
    layouts = weights_layout.sharded_packages()
    by_pkg = {}
    for pkg, test, secs, leg in rows:
        by_pkg.setdefault(pkg, {})[test] = (secs, leg)
    packages, findings, notes = [], [], []
    for pkg in sorted(by_pkg):
        if pkg not in layouts:
            continue
        info = layouts[pkg]
        n = info["shards"]
        tests = by_pkg[pkg]
        rowsw = explicit.get(pkg, {})
        dflt = default.get(pkg, 1.0)  # the awk in weighted_shard_assignment: def = 1 without a `*` row
        shard_of = weights_layout.assign(pkg, n, info["preload"], sorted(tests), weights_path)
        pre = preload_map(info["preload"])
        predicted = {k: pre.get(k, 0.0) for k in range(1, n + 1)}
        measured = {k: 0.0 for k in range(1, n + 1)}
        heaviest = {k: ("", 0.0) for k in range(1, n + 1)}  # shard -> (test, explicit weight)
        for test, (secs, _leg) in tests.items():
            k = shard_of[test]
            predicted[k] += rowsw.get(test, dflt)
            measured[k] += secs
            if test in rowsw and rowsw[test] > heaviest[k][1]:
                heaviest[k] = (test, rowsw[test])
        legs_seen = {leg for _s, leg in tests.values() if leg}
        moved = sum(1 for t, (_s, leg) in tests.items()
                    if leg and leg != f"{info['prefix']}-{shard_of[t]}")
        if moved:
            notes.append(f"{pkg}: {moved} of {len(tests)} tests ran on another leg than this weights file places them "
                         f"(the run used another file); measured sums below follow this file's layout")
        total_pred = sum(predicted.values())
        target = total_pred / n
        med = statistics.median(measured.values())
        pk = {"package": pkg, "shards": n, "prefix": info["prefix"], "predicted": predicted, "measured": measured,
              "median": med, "target": target, "tests": len(tests)}
        packages.append(pk)

        for test, (secs, _leg) in sorted(tests.items(), key=lambda kv: (-kv[1][0], kv[0])):
            if secs > RULE_A_SECONDS and test not in rowsw:
                findings.append({"rule": "A", "package": pkg, "test": test, "seconds": secs,
                                 "default": dflt, "shard": shard_of[test],
                                 "msg": f"{pkg} {test} took {secs:.0f} s and has no row in the weights file "
                                        f"(it weighs the default {dflt:.4g}); it sits on {info['prefix']}-{shard_of[test]}"})

        if len(legs_seen) and len(legs_seen) < n:
            notes.append(f"{pkg}: timings cover {len(legs_seen)} of {n} legs ({', '.join(sorted(legs_seen))}); Rule B skipped")
            continue
        if med <= 0:
            continue
        for k in range(1, n + 1):
            if measured[k] > RULE_B_RATIO * med:
                top, topw = heaviest[k]
                table = ", ".join(f"{info['prefix']}-{j} {predicted[j]:.0f}/{measured[j]:.0f}" for j in range(1, n + 1))
                if top and topw > target:
                    msg = (f"{pkg} {info['prefix']}-{k}: measured {measured[k]:.0f} s vs median {med:.0f} s, dominated by "
                           f"{top} ({tests[top][0]:.0f} s, weight {topw:.0f} > shard target {target:.0f}): "
                           f"weights cannot balance this, split the test")
                    kind = "dominated"
                else:
                    msg = (f"{pkg} {info['prefix']}-{k}: measured {measured[k]:.0f} s is {measured[k] / med:.2f}x the median "
                           f"{med:.0f} s (predicted {predicted[k]:.0f} s); predicted/measured per shard: {table}")
                    kind = "drift"
                findings.append({"rule": "B", "kind": kind, "package": pkg, "shard": k, "predicted": predicted[k],
                                 "measured": measured[k], "median": med, "msg": msg})
    return packages, findings, notes


BLIND_SPOTS = ("Blind spots: t.Parallel tests are timed from resume; subtests are not shard units; a test absent from "
               "the timings is invisible; runner noise is +-6 min between rounds.")


def render(packages, findings, notes, weights_path, timings_path):
    out = ["## Weights drift (report-only)", "",
           f"timings `{os.path.basename(timings_path)}`, weights `{os.path.basename(weights_path)}`, "
           f"Rule A > {RULE_A_SECONDS:.0f} s without a row, Rule B > {RULE_B_RATIO:.2f} x median shard.", ""]
    if not packages:
        out += ["No sharded package in the timings: nothing was checked.", ""]
    for pk in packages:
        out += [f"### {pk['package']} ({pk['tests']} tests, {pk['shards']} shards, target {pk['target']:.0f} s)", "",
                "| shard | predicted | measured | x median |", "|---|---|---|---|"]
        for k in range(1, pk["shards"] + 1):
            ratio = pk["measured"][k] / pk["median"] if pk["median"] else 0.0
            out.append(f"| {pk['prefix']}-{k} | {pk['predicted'][k]:.0f} | {pk['measured'][k]:.0f} | {ratio:.2f} |")
        out.append("")
    for note in notes:
        out.append(f"- note: {note}")
    if notes:
        out.append("")
    if findings:
        out += [f"**{len(findings)} warning(s):**", ""] + [f"- Rule {f['rule']}: {f['msg']}" for f in findings]
    else:
        out.append("No drift found.")
    out += ["", BLIND_SPOTS, ""]
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("timings")
    ap.add_argument("--weights", default=DEFAULT_WEIGHTS)
    ap.add_argument("--summary", help="append the markdown report to this file (GITHUB_STEP_SUMMARY)")
    ap.add_argument("--strict", action="store_true", help="exit 1 on a finding, 2 on unusable input (default: always 0)")
    args = ap.parse_args(argv)
    try:
        rows = read_timings(args.timings)
        if not os.path.isfile(args.weights):
            raise InputError(f"cannot read weights {args.weights}")
        packages, findings, notes = analyse(rows, args.weights)
    except (InputError, RuntimeError) as err:
        print(f"check-weights-drift: ERROR {err}", file=sys.stderr)
        print(f"::warning title=weights-drift input::{err}")
        return 2 if args.strict else 0
    report = render(packages, findings, notes, args.weights, args.timings)
    print(report)
    for f in findings:
        print(f"::warning title=weights-drift rule {f['rule']}::{f['msg']}")
    if args.summary:
        with open(args.summary, "a", encoding="utf-8") as fh:
            fh.write(report + "\n")
    return 1 if (findings and args.strict) else 0


if __name__ == "__main__":
    sys.exit(main())
