#!/usr/bin/env python3
"""scripts/ci/coverage-shadow-replay.py -- replay lever C (coverage-shadow.py)
over recent real merges. Research/validation tool, not run by CI.

For each of the most recent first-parent merge commits of origin/main (what a
merge_group entry was: the PR on top of the entry ahead of it, so the diff of
`<merge>^1..<merge>` is that one PR), check the merge out, ask lever A
(select-affected.py) what it selects, and, when it selects >= 1 dependent,
run coverage-shadow.py on it. Writes into --out:
  scan.jsonl     one line per merge: PR, mode, seeds, dependents (lever A only)
  shadow.jsonl   coverage-shadow.py's own log (run/decision/summary records)
  decision-<sha7>.json   lever A's decision, for audit

Run it from a throwaway clone, with this script, coverage-shadow.py and
select-affected.py COPIED to a directory outside the clone (the checkout of an
older merge removes or replaces the tracked copies), and --declrefs pointing at
a binary built from a current checkout.
Usage:
  coverage-shadow-replay.py --out DIR [--merges 200] [--want 20]
        [--scan-only] [--max-seconds-per-pr 2400] [--test-timeout 15m]
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))


def sh(*cmd, check=True):
    return subprocess.run(cmd, capture_output=True, text=True, check=check).stdout


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--ref", default="origin/main")
    ap.add_argument("--merges", type=int, default=200)
    ap.add_argument("--want", type=int, default=20, help="stop after this many merges with >= 1 dependent")
    ap.add_argument("--scan-only", action="store_true")
    ap.add_argument("--max-seconds-per-pr", type=int, default=2400)
    ap.add_argument("--test-timeout", default="15m")
    ap.add_argument("--only-prs", default="", help="comma-separated PR numbers: replay only these")
    ap.add_argument("--skip-prs", default="", help="comma-separated PR numbers to leave out")
    ap.add_argument("--pg-dsn-map", help="JSON {package: DSN} passed to coverage-shadow.py: one Postgres database per package")
    ap.add_argument("--tmpdir", help="directory for coverage-shadow.py's private temp root (default: $TMPDIR)")
    ap.add_argument("--declrefs", help="prebuilt scripts/ci/declrefs binary")
    ap.add_argument("--no-refine", action="store_true", help="plain coverage verdicts (the CI-SELECT-2-1 behaviour)")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    if not args.no_refine and not args.declrefs:
        ap.error("--declrefs BIN is required (go build -o BIN ./scripts/ci/declrefs, from a current checkout): older merges do not have it")
    skip = {s for s in args.skip_prs.split(",") if s}
    only = {s for s in args.only_prs.split(",") if s}
    shas = sh("git", "log", "--first-parent", "--merges", f"-n{args.merges}", "--format=%H %s", args.ref).splitlines()
    print(f"replay: {len(shas)} merges on {args.ref}; want {args.want} with dependents", file=sys.stderr)
    found = 0
    with open(os.path.join(args.out, "scan.jsonl"), "a", encoding="utf-8") as scan:
        for line in shas:
            sha, _, subject = line.partition(" ")
            m = re.search(r"#(\d+)", subject)
            pr = m.group(1) if m else sha[:7]
            if pr in skip or (only and pr not in only):
                continue
            base = sha + "^1"
            rec = {"pr": pr, "sha": sha, "subject": subject[:100]}
            try:
                sh("git", "checkout", "--detach", "-q", sha)
                dpath = os.path.join(args.out, f"decision-{sha[:7]}.json")
                t0 = time.time()
                out = sh(sys.executable, "scripts/ci/select-affected.py", "--base", base, "--head", sha, "--json")
                with open(dpath, "w", encoding="utf-8") as fh:
                    fh.write(out)
                d = json.loads(out)
                seeds = set(d.get("seeds") or {})
                deps = sorted(set(d.get("affected") or []) - seeds) if d.get("mode") == "selected" else []
                rec.update(mode=d.get("mode"), reason=d.get("reason", "")[:120], seeds=len(seeds), dependents=len(deps),
                           select_seconds=round(time.time() - t0, 1))
            except Exception as exc:  # noqa: BLE001
                rec.update(mode="error", error=f"{type(exc).__name__}: {exc}"[:200], dependents=0)
            scan.write(json.dumps(rec, sort_keys=True) + "\n")
            scan.flush()
            print(f"replay: PR {pr} mode={rec.get('mode')} dependents={rec.get('dependents')}", file=sys.stderr)
            if rec.get("dependents", 0) < 1:
                continue
            found += 1
            if not args.scan_only:
                cmd = [sys.executable, os.path.join(HERE, "coverage-shadow.py"), "--base", base, "--head", sha,
                       "--pr", pr, "--decision", dpath, "--log", os.path.join(args.out, "shadow.jsonl"),
                       "--test-timeout", args.test_timeout, "--max-seconds", str(args.max_seconds_per_pr)]
                if args.pg_dsn_map:
                    cmd += ["--pg-dsn-map", args.pg_dsn_map]
                if args.tmpdir:
                    cmd += ["--tmpdir", args.tmpdir]
                cmd += ["--no-refine"] if args.no_refine else ["--declrefs", os.path.abspath(args.declrefs)]
                subprocess.run(cmd, check=False)
            if found >= args.want:
                break
    print(f"replay: done, {found} merge(s) with dependents", file=sys.stderr)


if __name__ == "__main__":
    main()
