#!/usr/bin/env python3
"""regate.py — finding re-fuzz gate.

Given a git diff range (or a list of changed files), maps the changed packages
to KFZ findings whose fuzz targets cover those packages, then:
  1. Replays any committed seed-corpus entries (testdata/fuzz/<FuncName>/<seed>)
     for each matched finding.
  2. Runs a bounded fuzz burst (default 60 s) for each matched target.

Exits 0 when no findings match ('no findings touch this diff') or when all
replay and burst checks pass.  Exits 1 on any replay failure or burst crash.
Exits 2 on configuration/registry errors (missing registry, missing seed file,
bad arguments).

Usage:
  regate.py --diff-range HEAD~1..HEAD [options]
  regate.py --diff-names file1.go file2.go [options]
  git diff --name-only HEAD~1..HEAD | regate.py --stdin [options]

Required:
  --registry DIR        Path to registry/findings/ directory.
                        May also be set via REGATE_REGISTRY env var.

Optional:
  --targets-d DIR       Path to scripts/fuzzing/targets.d/ (default: auto-detect
                        relative to this script's location).
  --repo-root DIR       Repository root (default: auto-detect via git).
  --fuzztime DURATION   Fuzz burst duration (default: 60s).
  --no-burst            Skip the burst step; run replay only.
  --no-replay           Skip the seed replay; run burst only.
  --id ID [ID...]       Only check these finding IDs.
  --dry-run             Print the matched findings table without running any tests.
  --registered-seeds FILE
                        JSON file mapping finding_id → [seed_rel_paths].
                        When provided, missing seed files are an error rather than
                        a silent gap.  Intended for the private-registry CI variant.
  -v, --verbose         Print full go test output on failure.
"""
import argparse
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))


def _auto_targets_d() -> str:
    """Find targets.d relative to this script's location."""
    candidate = os.path.join(_HERE, "..", "targets.d")
    candidate = os.path.normpath(candidate)
    if os.path.isdir(candidate):
        return candidate
    return ""


def _auto_repo_root() -> str:
    """Find the repository root via git."""
    import subprocess
    try:
        r = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, check=True,
        )
        return r.stdout.strip()
    except Exception:
        return os.getcwd()


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Map a git diff to KFZ findings and run a re-fuzz gate.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    source = p.add_mutually_exclusive_group(required=True)
    source.add_argument("--diff-range", metavar="A..B",
                        help="git diff range, e.g. HEAD~1..HEAD")
    source.add_argument("--diff-names", nargs="+", metavar="FILE",
                        help="explicit list of changed file paths")
    source.add_argument("--staged", action="store_true",
                        help="use git diff --cached (staged changes)")
    source.add_argument("--stdin", action="store_true",
                        help="read changed file names from stdin, one per line")

    p.add_argument("--registry", metavar="DIR",
                   help="path to registry/findings/ (or set REGATE_REGISTRY)")
    p.add_argument("--targets-d", metavar="DIR",
                   help="path to scripts/fuzzing/targets.d/")
    p.add_argument("--repo-root", metavar="DIR",
                   help="repository root (default: git rev-parse --show-toplevel)")
    p.add_argument("--fuzztime", default="60s",
                   help="fuzz burst duration (default: %(default)s)")
    p.add_argument("--no-burst", action="store_true",
                   help="skip burst step")
    p.add_argument("--no-replay", action="store_true",
                   help="skip seed replay step")
    p.add_argument("--id", nargs="+", metavar="KFZ-YYYY-NNN",
                   help="limit to specific finding IDs")
    p.add_argument("--dry-run", action="store_true",
                   help="print matched findings without running tests")
    p.add_argument("--registered-seeds", metavar="FILE",
                   help="JSON map {finding_id: [seed_path, ...]}")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="print full go test output on failure")
    return p


def _get_diff_names(args, repo_root: str) -> list[str]:
    from regate_lib import git_diff_names, git_staged_names
    if args.diff_range:
        return git_diff_names(args.diff_range, repo_root)
    if args.staged:
        return git_staged_names(repo_root)
    if args.stdin:
        return [l.rstrip("\n") for l in sys.stdin if l.strip()]
    # args.diff_names
    return list(args.diff_names)


def _fmt_ok(ok: bool) -> str:
    return "PASS" if ok else "FAIL"


def _print_table(rows, verbose: bool = False) -> None:
    if not rows:
        return
    # Header
    print(f"\n{'FINDING':<20} {'TARGET PKG':<35} {'FUNC':<40} {'STEP':<30} {'RESULT'}")
    print("-" * 130)
    for r in rows:
        step = r.seed_name if r.seed_name else "(burst)"
        result = _fmt_ok(r.ok)
        if r.error_msg and not r.ok:
            result += f"  [{r.error_msg}]"
        print(f"{r.finding_id:<20} {r.target.pkg:<35} {r.target.func:<40} {step:<30} {result}")
        if not r.ok and verbose and r.output:
            # Print only FAIL/panic lines to avoid leaking input bytes
            for line in r.output.splitlines():
                if any(line.startswith(p) for p in ("--- FAIL", "FAIL", "panic")):
                    print(f"    {line}")
    print()


def main(argv=None) -> int:
    # Import here so tests can patch sys.path before import
    sys.path.insert(0, _HERE)
    from regate_lib import (
        GateConfig,
        ReproMissingError,
        RegistryError,
        changed_packages,
        run_gate,
    )

    p = _build_parser()
    args = p.parse_args(argv)

    registry = args.registry or os.environ.get("REGATE_REGISTRY", "")
    if not registry:
        print("ERROR: --registry (or REGATE_REGISTRY) is required.", file=sys.stderr)
        return 2

    targets_d = args.targets_d or _auto_targets_d()
    if not targets_d or not os.path.isdir(targets_d):
        print(f"ERROR: targets.d directory not found (tried {targets_d!r}).\n"
              "Pass --targets-d.", file=sys.stderr)
        return 2

    repo_root = args.repo_root or _auto_repo_root()

    try:
        diff_names = _get_diff_names(args, repo_root)
    except Exception as exc:
        print(f"ERROR getting diff: {exc}", file=sys.stderr)
        return 2

    pkgs = changed_packages(diff_names)
    if not pkgs:
        print("no findings touch this diff")
        return 0

    registered_seeds = None
    if args.registered_seeds:
        try:
            with open(args.registered_seeds) as fh:
                registered_seeds = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"ERROR reading --registered-seeds: {exc}", file=sys.stderr)
            return 2

    cfg = GateConfig(
        registry_dir=registry,
        targets_d=targets_d,
        repo_root=repo_root,
        fuzztime=args.fuzztime,
        no_burst=args.no_burst,
        no_replay=args.no_replay,
        only_ids=args.id or [],
    )

    try:
        out = run_gate(diff_names, cfg, registered_seeds)
    except ReproMissingError as exc:
        print(f"ERROR (missing reproducer): {exc}", file=sys.stderr)
        return 2
    except RegistryError as exc:
        print(f"ERROR (registry): {exc}", file=sys.stderr)
        return 2

    if not out.matched_findings:
        print("no findings touch this diff")
        return 0

    # Print matched findings summary
    print(f"\nFound {len(out.matched_findings)} finding(s) touching this diff:")
    for fm in out.matched_findings:
        funcs = sorted({t.func for t in fm.targets if t.func})
        pkgs_hit = sorted({t.pkg for t in fm.targets})
        print(f"  {fm.id}: {fm.title[:60]}")
        print(f"    packages: {', '.join(pkgs_hit)}")
        if funcs:
            print(f"    fuzz funcs: {', '.join(funcs)}")

    if args.dry_run:
        print("\n(dry-run: no tests executed)")
        return 0

    # Execute
    _print_table(out.rows, verbose=args.verbose)

    failures = [r for r in out.rows if not r.ok and "burst skipped" not in r.error_msg]
    if failures:
        print(f"GATE FAILED: {len(failures)} check(s) failed.", file=sys.stderr)
        return 1

    # All passed
    n_replay = sum(1 for r in out.rows if r.seed_name is not None)
    n_burst = sum(1 for r in out.rows if r.seed_name is None and "skipped" not in r.error_msg)
    print(f"GATE PASSED: {n_replay} replay(s), {n_burst} burst(s), 0 failures.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
