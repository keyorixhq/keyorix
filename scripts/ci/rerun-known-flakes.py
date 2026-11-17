#!/usr/bin/env python3
"""Run a `go test` command; rerun a failed test ONCE if, and only if, it is on
scripts/ci/known-flakes.txt (MQ-LEVERS-2 P2).

    rerun-known-flakes.py [--allowlist FILE] [--label LEG] -- go test <flags> <pkgs>

A merge-queue entry is ejected the moment a required job fails, so the retry has
to live inside the job. gotestsum --rerun-fails is not used: it is not installed
on the runners and it would rerun with the same -coverprofile, replacing the
leg's coverage file with the rerun's. This wrapper keeps the flags, drops
-coverprofile/-covermode from the rerun and sends nothing to the leg's profile.

The wrapper is a pass-through (same output, same exit code) unless
KNOWN_FLAKE_RERUN=1 is set; ci.yml sets it on merge_group only, so pull
requests, push and the nightly never rerun.

Rules, all fail-closed:
  * Output of the first run is printed untouched, live. Nothing is rewritten.
  * A rerun happens only when EVERY failed package has parsable `--- FAIL:`
    leaf tests and every leaf is on the allowlist (entry == leaf, or leaf below
    entry/). A build failure, a panic, a timeout, a DATA RACE, an unparsable
    failure, a package with no failing test, or more than MAX_RERUN leaves
    means: no rerun, the leg fails with the original exit code.
  * One rerun per test. A test that fails (or does not run, or is skipped) on
    the retry fails the leg.
  * Every rerun is recorded (see report()).
"""
import os
import re
import subprocess
import sys

MODULE_PREFIX = "github.com/keyorixhq/keyorix/"
MAX_RERUN = 5
ENABLE_ENV = "KNOWN_FLAKE_RERUN"

# go test flags whose value is the next argv word (when not written -flag=value).
VALUE_FLAGS = {
    "run", "skip", "timeout", "coverprofile", "covermode", "coverpkg", "tags", "p",
    "parallel", "count", "cpu", "bench", "benchtime", "shuffle", "vet", "ldflags",
    "gcflags", "mod", "o", "exec", "outputdir", "fuzz", "fuzztime", "fuzzminimizetime",
    "blockprofile", "cpuprofile", "memprofile", "mutexprofile", "trace", "json",
}
BOOL_FLAGS_WITH_VALUE_FORMS = {"json"}  # `-json` is boolean; never takes a value word

FAIL_TOP = re.compile(r"^--- FAIL: (\S+) \(")
FAIL_SUB = re.compile(r"^\s+--- FAIL: (\S+) \(")
PKG_FAIL = re.compile(r"^FAIL\t(\S+)(\t|\s+\[)")
PKG_DONE = re.compile(r"^(ok|\?|FAIL)\s")
UNSAFE = re.compile(r"^(panic: |fatal error: )|WARNING: DATA RACE|^panic: test timed out")


def load_allowlist(path):
    """[(pkg, test_path)] from the allowlist file; a malformed line is an error."""
    entries = []
    with open(path, encoding="utf-8") as fh:
        for n, raw in enumerate(fh, 1):
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) != 2:
                raise SystemExit(f"{path}:{n}: want '<package> <test>', got {raw.rstrip()!r}")
            entries.append((parts[0], parts[1]))
    return entries


def relpkg(pkg):
    return pkg[len(MODULE_PREFIX):] if pkg.startswith(MODULE_PREFIX) else pkg


def allowed(entries, pkg, leaf):
    rp = relpkg(pkg)
    for epkg, etest in entries:
        if epkg == rp and (leaf == etest or leaf.startswith(etest + "/")):
            return True
    return False


def parse_failures(lines):
    """-> ({pkg: [leaf, ...]}, [reason it cannot be rerun, ...]) from go test output."""
    failed = {}
    problems = []
    block = []  # lines since the last package summary line
    for line in lines:
        m = PKG_FAIL.match(line)
        if m:
            pkg = m.group(1)
            if "[build failed]" in line or "[setup failed]" in line:
                problems.append(f"{pkg}: build or setup failed")
            tops = []
            subs = []
            unsafe = None
            for b in block:
                if UNSAFE.search(b):
                    unsafe = b.strip()[:80]
                t = FAIL_TOP.match(b)
                if t:
                    tops.append(t.group(1))
                    continue
                s = FAIL_SUB.match(b)
                if s and "/" in s.group(1) and s.group(1).split("/", 1)[0] in tops:
                    # a nested name that is not below a real top-level failure is
                    # text a test logged, not a failure
                    subs.append(s.group(1))
            if unsafe:
                problems.append(f"{pkg}: {unsafe}")
            leaves = [n for n in tops + subs if not any(o != n and o.startswith(n + "/") for o in tops + subs)]
            if not leaves:
                problems.append(f"{pkg}: failed with no parsable '--- FAIL:' test")
            failed[pkg] = leaves
            block = []
        elif PKG_DONE.match(line):
            block = []
        else:
            block.append(line)
    return failed, problems


def split_cmd(cmd):
    """(flags, pkgs): the go test words before the first package, and the packages.
    Flags that take a value keep both words. -run/-coverprofile/-covermode are
    removed from flags (the rerun sets its own)."""
    i = cmd.index("test") + 1
    flags, pkgs = [], []
    while i < len(cmd):
        w = cmd[i]
        if not w.startswith("-"):
            pkgs = cmd[i:]
            break
        name = w.lstrip("-").split("=", 1)[0]
        takes_next = "=" not in w and name in VALUE_FLAGS and name not in BOOL_FLAGS_WITH_VALUE_FORMS
        word = [w, cmd[i + 1]] if takes_next and i + 1 < len(cmd) else [w]
        i += len(word)
        if name in ("run", "coverprofile", "covermode", "count", "json"):
            continue
        flags += word
    return flags, pkgs


def run_regex(leaf):
    return "/".join("^" + re.escape(part) + "$" for part in leaf.split("/"))


def stream(cmd, env=None):
    """Run cmd, echo its output live, return (rc, lines)."""
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            env=env)
    lines = []
    for raw in proc.stdout:
        line = raw.decode("utf-8", "replace")
        sys.stdout.write(line)
        sys.stdout.flush()
        lines.append(line.rstrip("\r\n"))
    return proc.wait(), lines


def report(label, results):
    """FLAKE-RERUN lines the harness greps, a GitHub annotation, the job summary."""
    passed = sum(1 for r in results if r[2])
    failed = len(results) - passed
    for pkg, leaf, ok in results:
        word = "passed on retry" if ok else "FAILED on retry"
        print(f"FLAKE-RERUN {leaf} {word} [pkg={relpkg(pkg)} leg={label}]")
        level = "warning" if ok else "error"
        print(f"::{level} title=FLAKE-RERUN::{leaf} {word} (pkg {relpkg(pkg)}, leg {label}); see the first failure above")
    print(f"FLAKE-RERUN-COUNT leg={label} attempted={len(results)} passed={passed} failed={failed}")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary and results:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(f"### FLAKE-RERUN ({label})\n\n")
            for pkg, leaf, ok in results:
                fh.write(f"- `{leaf}` ({relpkg(pkg)}) {'passed on retry' if ok else '**FAILED on retry**'}\n")
            fh.write("\nA known-flake test failed once and was rerun; its first failure is in the step log above.\n")


def main(argv):
    here = os.path.dirname(os.path.abspath(__file__))
    allowlist = os.path.join(here, "known-flakes.txt")
    label = os.environ.get("MATRIX_LEG", "-")
    args = argv[1:]
    while args and args[0] != "--":
        if args[0] == "--allowlist" and len(args) > 1:
            allowlist = args[1]
            args = args[2:]
        elif args[0] == "--label" and len(args) > 1:
            label = args[1]
            args = args[2:]
        else:
            raise SystemExit(f"unknown argument {args[0]!r}")
    cmd = args[1:]
    if len(cmd) < 2 or cmd[0] != "go" or cmd[1] != "test":
        raise SystemExit("usage: rerun-known-flakes.py [--allowlist F] [--label L] -- go test <flags> <pkgs>")

    rc, lines = stream(cmd)
    if rc == 0 or os.environ.get(ENABLE_ENV) != "1":
        if os.environ.get(ENABLE_ENV) == "1":
            report(label, [])
        return rc

    entries = load_allowlist(allowlist)
    failed, problems = parse_failures(lines)
    leaves = [(p, l) for p, ls in failed.items() for l in ls]
    refuse = list(problems)
    if not failed:
        refuse.append("no failed package could be identified in the output")
    refuse += [f"{relpkg(p)}: {l} is not on the known-flake list" for p, l in leaves if not allowed(entries, p, l)]
    if len(leaves) > MAX_RERUN:
        refuse.append(f"{len(leaves)} failing tests (more than {MAX_RERUN}) is not a flake")
    if refuse:
        print("FLAKE-RERUN not attempted (the leg fails with the first run's result):")
        for r in refuse:
            print(f"  - {r}")
        report(label, [])
        return rc

    flags, _ = split_cmd(cmd)
    results = []
    for pkg, leaf in leaves:
        print(f"FLAKE-RERUN rerunning {leaf} once ({relpkg(pkg)}, leg {label}); first failure is above")
        rerun = ["go", "test", *flags, "-count=1", "-v", "-run", run_regex(leaf), pkg]
        rrc, out = stream(rerun)
        passed_line = re.compile(r"^\s*--- PASS: " + re.escape(leaf) + r" \(")
        results.append((pkg, leaf, rrc == 0 and any(passed_line.match(o) for o in out)))
    report(label, results)
    return 0 if all(r[2] for r in results) else rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
