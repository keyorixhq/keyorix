#!/usr/bin/env python3
"""Run the RD-AAT SMT model (docs/formal/rd-aat-smt/README.md) and check every verdict.

    python3 docs/formal/rd-aat-smt/run.py                  # every case, z3 (and cvc5 if found)
    python3 docs/formal/rd-aat-smt/run.py --solver z3      # one solver
    python3 docs/formal/rd-aat-smt/run.py --witness c-keys/c04_mutant_drop_R3.smt2

Each case file is appended to its directory's prelude.smt2 and fed to the solver on stdin.
The case's `; EXPECT:` line lists the verdict of every (check-sat) in order. A case passes only
if the solver prints exactly that sequence. `unknown` or a timeout is a failure, never a pass.

Exit codes: 0 every case as expected on every solver run; 1 at least one mismatch;
2 no solver found ("pending tool install"). Standard library only. Not run by CI.
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PARTS = ["a-core", "b-allany", "c-keys"]
TIMEOUT_S = 60
VERDICT = re.compile(r"^(sat|unsat|unknown|timeout)\s*$")


def solver_cmd(name):
    if name == "z3":
        return ["z3", f"-T:{TIMEOUT_S}", "-in"]
    # cvc5: incremental for push/pop, finite-model-find so satisfiable cases over uninterpreted
    # sorts come back sat instead of unknown. Not exercised on the machine that built the model.
    return ["cvc5", "--incremental", "--finite-model-find", f"--tlimit={TIMEOUT_S * 1000}", "--lang", "smt2"]


def solver_version(name):
    try:
        out = subprocess.run([name, "--version"], capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return "?"
    return out.strip().splitlines()[0] if out.strip() else "?"


def header(path, key):
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.startswith(f"; {key}:"):
                return line.split(":", 1)[1].split()
    return []


def cases(selected):
    if selected:
        return [os.path.join(HERE, s) for s in selected]
    out = []
    for part in PARTS:
        d = os.path.join(HERE, part)
        out += [os.path.join(d, f) for f in sorted(os.listdir(d)) if f.endswith(".smt2") and f != "prelude.smt2"]
    return out


def run_case(solver, path):
    with open(os.path.join(os.path.dirname(path), "prelude.smt2"), encoding="utf-8") as f:
        src = f.read()
    with open(path, encoding="utf-8") as f:
        src += "\n" + f.read()
    t0 = time.monotonic()
    try:
        p = subprocess.run(solver_cmd(solver), input=src, capture_output=True, text=True, timeout=TIMEOUT_S * 4)
        out = p.stdout + p.stderr
    except subprocess.TimeoutExpired:
        out = "timeout\n"
    ms = int((time.monotonic() - t0) * 1000)
    got = [m.group(1) for m in (VERDICT.match(l) for l in out.splitlines()) if m]
    return got, ms, out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--solver", choices=["z3", "cvc5", "all"], default="all")
    ap.add_argument("--witness", action="store_true", help="print the solver's full output (models of sat cases)")
    ap.add_argument("case", nargs="*", help="case files relative to this directory (default: all)")
    a = ap.parse_args()

    wanted = ["z3", "cvc5"] if a.solver == "all" else [a.solver]
    found = [s for s in wanted if shutil.which(s)]
    missing = [s for s in wanted if s not in found]
    for s in missing:
        print(f"note: {s} not on PATH, skipped", file=sys.stderr)
    if not found:
        print("pending tool install: neither z3 nor cvc5 is on PATH (brew install z3 cvc5)", file=sys.stderr)
        return 2

    tty = sys.stderr.isatty()
    failures = 0
    total = 0
    for s in found:
        print(f"== {s}: {solver_version(s)}  (timeout {TIMEOUT_S}s per case)", file=sys.stderr)
        t_all = time.monotonic()
        for path in cases(a.case):
            rel = os.path.relpath(path, HERE)
            expect = header(path, "EXPECT")
            kind = (header(path, "KIND") or ["?"])[0]
            if tty:
                print(f"   running {rel} ...", end="", file=sys.stderr, flush=True)
            got, ms, out = run_case(s, path)
            # A solver error (syntax, unknown symbol) fails the case even when the verdicts match:
            # an assertion the solver rejected was not checked, so a mutant could "pass" without it.
            errored = "(error" in out
            ok = got == expect and bool(expect) and not errored
            total += 1
            failures += 0 if ok else 1
            if tty:
                print("\r\033[K", end="", file=sys.stderr)
            print(f"{'ok  ' if ok else 'FAIL'} {s:4} {kind:6} {rel:52} expect={' '.join(expect):11} got={' '.join(got) or '-':11} {ms:6d} ms")
            if a.witness or not ok:
                print(out.rstrip())
        print(f"== {s}: done in {time.monotonic() - t_all:.1f}s", file=sys.stderr)
    print(f"{total - failures}/{total} cases as expected", file=sys.stderr)
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
