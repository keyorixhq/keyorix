#!/usr/bin/env python3
"""scripts/ci/coverage-shadow.py -- lever C, SHADOW MODE (CI-SELECT-2).

Lever A (select-affected.py) selects every package that imports a changed
package. Most of those dependents never execute the changed lines. This script
measures that, and ONLY measures it: it logs a KEEP / SKIPPABLE decision per
lever-A dependent as JSON lines and never skips, fails or reorders a test.
Nothing here is wired into an enforcement path; it exits 0 on every path
(an internal error is logged as an "error" record) unless --strict is given.

Usage:
  coverage-shadow.py --base <sha> [--head <rev>] [--pr N] [--log FILE]
                     [--decision FILE] [--test-timeout 10m]
                     [--max-dependents N] [--max-seconds S]

  --log FILE     append JSON lines there ("-" = stdout, the default)
  --decision F   a saved `select-affected.py --json` output (replay/tests);
                 without it select-affected.py is run for --base/--head
  The working tree must be --head (a merge_group checkout is): coverage line
  numbers are the tree's. A mismatch is logged and every dependent is KEEP.

Per dependent D (lever A's `affected` minus its `seeds`):
  go test -covermode=set -coverpkg=<changed packages> -coverprofile=T -json D
  then the diff's changed lines (new side, `git diff -U0`) are matched
  against T's blocks. A changed line is
    covered       some profile block containing it has count > 0
    uncovered     blocks contain it, all count 0
    ignored       no block, and the line is blank, comment-only, closing
                  punctuation or a plain import (cannot change behaviour)
    undetermined  no block and not ignorable (a const, type, case label,
                  package-level var, a deleted line, a file absent from the
                  profile because of build tags ...): coverage cannot say
  KEEP when any line is covered. SKIPPABLE only when no line is covered, none
  is undetermined and at least one is uncovered (or every changed line is
  ignorable). EVERY doubt resolves to KEEP, because a false SKIPPABLE would
  skip a test that exercises the change while a false KEEP only costs CI time:
    test-failed / timeout / build-failed / no-test-files / profile-missing
    non-go-input       D reaches a package that reads a changed non-Go file
                       (or has one embedded): coverage cannot see that
    spawns-subprocess  D's tests import os/exec: code run in a child process
                       is not in the profile
    tests-skipped      D's tests skipped (a missing Postgres DSN, ...): the
                       skipped tests would have executed lines. The verdict
                       without this rule is kept as verdict_if_skips_ignored.
    tree-mismatch      the working tree is not --head

Temp files: one private root directory (also GOTMPDIR for the go build), the
profile removed right after it is parsed, the whole root removed on every exit
path (normal, exception, timeout, SIGTERM/SIGINT). A timed-out test run is
killed as a process group.
"""
import argparse
import atexit
import bisect
import importlib.util
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from collections import deque

MODULE = "github.com/keyorixhq/keyorix"
SCHEMA = 1
OTHER_MODULES = ("cli/", "operator/", "migrate/", "devtools/vacuum/")

PROFILE_LINE = re.compile(r"^(.+):(\d+)\.(\d+),(\d+)\.(\d+) (\d+) (\d+)$")
HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def log(msg):
    print(f"coverage-shadow: {msg}", file=sys.stderr, flush=True)


# --------------------------------------------------------------------------
# diff -> changed line ranges
# --------------------------------------------------------------------------

def parse_diff(text):
    """`git diff -U0` text -> ({path: [(start, end, deletion)]}, [deleted paths]).

    Ranges are new-side line numbers, inclusive. A hunk that only removes lines
    (count 0 on the new side) has no new line: it is recorded as the two lines
    around the cut, deletion=True, so the matcher can look at the surrounding
    blocks but never treats the cut as a comment-only change. A deleted file
    (`+++ /dev/null`) is returned in the second list."""
    ranges, deleted, cur, old = {}, [], None, ""
    for line in text.splitlines():
        if line.startswith("--- "):
            old = line[4:].split("\t", 1)[0]
            old = old[2:] if old.startswith("a/") else old
            cur = None
        elif line.startswith("+++ "):
            target = line[4:].split("\t", 1)[0]
            if target == "/dev/null":
                cur = None
                if old and old != "/dev/null":
                    deleted.append(old)
            else:
                cur = target[2:] if target.startswith("b/") else target
                ranges.setdefault(cur, [])
        elif line.startswith("@@") and cur is not None:
            m = HUNK.match(line)
            if not m:
                continue
            start = int(m.group(1))
            count = 1 if m.group(2) is None else int(m.group(2))
            if count == 0:
                ranges[cur].append((max(start, 1), start + 1, True))
            else:
                ranges[cur].append((start, start + count - 1, False))
    return {k: v for k, v in ranges.items() if v}, deleted


# --------------------------------------------------------------------------
# coverage profile
# --------------------------------------------------------------------------

def parse_profile(text, module=MODULE):
    """Coverage profile -> {repo-relative path: [(start, end, count)]}.

    Only the line span of a block matters here (columns are ignored: a diff
    hunk is whole lines). Paths are stored module-relative so they compare with
    `git diff` paths. Unparseable lines are skipped; `mode:` is checked by the
    caller."""
    blocks = {}
    prefix = module + "/"
    for line in text.splitlines():
        m = PROFILE_LINE.match(line.strip())
        if not m:
            continue
        path = m.group(1)
        if path.startswith(prefix):
            path = path[len(prefix):]
        blocks.setdefault(path, []).append((int(m.group(2)), int(m.group(4)), int(m.group(7))))
    return blocks


# --------------------------------------------------------------------------
# which changed lines cannot change behaviour
# --------------------------------------------------------------------------

DIRECTIVE = re.compile(r"^//(go:|line |export |\s*\+build)")
CLOSERS = re.compile(r"^[\s)}\],;]*$")
IMPORT_SPEC = re.compile(r'^(?:[A-Za-z0-9_]+\s+)?"[^"]*"$')


def code_text_by_line(src):
    """The source with comments blanked, one string per line (index 0 = line 1).

    A mini Go lexer: it knows "..." and rune and raw `...` literals (which can
    hold // or /*), // and /* */ comments. Directive comments (//go:build,
    //go:embed, //line, //export, // +build) are kept: they change compilation."""
    lines, cur, i, n = [], [], 0, len(src)

    def newline():
        lines.append("".join(cur))
        cur.clear()

    while i < n:
        c = src[i]
        if c == "\n":
            newline()
            i += 1
        elif c == "/" and src.startswith("//", i):
            j = src.find("\n", i)
            j = n if j < 0 else j
            text = src[i:j]
            if DIRECTIVE.match(text):
                cur.append(text)
            i = j
        elif c == "/" and src.startswith("/*", i):
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            for ch in src[i:j]:
                if ch == "\n":
                    newline()
            cur.append(" ")
            i = j
        elif c == '"':
            j = i + 1
            while j < n and src[j] not in '"\n':
                j += 2 if src[j] == "\\" else 1
            cur.append(src[i:j + 1])
            i = j + 1
        elif c == "`":
            j = src.find("`", i + 1)
            j = n - 1 if j < 0 else j
            seg = src[i:j + 1]
            parts = seg.split("\n")
            for k, part in enumerate(parts):
                cur.append(part if part.strip() else "`")  # a raw-string line is code
                if k < len(parts) - 1:
                    newline()
            i = j + 1
        elif c == "'":
            j = i + 1
            while j < n and src[j] not in "'\n":
                j += 2 if src[j] == "\\" else 1
            cur.append(src[i:j + 1])
            i = j + 1
        else:
            cur.append(c)
            i += 1
    if cur or not src.endswith("\n"):
        newline()
    return lines


def ignorable_lines(src):
    """1-based line numbers of `src` that cannot change behaviour: blank,
    comment-only, closing punctuation only, `package x`, and a plain import
    (not `_`/`.`, whose init side effect is behaviour). A file importing "C"
    (cgo: a /* */ preamble is code) has none."""
    text = code_text_by_line(src)
    if any(re.match(r'^\s*import\s+"C"\s*$', t) for t in text):
        return set()
    out, in_block = set(), False
    for no, t in enumerate(text, 1):
        s = t.strip()
        if in_block:
            if s.startswith(")"):
                in_block = False
                out.add(no)
            elif IMPORT_SPEC.match(s) and not re.match(r'^[_.]\s', s):
                out.add(no)
            continue
        if s == "" or CLOSERS.match(s) or re.match(r"^package\s+\w+$", s):
            out.add(no)
        elif re.match(r"^import\s*\($", s):
            in_block = True
            out.add(no)
        elif re.match(r'^import\s+(?:[A-Za-z0-9]+\s+)?"[^"]*"$', s):
            out.add(no)
    return out


# --------------------------------------------------------------------------
# the matcher: changed ranges vs profile blocks
# --------------------------------------------------------------------------

def expand(ranges):
    """({line: deletion?}) for [(start, end, deletion)]. A line that is both
    an added line and next to a pure deletion counts as added (stricter on
    nothing: deletion only widens what must not be ignored)."""
    lines = {}
    for s, e, deletion in ranges:
        for ln in range(s, e + 1):
            lines[ln] = lines.get(ln, True) and deletion
    return lines


def match_file(ranges, blocks, ignorable):
    """Classify the changed lines of one file.

    ranges: [(start, end, deletion)]; blocks: [(start, end, count)] or [] when
    the file is not in the profile; ignorable: lines safe to ignore.
    Returns {"covered": [...], "uncovered": [...], "undetermined": [...],
    "ignored": [...]} (sorted line numbers). Pure-deletion lines are never
    ignored."""
    lines = expand(ranges)
    order = sorted(lines)
    hit = {ln: None for ln in order}  # None = no block; False = blocks, all 0; True = covered
    for s, e, count in blocks:
        i = bisect.bisect_left(order, s)
        while i < len(order) and order[i] <= e:
            ln = order[i]
            hit[ln] = True if count > 0 else (hit[ln] if hit[ln] else False)
            i += 1
    res = {"covered": [], "uncovered": [], "undetermined": [], "ignored": []}
    for ln in order:
        if hit[ln] is True:
            res["covered"].append(ln)
        elif hit[ln] is False:
            res["uncovered"].append(ln)
        elif lines[ln] is False and ln in ignorable:
            res["ignored"].append(ln)
        else:
            res["undetermined"].append(ln)
    return res


def match_all(changes, profile, ignorable_by_file):
    """{file: match_file(...)} for every measured changed file."""
    return {f: match_file(r, profile.get(f, []), ignorable_by_file.get(f, set())) for f, r in changes.items()}


def verdict_from_match(per_file):
    """(verdict, basis) from match_all's result, before the run-level rules."""
    tot = {k: sum(len(v[k]) for v in per_file.values()) for k in ("covered", "uncovered", "undetermined", "ignored")}
    if tot["covered"]:
        return "KEEP", "covered"
    if tot["undetermined"]:
        return "KEEP", "undetermined-lines"
    if tot["uncovered"]:
        return "SKIPPABLE", "uncovered"
    if tot["ignored"]:
        return "SKIPPABLE", "comment-only"
    return "KEEP", "no-go-change"


def to_ranges(nums):
    """[3,4,5,9] -> ["3-5", "9"]."""
    out, i = [], 0
    while i < len(nums):
        j = i
        while j + 1 < len(nums) and nums[j + 1] == nums[j] + 1:
            j += 1
        out.append(str(nums[i]) if i == j else f"{nums[i]}-{nums[j]}")
        i = j + 1
    return out


# --------------------------------------------------------------------------
# lever A glue
# --------------------------------------------------------------------------

def load_lever_a(path):
    """select-affected.py as a module (read only: its own helpers decide what
    a "package that reads this file" is, so this script does not copy rule 3).
    None when it cannot be loaded; the caller then keeps every dependent."""
    try:
        spec = importlib.util.spec_from_file_location("select_affected", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        for name in ("load_packages", "literal_index", "references", "module_go_files"):
            if not hasattr(mod, name):
                return None
        return mod
    except Exception as exc:  # noqa: BLE001 - shadow mode: never raise
        log(f"cannot load select-affected.py helpers: {type(exc).__name__}: {exc}")
        return None


def owning_package(path, dir_to_pkg):
    if path.startswith(OTHER_MODULES):
        return None
    d = os.path.dirname(path)
    while d:
        if d in dir_to_pkg:
            return dir_to_pkg[d]
        d = os.path.dirname(d)
    return None


def reaches(obj, packages, targets):
    """lever A's importer rule: transitive Deps, direct test imports, and one
    hop through their Deps."""
    if set(obj.get("Deps") or []) & targets:
        return True
    timps = set((obj.get("TestImports") or []) + (obj.get("XTestImports") or []))
    return bool(timps & targets) or any(targets & set((packages.get(q) or {}).get("Deps") or []) for q in timps)


def tainted_sources(sa, packages, repo, changed, dir_to_pkg):
    """Packages whose behaviour can change through a changed NON-Go-line input,
    which a coverage profile cannot show: a non-Go, non-test-data file inside
    the package directory (may be //go:embed), or non-test code whose string
    literals name any changed file (it reads it at run time)."""
    out = set()
    for f in changed:
        if f.endswith("_test.go"):
            continue
        pkg = owning_package(f, dir_to_pkg)
        if pkg and not f.endswith(".go") and "/testdata/" not in f and not f.endswith(".md"):
            out.add(pkg)
    readers = [(f, owning_package(f, dir_to_pkg) is None, not f.endswith(".go")) for f in changed if not f.endswith("_test.go")]
    for imp, obj in packages.items():
        files = [os.path.join(obj["Dir"], n) for k in ("GoFiles", "CgoFiles") for n in (obj.get(k) or [])]
        index = sa.literal_index(files)
        if any(sa.references(index, f, outside, by_base) for f, outside, by_base in readers):
            out.add(imp)
    return out


def package_dirs(packages, repo):
    m = {}
    for imp, obj in packages.items():
        rel = os.path.relpath(obj.get("Dir", ""), repo)
        if rel != "." and not rel.startswith(".."):
            m[rel] = imp
    return m


# --------------------------------------------------------------------------
# running one dependent
# --------------------------------------------------------------------------

class Run:
    """Per-invocation state that must be cleaned up: one temp root."""

    def __init__(self, tmpdir=None):
        self.root = tempfile.mkdtemp(prefix="coverage-shadow-", dir=tmpdir)
        self.gotmp = os.path.join(self.root, "gotmp")
        os.makedirs(self.gotmp)
        self._n = 0
        atexit.register(self.cleanup)

    def profile_path(self):
        self._n += 1
        return os.path.join(self.root, f"cover-{self._n}.out")

    def cleanup(self):
        shutil.rmtree(self.root, ignore_errors=True)


def run_go_test(run, go_bin, dependent, coverpkg, test_timeout, kill_after, profile):
    """Run the tests of one dependent. Returns a dict: exit, timed_out,
    no_test_files, build_failed, pass/fail/skip counts, tail (last output
    lines). Never raises on a test failure; the process group is killed on
    timeout."""
    cmd = [go_bin, "test", "-covermode=set", f"-coverpkg={','.join(coverpkg)}", f"-coverprofile={profile}",
           f"-timeout={test_timeout}", "-json", dependent]
    env = dict(os.environ, GOTMPDIR=run.gotmp)
    info = {"exit": None, "timed_out": False, "no_test_files": False, "build_failed": False,
            "pass": 0, "fail": 0, "skip": 0, "skip_reasons": []}
    tail = deque(maxlen=6)
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env, start_new_session=True)

    def reader():
        for raw in proc.stdout:
            raw = raw.rstrip("\n")
            try:
                ev = json.loads(raw)
            except ValueError:
                tail.append(raw[:300])
                continue
            action, out = ev.get("Action"), ev.get("Output", "")
            if action == "output":
                if "[no test files]" in out:
                    info["no_test_files"] = True
                if "[build failed]" in out or "[setup failed]" in out:
                    info["build_failed"] = True
                if out.strip():
                    tail.append(out.strip()[:300])
                    if len(info["skip_reasons"]) < 3 and "--- SKIP" in out:
                        info["skip_reasons"].append(out.strip()[:200])
            elif ev.get("Test") and action in ("pass", "fail", "skip"):
                info[action] += 1

    t = threading.Thread(target=reader, daemon=True)
    t.start()
    try:
        info["exit"] = proc.wait(timeout=kill_after)
    except subprocess.TimeoutExpired:
        info["timed_out"] = True
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except OSError:
            pass
        proc.wait()
        info["exit"] = proc.returncode
    t.join(timeout=10)
    proc.stdout.close()
    info["tail"] = list(tail)
    return info


def parse_duration_s(text):
    total, found = 0.0, False
    for num, unit in re.findall(r"(\d+(?:\.\d+)?)(ms|s|m|h)", text):
        found = True
        total += float(num) * {"ms": 0.001, "s": 1, "m": 60, "h": 3600}[unit]
    return total if found else 600.0


def measure_dependent(run, go_bin, dependent, coverpkg, changes, ignorable_by_file, test_timeout, module=MODULE, grace=120):
    """Decision record fields for one dependent (without the run-level rules)."""
    profile = run.profile_path()
    started = time.time()
    try:
        info = run_go_test(run, go_bin, dependent, coverpkg, test_timeout, parse_duration_s(test_timeout) + grace, profile)
        rec = {"duration_s": round(time.time() - started, 1), "go_exit": info["exit"],
               "tests": {k: info[k] for k in ("pass", "fail", "skip")}}
        if info["skip_reasons"]:
            rec["skip_examples"] = info["skip_reasons"]
        if info["timed_out"]:
            return {**rec, "verdict": "KEEP", "basis": "timeout"}
        if info["no_test_files"]:
            return {**rec, "verdict": "KEEP", "basis": "no-test-files"}
        if info["build_failed"]:
            return {**rec, "verdict": "KEEP", "basis": "build-failed", "tail": info["tail"]}
        if info["exit"] != 0 or info["fail"]:
            return {**rec, "verdict": "KEEP", "basis": "test-failed", "tail": info["tail"]}
        try:
            with open(profile, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            return {**rec, "verdict": "KEEP", "basis": "profile-missing"}
        if not text.startswith("mode:"):
            return {**rec, "verdict": "KEEP", "basis": "profile-missing"}
        per_file = match_all(changes, parse_profile(text, module), ignorable_by_file)
        verdict, basis = verdict_from_match(per_file)
        rec.update(verdict=verdict, basis=basis, files={
            f: {k: to_ranges(v) for k, v in m.items() if v} for f, m in per_file.items()})
        return rec
    finally:
        try:
            os.remove(profile)
        except OSError:
            pass


def apply_run_level_rules(rec, dependent, tainted, spawns, tree_ok):
    """The rules that do not depend on the profile. KEEP always wins over a
    SKIPPABLE from coverage; the coverage verdict is kept as `coverage_verdict`."""
    if rec["verdict"] != "SKIPPABLE":
        return rec
    reason = None
    if not tree_ok:
        reason = "tree-mismatch"
    elif dependent in tainted:
        reason = "non-go-input"
    elif dependent in spawns:
        reason = "spawns-subprocess"
    elif rec.get("tests", {}).get("skip"):
        rec["verdict_if_skips_ignored"] = "SKIPPABLE"
        reason = "tests-skipped"
    if reason:
        rec["coverage_verdict"] = "SKIPPABLE"
        rec["verdict"], rec["basis"] = "KEEP", reason
    return rec


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def git(*args):
    return subprocess.run(["git", *args], capture_output=True, text=True, check=True).stdout


class Out:
    def __init__(self, path):
        self.fh = sys.stdout if path in (None, "-") else open(path, "a", encoding="utf-8")

    def emit(self, rec):
        self.fh.write(json.dumps(rec, sort_keys=True) + "\n")
        self.fh.flush()

    def close(self):
        if self.fh is not sys.stdout:
            self.fh.close()


def lever_a_decision(args):
    if args.decision:
        with open(args.decision, encoding="utf-8") as fh:
            return json.load(fh)
    here = os.path.dirname(os.path.abspath(__file__))
    out = subprocess.run([sys.executable, os.path.join(here, "select-affected.py"), "--base", args.base, "--head", args.head, "--json"],
                         capture_output=True, text=True, check=True).stdout
    return json.loads(out)


def shadow(args, out, run):
    ident = {"pr": args.pr, "base": args.base, "head": args.head, "run_id": os.environ.get("GITHUB_RUN_ID")}
    decision = lever_a_decision(args)
    if decision.get("mode") != "selected":
        out.emit({"type": "skip", **ident, "reason": f"lever-a-mode-{decision.get('mode')}"})
        log(f"lever A mode={decision.get('mode')}: nothing to do")
        return
    seeds = set(decision.get("seeds") or {})
    dependents = sorted(set(decision.get("affected") or []) - seeds)
    if not dependents:
        out.emit({"type": "skip", **ident, "reason": "lever-a-zero-dependents", "seeds": len(seeds)})
        log("lever A selects 0 dependents: nothing to filter")
        return

    repo = os.getcwd()
    head_sha = git("rev-parse", args.head).strip()
    tree_ok = git("rev-parse", "HEAD").strip() == head_sha
    ident["head_sha"] = head_sha
    here = os.path.dirname(os.path.abspath(__file__))
    sa = load_lever_a(os.path.join(here, "select-affected.py"))

    changed = decision.get("changed") or []
    diff_go = git("diff", "-U0", "--no-renames", "--no-color", args.base, args.head, "--", "*.go")
    all_ranges, deleted_files = parse_diff(diff_go)
    packages = sa.load_packages() if sa else {}
    dir_to_pkg = package_dirs(packages, repo)

    changes, coverpkg, ignorable_by_file, generated = {}, set(), {}, []
    for f, rngs in all_ranges.items():
        if f.endswith("_test.go"):
            continue
        pkg = owning_package(f, dir_to_pkg)
        if not pkg:
            continue
        changes[f] = rngs
        coverpkg.add(pkg)
        try:
            with open(f, encoding="utf-8", errors="replace") as fh:
                src = fh.read()
        except OSError:
            src = ""
        ignorable_by_file[f] = ignorable_lines(src)
        if "Code generated" in src[:600] and "DO NOT EDIT" in src[:600]:
            generated.append(f)
    deleted_files = [f for f in deleted_files if not f.endswith("_test.go")]

    tainted_pkgs = set()
    if sa:
        tainted_pkgs = tainted_sources(sa, packages, repo, changed, dir_to_pkg)
        if deleted_files:
            tainted_pkgs |= {owning_package(f, dir_to_pkg) for f in deleted_files} - {None}
    tainted = {d for d in dependents if not sa or reaches(packages.get(d, {}), packages, tainted_pkgs)}
    spawns = {d for d in dependents if "os/exec" in ((packages.get(d) or {}).get("TestImports") or []) + ((packages.get(d) or {}).get("XTestImports") or [])}

    out.emit({"type": "run", "schema": SCHEMA, **ident, "dependents": len(dependents), "coverpkg": sorted(coverpkg),
              "changed_go_files": sorted(changes), "generated_files": generated, "deleted_go_files": deleted_files,
              "lever_a_seeds": len(seeds), "tree_ok": tree_ok})
    log(f"{len(dependents)} lever-A dependents, {len(coverpkg)} changed package(s) under coverage")

    counts, started = {}, time.time()
    todo = dependents[: args.max_dependents] if args.max_dependents else dependents
    for n, dep in enumerate(todo, 1):
        if args.max_seconds and time.time() - started > args.max_seconds:
            out.emit({"type": "decision", **ident, "dependent": dep, "verdict": "KEEP", "basis": "budget-exhausted"})
            counts["KEEP/budget-exhausted"] = counts.get("KEEP/budget-exhausted", 0) + 1
            continue
        log(f"[{n}/{len(todo)}] {dep}")
        if not coverpkg or not sa:
            rec = {"verdict": "KEEP", "basis": "no-go-change" if sa else "lever-a-helpers-unavailable"}
        else:
            rec = apply_run_level_rules(measure_dependent(run, args.go, dep, sorted(coverpkg), changes, ignorable_by_file, args.test_timeout),
                                        dep, tainted, spawns, tree_ok)
        out.emit({"type": "decision", **ident, "dependent": dep, **rec})
        key = f"{rec['verdict']}/{rec['basis']}"
        counts[key] = counts.get(key, 0) + 1
        log(f"  {rec['verdict']} ({rec['basis']})")
    keep = sum(v for k, v in counts.items() if k.startswith("KEEP"))
    skippable = sum(v for k, v in counts.items() if k.startswith("SKIPPABLE"))
    out.emit({"type": "summary", **ident, "dependents": len(dependents), "evaluated": len(todo), "keep": keep,
              "skippable": skippable, "by_basis": counts, "seconds": round(time.time() - started, 1)})
    log(f"done: {keep} KEEP, {skippable} SKIPPABLE of {len(todo)} (logging only; no test was skipped)")


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--head", default="HEAD")
    ap.add_argument("--pr")
    ap.add_argument("--log", default="-")
    ap.add_argument("--decision")
    ap.add_argument("--go", default="go")
    ap.add_argument("--tmpdir")
    ap.add_argument("--test-timeout", default="10m")
    ap.add_argument("--max-dependents", type=int, default=0)
    ap.add_argument("--max-seconds", type=int, default=0)
    ap.add_argument("--strict", action="store_true", help="exit non-zero on an internal error (tests); CI never passes this")
    args = ap.parse_args(argv)

    out, run = Out(args.log), Run(args.tmpdir)

    def die(signum, _frame):  # run the finally blocks: no leaked profile on SIGTERM
        raise SystemExit(128 + signum)

    signal.signal(signal.SIGTERM, die)
    signal.signal(signal.SIGINT, die)
    log(f"shadow mode: logging only, no test is skipped or failed by this script (base={args.base} head={args.head})")
    code = 0
    try:
        shadow(args, out, run)
    except Exception as exc:  # noqa: BLE001 - observation only: an error here must never fail CI
        out.emit({"type": "error", "pr": args.pr, "base": args.base, "head": args.head, "error": f"{type(exc).__name__}: {exc}"})
        log(f"internal error (logged, CI unaffected): {type(exc).__name__}: {exc}")
        code = 1 if args.strict else 0
    finally:
        run.cleanup()
        out.close()
    return code


if __name__ == "__main__":
    sys.exit(main())
