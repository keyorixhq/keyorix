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
  --pg-dsn-map F JSON {package: DSN}: each dependent's tests get their own
                 KEYORIX_TEST_PG_DSN (none when absent), as CI's test legs do
  --declrefs B   a prebuilt scripts/ci/declrefs (default: built from the tree)
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
  Before the verdict, `undetermined` lines are refined (refine_file; --no-refine
  turns it off) with four provable facts, each of which only ever moves a line
  to covered or uncovered, never to ignored:
    unlinked      the file's package is not in this dependent's test binary
                  (checked against `go list` for linux, darwin and windows), so
                  none of its code can run. Never applied to a pure-deletion
                  marker: what was deleted is not in this tree's profile.
    cut-in-function  a pure-deletion marker whose two lines both lie strictly
                  inside one function body: what was removed could only have run
                  if that function ran, so the body's blocks decide (any block
                  with count > 0 = covered). Cuts at the top level, in imports,
                  or touching a `{` / `}` line of the function stay undetermined.
                  Related, in the diff step: a hunk that removed only body-level
                  code and added at least one real line no longer withholds its
                  added comment/blank lines from "ignored" (the real line stands
                  in for the removed code); a hunk that added only comments or
                  removed a top-level declaration still does.
    func-header   a func signature line has no block; it takes the status of
                  its own body (any block with count > 0 = the function ran).
    declaration   a const / type / var line has no block. scripts/ci/declrefs
                  (go/ast) names what it declares and lists every mention of
                  those names in the repo. No relevant mention = nothing can
                  reach it: uncovered. A mention on a covered line = covered. A
                  mention we cannot judge, or only on uncovered lines, = stays
                  undetermined (the strict rule). A const group that uses iota
                  or repeats implicitly is judged as a whole (adding a spec
                  renumbers the rest), and a var whose initialiser can run code
                  (anything but literals and errors.New) is never refined.
  verdict_if_uncovered_refs_ok = SKIPPABLE marks a dependent that would be
  SKIPPABLE if mentions on provably uncovered lines were also ignored: a logged
  what-if, never the verdict.
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

def hunk_removed(text):
    """{path: [removed lines of each hunk, in parse_diff's order]} for the same
    `git diff -U0` text (new-side paths; deleted files are left out)."""
    out, cur, hunk, in_hunk = {}, None, None, False
    for line in text.splitlines():
        if line.startswith("diff --git"):
            cur, hunk, in_hunk = None, None, False
        elif not in_hunk and line.startswith("+++ "):
            target = line[4:].split("\t", 1)[0]
            cur = None if target == "/dev/null" else (target[2:] if target.startswith("b/") else target)
        elif line.startswith("@@") and cur is not None:
            in_hunk = HUNK.match(line) is not None
            hunk = []
            if in_hunk:
                out.setdefault(cur, []).append(hunk)
        elif in_hunk and line.startswith("-"):
            hunk.append(line[1:])
    return out


def inert_removed(line):
    """A removed line that cannot have changed behaviour: blank, a plain
    comment, closing punctuation or a plain import."""
    s = line.strip()
    if s == "" or CLOSERS.match(s):
        return True
    if s.startswith("//"):
        return not DIRECTIVE.match(s)
    return bool(IMPORT_SPEC.match(s)) and not re.match(r"^[_.]\s", s)


def body_level_removed(line):
    """A removed line that sits inside a block: inert, or indented. gofmt puts
    every top-level declaration (func, method, var, const, type, init) at column
    0, so a hunk whose removed lines are all `body_level_removed` took nothing
    out of the package's declarations or method sets, only out of a body (a
    function, or a struct/var group, whose own lines are judged separately)."""
    return inert_removed(line) or line[:1] in (" ", "\t")


def apply_removed(changes, removed):
    """Use what the diff removed. A pure-deletion cut whose removed lines are all
    inert stops being a deletion marker (its neighbours are judged normally).
    A hunk that adds lines but removed real code must not have its added lines
    ignored as comment-only. They are returned in `noignore`
    {path: [(start, end, force)]}: force=True means always withhold the hunk's
    ignorable lines; force=False means only when the hunk added nothing but
    ignorable lines (the code it removed was replaced by a comment), see
    `withheld_lines`. A hunk that removed a top-level declaration (anything not
    `body_level_removed`) is always force. A file whose hunks do not line up with
    parse_diff's keeps its markers and is force throughout."""
    new, noignore = {}, {}
    for f, rngs in changes.items():
        rem = removed.get(f)
        if rem is None or len(rem) != len(rngs):
            new[f] = rngs
            noignore[f] = [(s, e, True) for s, e, d in rngs]
            continue
        out, no = [], []
        for (s, e, d), r in zip(rngs, rem):
            inert = all(inert_removed(x) for x in r)
            out.append((s, e, False) if d and inert else (s, e, d))
            if not d and not inert:
                no.append((s, e, not all(body_level_removed(x) for x in r)))
        new[f], noignore[f] = out, no
    return new, noignore


def withheld_lines(hunks, ignorable):
    """Lines of `hunks` (apply_removed's noignore for one file) that must not be
    ignored: a force hunk entirely; any other hunk only when every line it added
    is ignorable, because then nothing else in the hunk stands in for the code
    it removed. With a real added line the replacement is judged by its own
    block, in the same body, at the same place."""
    out = set()
    for s, e, force in hunks:
        if force or all(ln in ignorable for ln in range(s, e + 1)):
            out.update(range(s, e + 1))
    return out


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


# --------------------------------------------------------------------------
# refining "undetermined": declarations, function headers, unlinked packages
# --------------------------------------------------------------------------

class DeclEval:
    """Decides a changed const/type/var line from where its names are mentioned.

    refs: declrefs' {"<declaring file>#<name>": [{"file","line","test"}]}.
    A mention is judged against ONE dependent's test run:
      irrelevant  cannot run in it: a _test.go file of another package, or a
                  non-test file of a package its test binary does not link
      covered     a profile block holding that line has count > 0
      uncovered   blocks hold it and all have count 0
      unknown     anything else (a test file of the dependent itself, code of
                  a package outside the profile, a line without a block)
    A declaration with a covered mention is covered. With no relevant mention
    it is unreachable from this run: uncovered. With only uncovered mentions it
    stays undetermined (strict, the default); `relaxed` calls it uncovered and
    only feeds the logged what-if verdict_if_uncovered_refs_ok."""

    def __init__(self, refs, owning, closure, dependent, profile):
        self.refs, self.owning, self.closure, self.dependent, self.profile = refs, owning, closure, dependent, profile

    def site_status(self, site):
        pkg = self.owning(site["file"])
        if site.get("test"):
            return "unknown" if pkg == self.dependent else "irrelevant"
        if pkg is None:
            return "unknown"  # another Go module, or no package: do not reason about it
        if self.closure is not None and pkg not in self.closure:
            return "irrelevant"
        hit = [c for s, e, c in self.profile.get(site["file"], []) if s <= site["line"] <= e]
        if hit:
            return "covered" if any(c > 0 for c in hit) else "uncovered"
        return "unknown"

    def verdict(self, decl_file, li, relaxed):
        """(status, reason) with status covered / uncovered / undetermined."""
        sites = []
        for name in li.get("names") or []:
            got = self.refs.get(f"{decl_file}#{name}")
            if got is None:
                return "undetermined", None
            sites += got
        states = [self.site_status(s) for s in sites]
        if "covered" in states:
            return "covered", "decl-referenced-covered"
        live = [s for s in states if s != "irrelevant"]
        if not live:
            return "uncovered", "decl-unreferenced"
        if relaxed and all(s == "uncovered" for s in live):
            return "uncovered", "decl-referenced-only-uncovered"
        return "undetermined", None


def refine_file(path, res, flags, blocks, info, linked, compiled, decl_eval, relaxed=False, legacy=False):
    """Move provable lines out of match_file's `undetermined`.

    flags: expand(ranges) ({line: pure-deletion?}); blocks: the file's profile
    blocks; info: declrefs' {"<line>": {kind, ...}} for the file (None = no
    help); linked: False when the file's package is not in the dependent's test
    binary, None when unknown; compiled: the file is part of the package under
    this GOOS/tags. Returns (res2, notes) where notes = {reason: [lines]}.
    A pure-deletion marker is refined only as cut-in-function (see the module
    docstring): what was deleted is not in this tree's profile, so only the
    enclosing function's status can speak for it. Anything not proven stays
    undetermined."""
    out = {k: list(v) for k, v in res.items()}
    notes, keep = {}, []
    for ln in res["undetermined"]:
        status = reason = None
        if compiled and flags.get(ln) is True and not legacy:
            # A pure-deletion marker. Only a cut strictly inside one function body
            # is refined (declrefs says "funcbody" for the lines of such a body, not
            # for its `{` / `}` lines): what was removed could only have run if
            # that function ran, so the body's blocks decide. Everything else
            # (imports, between declarations, a removed method or var) stays.
            li = (info or {}).get(str(ln))
            if li and li.get("kind") == "funcbody":
                lo, hi = li["body"]
                inside = [c for s, e, c in blocks if s >= lo and e <= hi]
                if inside:
                    status = "covered" if any(c > 0 for c in inside) else "uncovered"
                    reason = "cut-in-function"
        elif compiled and flags.get(ln) is False:
            li = (info or {}).get(str(ln))
            if linked is False:
                status, reason = "uncovered", "unlinked"
            elif li and li.get("kind") == "funcheader":
                lo, hi = li["body"]
                inside = [c for s, e, c in blocks if s >= lo and e <= hi]
                if inside:
                    status = "covered" if any(c > 0 for c in inside) else "uncovered"
                    reason = "func-header"
            elif li and li.get("kind") == "decl" and not li.get("impure") and decl_eval:
                status, reason = decl_eval.verdict(path, li, relaxed)
        if status in ("covered", "uncovered"):
            out[status].append(ln)
            notes.setdefault(reason, []).append(ln)
        else:
            keep.append(ln)
    out["undetermined"] = keep
    out["covered"].sort()
    out["uncovered"].sort()
    return out, notes


def test_closure(variants, dependent):
    """Import paths linked into `dependent`'s test binary, over every package
    listing in `variants` (one per GOOS, so a platform-specific import counts).
    None when there is nothing to reason from."""
    if not variants or not any(dependent in pk for pk in variants):
        return None
    out = {dependent}
    for pk in variants:
        obj = pk.get(dependent)
        if not obj:
            continue
        out |= set(obj.get("Deps") or [])
        for q in (obj.get("TestImports") or []) + (obj.get("XTestImports") or []):
            out.add(q)
            out |= set((pk.get(q) or {}).get("Deps") or [])
    return out


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


def run_go_test(run, go_bin, dependent, coverpkg, test_timeout, kill_after, profile, env_extra=None):
    """Run the tests of one dependent. Returns a dict: exit, timed_out,
    no_test_files, build_failed, pass/fail/skip counts, tail (last output
    lines). Never raises on a test failure; the process group is killed on
    timeout. env_extra overlays the environment (a None value removes the
    variable)."""
    cmd = [go_bin, "test", "-covermode=set", f"-coverpkg={','.join(coverpkg)}", f"-coverprofile={profile}",
           f"-timeout={test_timeout}", "-json", dependent]
    env = dict(os.environ, GOTMPDIR=run.gotmp)
    for k, v in (env_extra or {}).items():
        if v is None:
            env.pop(k, None)
        else:
            env[k] = v
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
                if "panic: test timed out" in out:
                    info["timed_out"] = True  # go test's own -timeout fired: a timeout, not a failing test
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


def measure_dependent(run, go_bin, dependent, coverpkg, changes, ignorable_by_file, test_timeout, module=MODULE, grace=120,
                      refine=None, env_extra=None, legacy_ignorable_by_file=None):
    """Decision record fields for one dependent (without the run-level rules).

    refine(dependent, path, per_file_result, ranges, profile, relaxed) ->
    (result, notes) is the optional undetermined-line refinement (see
    refine_file); without it the verdict is the plain coverage one."""
    profile = run.profile_path()
    started = time.time()
    try:
        info = run_go_test(run, go_bin, dependent, coverpkg, test_timeout, parse_duration_s(test_timeout) + grace, profile, env_extra)
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
        prof = parse_profile(text, module)
        per_file = match_all(changes, prof, ignorable_by_file)
        relaxed_file, refined = None, {}
        if refine:
            relaxed_file = {}
            for f, m in list(per_file.items()):
                per_file[f], notes = refine(dependent, f, m, changes[f], prof, False)
                relaxed_file[f], _ = refine(dependent, f, m, changes[f], prof, True)
                for reason, lines in notes.items():
                    refined.setdefault(reason, {})[f] = to_ranges(lines)
        verdict, basis = verdict_from_match(per_file)
        rec.update(verdict=verdict, basis=basis, files={
            f: {k: to_ranges(v) for k, v in m.items() if v} for f, m in per_file.items()})
        if refined:
            rec["refined"] = refined
        if legacy_ignorable_by_file is not None:
            # the verdict the CI-SELECT-2-2 rules would have given on this same profile
            old = match_all(changes, prof, legacy_ignorable_by_file)
            if refine:
                old = {f: refine(dependent, f, m, changes[f], prof, False, True)[0] for f, m in old.items()}
            rec["legacy"] = dict(zip(("verdict", "basis"), verdict_from_match(old)))
        if relaxed_file and verdict == "KEEP" and basis == "undetermined-lines" and verdict_from_match(relaxed_file)[0] == "SKIPPABLE":
            rec["verdict_if_uncovered_refs_ok"] = "SKIPPABLE"  # what-if only; see DeclEval
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
        if rec.get("verdict_if_uncovered_refs_ok") and (not tree_ok or dependent in tainted or dependent in spawns
                                                        or rec.get("tests", {}).get("skip")):
            del rec["verdict_if_uncovered_refs_ok"]  # the what-if would be KEEP for the same run-level reason
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


def legacy_after_run_level(rec, dependent, tainted, spawns, tree_ok):
    """Apply the same run-level rules to rec["legacy"], so it is comparable with the verdict."""
    old = rec.get("legacy")
    if old and old["verdict"] == "SKIPPABLE":
        got = apply_run_level_rules({"verdict": "SKIPPABLE", "basis": old["basis"], "tests": rec.get("tests", {})},
                                    dependent, tainted, spawns, tree_ok)
        rec["legacy"] = {"verdict": got["verdict"], "basis": got["basis"]}
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


def dsn_env(dsn_map, dependent):
    """env overlay giving `dependent` its own Postgres database (or none)."""
    if dsn_map is None:
        return None
    rel = dependent[len(MODULE) + 1:] if dependent.startswith(MODULE + "/") else dependent
    return {"KEYORIX_TEST_PG_DSN": dsn_map.get(dependent) or dsn_map.get(rel)}


def package_variants(sa, host):
    """`go list` of the module for the host and every other GOOS we ship to,
    so "not linked" means not linked on any of them. None if one fails."""
    out = [host]
    old = os.environ.get("GOOS")
    try:
        have = subprocess.run(["go", "env", "GOOS"], capture_output=True, text=True, check=True).stdout.strip()
        for goos in sorted({"linux", "darwin", "windows"} - {have}):
            os.environ["GOOS"] = goos
            out.append(sa.load_packages())
    except Exception as exc:  # noqa: BLE001 - shadow mode: never raise
        log(f"cannot list packages for every GOOS ({type(exc).__name__}: {exc}): no package is treated as unlinked")
        return None
    finally:
        if old is None:
            os.environ.pop("GOOS", None)
        else:
            os.environ["GOOS"] = old
    return out


def run_declrefs(args, run, repo, here, changes):
    """declrefs' answer for the changed files, or None (then nothing is refined)."""
    binary = args.declrefs
    if not binary:
        binary = os.path.join(run.root, "declrefs")
        built = subprocess.run([args.go, "build", "-o", binary, os.path.join(here, "declrefs")], capture_output=True, text=True)
        if built.returncode != 0:
            log(f"cannot build declrefs ({built.stderr.strip()[:200]}): declarations stay undetermined")
            return None
    req = {"root": repo, "module": MODULE, "files": {f: sorted(expand(r)) for f, r in changes.items()}}
    try:
        res = subprocess.run([binary], input=json.dumps(req), capture_output=True, text=True, timeout=600)
        if res.returncode != 0:
            raise RuntimeError(res.stderr.strip()[:200])
        return json.loads(res.stdout)
    except Exception as exc:  # noqa: BLE001
        log(f"declrefs failed ({type(exc).__name__}: {exc}): declarations stay undetermined")
        return None


def mention_packages(refs, owning):
    """Packages holding a non-test mention of any declaration in declrefs' `refs`."""
    return {p for sites in refs.values() for site in sites if not site.get("test") for p in [owning(site["file"])] if p}


def build_refiner(args, run, sa, packages, repo, changes, dir_to_pkg, here, generated=()):
    """The `refine` callable of measure_dependent for this run."""
    variants = package_variants(sa, packages)
    answer = run_declrefs(args, run, repo, here, changes)
    info = (answer or {}).get("lines") or {}
    refs = (answer or {}).get("refs") or {}
    if answer and answer.get("parse_errors"):
        log(f"declrefs could not parse {len(answer['parse_errors'])} file(s): references cannot be trusted, declarations stay undetermined")
        refs = {}
    file_pkg = {f: owning_package(f, dir_to_pkg) for f in changes}
    compiled = {}
    for f, pkg in file_pkg.items():
        obj = packages.get(pkg) or {}
        compiled[f] = os.path.basename(f) in set(obj.get("GoFiles") or []) | set(obj.get("CgoFiles") or [])
    closures = {}

    def owning(path):
        return owning_package(path, dir_to_pkg)

    def refine(dep, f, res, ranges, profile, relaxed, legacy=False):
        if dep not in closures:
            closures[dep] = test_closure(variants, dep)
        closure = closures[dep]
        linked = None if closure is None else file_pkg[f] in closure
        ev = DeclEval(refs, owning, closure, dep, profile)
        # generated code (accessors, registries) gets no static reasoning: it is treated like a
        # file that is not compiled here, so its undetermined lines stay undetermined
        return refine_file(f, res, expand(ranges), profile.get(f, []), info.get(f), linked,
                           compiled[f] and f not in generated, ev, relaxed, legacy)

    # Packages with a non-test mention of a changed declaration: their code must be in the profile,
    # otherwise a mention there is "unknown" and the declaration can never be judged.
    refine.mention_pkgs = mention_packages(refs, owning)
    return refine


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

    all_ranges, noignore = apply_removed(all_ranges, hunk_removed(diff_go))
    changes, coverpkg, ignorable_by_file, generated, legacy_ignorable = {}, set(), {}, [], {}
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
        ign = ignorable_lines(src)
        ignorable_by_file[f] = ign - withheld_lines(noignore.get(f, []), ign)
        legacy_ignorable[f] = ign - withheld_lines([(a, b, True) for a, b, _ in noignore.get(f, [])], ign)
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

    refine = None
    if sa and coverpkg and not args.no_refine:
        refine = build_refiner(args, run, sa, packages, repo, changes, dir_to_pkg, here, set(generated))
    extra_cover = sorted(getattr(refine, "mention_pkgs", set()) - coverpkg) if refine else []
    coverpkg |= set(extra_cover)
    dsn_map = None
    if args.pg_dsn_map:
        with open(args.pg_dsn_map, encoding="utf-8") as fh:
            dsn_map = json.load(fh)

    out.emit({"type": "run", "schema": SCHEMA, **ident, "dependents": len(dependents), "coverpkg": sorted(coverpkg),
              "changed_go_files": sorted(changes), "coverpkg_extra": extra_cover, "generated_files": generated, "deleted_go_files": deleted_files,
              "lever_a_seeds": len(seeds), "tree_ok": tree_ok, "refine": refine is not None,
              "pg_dsn_per_package": dsn_map is not None})
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
            rec = apply_run_level_rules(measure_dependent(run, args.go, dep, sorted(coverpkg), changes, ignorable_by_file, args.test_timeout,
                                                          refine=refine, env_extra=dsn_env(dsn_map, dep),
                                                          legacy_ignorable_by_file=legacy_ignorable),
                                        dep, tainted, spawns, tree_ok)
            legacy_after_run_level(rec, dep, tainted, spawns, tree_ok)
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
    ap.add_argument("--pg-dsn-map", help="JSON {dependent import path or module-relative path: Postgres DSN}; each dependent's tests get "
                    "KEYORIX_TEST_PG_DSN from it, or none when absent (never a DSN shared with another package)")
    ap.add_argument("--declrefs", help="prebuilt scripts/ci/declrefs binary (default: built from the checkout)")
    ap.add_argument("--no-refine", action="store_true", help="plain coverage verdicts: no unlinked/func-header/declaration refinement")
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
