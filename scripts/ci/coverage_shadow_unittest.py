"""Unit tests for scripts/ci/coverage-shadow.py (CI-SELECT-2, shadow mode).

Run by scripts/ci/coverage_shadow_test.go (or: python3 -m unittest
scripts/ci/coverage_shadow_unittest.py from the repo root).

The matcher (changed line ranges vs coverage-profile blocks) is the part where
a bug means a false SKIPPABLE, so it is pinned three ways: hand cases for each
edge (partial-line hunk, multi-file diff, generated/vendored paths, deletions,
overlapping blocks), a randomized cross-check against a brute-force per-line
reference, and the cleanup contract (no temp file on any exit path).
"""
import importlib.util
import json
import os
import random
import stat
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("coverage_shadow", os.path.join(HERE, "coverage-shadow.py"))
cs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cs)

MOD = cs.MODULE


class ParseDiff(unittest.TestCase):
    def test_multi_file_partial_line_and_default_count(self):
        diff = (
            "diff --git a/a/x.go b/a/x.go\n--- a/a/x.go\n+++ b/a/x.go\n"
            "@@ -10,0 +11,3 @@ func f() {\n+a\n+b\n+c\n"
            "@@ -20 +23 @@\n-old\n+new\n"
            "diff --git a/b/y.go b/b/y.go\n--- a/b/y.go\n+++ b/b/y.go\n"
            "@@ -1,2 +1,2 @@\n-a\n-b\n+c\n+d\n"
        )
        ranges, deleted = cs.parse_diff(diff)
        self.assertEqual(ranges["a/x.go"], [(11, 13, False), (23, 23, False)])
        self.assertEqual(ranges["b/y.go"], [(1, 2, False)])
        self.assertEqual(deleted, [])

    def test_pure_deletion_is_flagged_and_covers_both_neighbours(self):
        ranges, _ = cs.parse_diff("--- a/a/x.go\n+++ b/a/x.go\n@@ -5,2 +4,0 @@\n-a\n-b\n")
        self.assertEqual(ranges["a/x.go"], [(4, 5, True)])

    def test_deletion_at_top_of_file_clamps_to_line_one(self):
        ranges, _ = cs.parse_diff("--- a/a/x.go\n+++ b/a/x.go\n@@ -1,2 +0,0 @@\n-a\n-b\n")
        self.assertEqual(ranges["a/x.go"], [(1, 1, True)])

    def test_new_file_and_deleted_file(self):
        diff = (
            "--- /dev/null\n+++ b/a/new.go\n@@ -0,0 +1,4 @@\n+x\n"
            "--- a/a/gone.go\n+++ /dev/null\n@@ -1,3 +0,0 @@\n-x\n"
        )
        ranges, deleted = cs.parse_diff(diff)
        self.assertEqual(ranges, {"a/new.go": [(1, 4, False)]})
        self.assertEqual(deleted, ["a/gone.go"])

    def test_hunk_header_with_section_text_and_no_hunks(self):
        ranges, _ = cs.parse_diff("--- a/m.go\n+++ b/m.go\n")
        self.assertEqual(ranges, {})


class ParseProfile(unittest.TestCase):
    def test_strips_module_and_keeps_foreign_paths(self):
        prof = (
            "mode: set\n"
            f"{MOD}/internal/a/a.go:10.2,12.3 2 1\n"
            f"{MOD}/internal/a/a.go:14.2,15.3 1 0\n"
            "golang.org/x/other/o.go:1.1,2.2 1 1\n"
            "garbage line\n"
        )
        got = cs.parse_profile(prof)
        self.assertEqual(got["internal/a/a.go"], [(10, 12, 1), (14, 15, 0)])
        self.assertEqual(got["golang.org/x/other/o.go"], [(1, 2, 1)])

    def test_count_and_atomic_style_counts(self):
        got = cs.parse_profile(f"mode: atomic\n{MOD}/p/p.go:3.1,4.2 1 57\n")
        self.assertEqual(got["p/p.go"], [(3, 4, 57)])


class MatchFile(unittest.TestCase):
    def m(self, ranges, blocks, ign=()):
        return cs.match_file(ranges, blocks, set(ign))

    def test_covered_uncovered_split(self):
        r = self.m([(10, 14, False)], [(10, 11, 3), (13, 14, 0)])
        self.assertEqual((r["covered"], r["uncovered"]), ([10, 11], [13, 14]))
        self.assertEqual(r["undetermined"], [12])

    def test_partial_line_hunk_uses_whole_line(self):
        # a one-character edit on line 7 inside a block that ends on line 7
        r = self.m([(7, 7, False)], [(5, 7, 1)])
        self.assertEqual(r["covered"], [7])

    def test_overlapping_blocks_on_one_line_any_covered_wins(self):
        # `if x { return }` on one line: outer block count 0, inner count 5
        r = self.m([(9, 9, False)], [(9, 9, 0), (9, 9, 5)])
        self.assertEqual(r["covered"], [9])
        r = self.m([(9, 9, False)], [(9, 9, 5), (9, 9, 0)])
        self.assertEqual(r["covered"], [9])

    def test_non_executable_line_is_undetermined_not_skippable(self):
        r = self.m([(3, 3, False)], [(10, 12, 0)])  # a const; no block near it
        self.assertEqual(r["undetermined"], [3])

    def test_ignorable_line_without_block_is_ignored(self):
        r = self.m([(3, 4, False)], [], ign={3, 4})
        self.assertEqual(r["ignored"], [3, 4])

    def test_block_wins_over_ignorable(self):
        # a `}` line (ignorable) that sits inside an uncovered block is uncovered
        r = self.m([(6, 6, False)], [(4, 6, 0)], ign={6})
        self.assertEqual(r["uncovered"], [6])

    def test_deletion_lines_are_never_ignored(self):
        r = self.m([(4, 5, True)], [], ign={4, 5})
        self.assertEqual(r["undetermined"], [4, 5])
        r = self.m([(4, 5, True)], [(1, 4, 7)], ign={5})
        self.assertEqual((r["covered"], r["undetermined"]), ([4], [5]))

    def test_added_line_beats_deletion_flag_on_overlap(self):
        r = self.m([(4, 5, True), (5, 5, False)], [], ign={4, 5})
        self.assertEqual((r["ignored"], r["undetermined"]), ([5], [4]))

    def test_file_absent_from_profile_build_tag_case(self):
        r = self.m([(1, 3, False)], [])
        self.assertEqual(r["undetermined"], [1, 2, 3])

    def test_multi_file_isolated(self):
        changes = {"a/a.go": [(1, 1, False)], "b/b.go": [(1, 1, False)]}
        profile = {"a/a.go": [(1, 1, 1)], "b/b.go": [(1, 1, 0)]}
        out = cs.match_all(changes, profile, {})
        self.assertEqual(out["a/a.go"]["covered"], [1])
        self.assertEqual(out["b/b.go"]["uncovered"], [1])

    def test_vendored_or_foreign_profile_path_does_not_match_repo_file(self):
        profile = cs.parse_profile(f"mode: set\nvendor/x/x.go:1.1,2.2 1 1\n")
        out = cs.match_all({"internal/x/x.go": [(1, 2, False)]}, profile, {})
        self.assertEqual(out["internal/x/x.go"]["undetermined"], [1, 2])

    def test_generated_file_is_measured_like_any_other(self):
        profile = cs.parse_profile(f"mode: set\n{MOD}/server/proto/pb/x.pb.go:100.1,110.2 5 1\n")
        out = cs.match_all({"server/proto/pb/x.pb.go": [(105, 105, False)]}, profile, {})
        self.assertEqual(out["server/proto/pb/x.pb.go"]["covered"], [105])

    def test_randomized_against_per_line_reference(self):
        rng = random.Random(20261027)
        for _ in range(400):
            blocks = []
            for _ in range(rng.randint(0, 8)):
                s = rng.randint(1, 40)
                blocks.append((s, s + rng.randint(0, 6), rng.choice([0, 0, 1, 9])))
            ranges = []
            for _ in range(rng.randint(1, 4)):
                s = rng.randint(1, 45)
                ranges.append((s, s + rng.randint(0, 5), rng.random() < 0.25))
            ign = {n for n in range(1, 50) if rng.random() < 0.3}
            got = cs.match_file(ranges, blocks, ign)
            # reference: expand everything per line, no bisect
            added, deleted = set(), set()
            for s, e, d in ranges:
                (deleted if d else added).update(range(s, e + 1))
            want = {"covered": [], "uncovered": [], "undetermined": [], "ignored": []}
            for ln in sorted(added | deleted):
                inside = [c for s, e, c in blocks if s <= ln <= e]
                if any(c > 0 for c in inside):
                    want["covered"].append(ln)
                elif inside:
                    want["uncovered"].append(ln)
                elif ln in added and ln in ign:
                    want["ignored"].append(ln)
                else:
                    want["undetermined"].append(ln)
            self.assertEqual(got, want, (ranges, blocks, sorted(ign)))


class Verdict(unittest.TestCase):
    def v(self, **kw):
        base = {"covered": [], "uncovered": [], "undetermined": [], "ignored": []}
        base.update(kw)
        return cs.verdict_from_match({"f.go": base})

    def test_each_case(self):
        self.assertEqual(self.v(covered=[1], uncovered=[2], undetermined=[3]), ("KEEP", "covered"))
        self.assertEqual(self.v(uncovered=[2], undetermined=[3]), ("KEEP", "undetermined-lines"))
        self.assertEqual(self.v(uncovered=[2], ignored=[4]), ("SKIPPABLE", "uncovered"))
        self.assertEqual(self.v(ignored=[4]), ("SKIPPABLE", "comment-only"))
        self.assertEqual(self.v(), ("KEEP", "no-go-change"))
        self.assertEqual(cs.verdict_from_match({}), ("KEEP", "no-go-change"))

    def test_one_covered_file_keeps_even_if_others_uncovered(self):
        a = {"covered": [], "uncovered": [1], "undetermined": [], "ignored": []}
        b = {"covered": [5], "uncovered": [], "undetermined": [], "ignored": []}
        self.assertEqual(cs.verdict_from_match({"a.go": a, "b.go": b}), ("KEEP", "covered"))


class Ignorable(unittest.TestCase):
    def ign(self, src):
        return cs.ignorable_lines(src)

    def test_comments_blank_and_closers(self):
        src = "package p\n\n// doc\nfunc f() {\n\tx()\n}\n/* a\nb */\nvar v = 1\n"
        self.assertEqual(sorted(self.ign(src)), [1, 2, 3, 6, 7, 8])

    def test_comment_markers_inside_strings_are_code(self):
        src = 'package p\nvar a = "// not a comment"\nvar b = "/* nope"\nvar c = 1\n'
        self.assertEqual(sorted(self.ign(src)), [1])

    def test_raw_string_lines_are_code(self):
        src = "package p\nvar q = `\n// inside raw\n\n`\n"
        self.assertEqual(sorted(self.ign(src)), [1])

    def test_directives_are_not_ignorable(self):
        src = "//go:build linux\n\npackage p\n//go:embed x.txt\nvar s string\n// plain\n"
        self.assertEqual(sorted(self.ign(src)), [2, 3, 6])

    def test_imports_plain_vs_side_effect(self):
        src = 'package p\n\nimport (\n\t"fmt"\n\tf2 "os"\n\t_ "embed"\n\t. "strings"\n)\n\nimport "sort"\nimport _ "net/http/pprof"\n'
        self.assertEqual(sorted(self.ign(src)), [1, 2, 3, 4, 5, 8, 9, 10])

    def test_cgo_file_has_no_ignorable_lines(self):
        src = 'package p\n/*\n#include <x.h>\n*/\nimport "C"\n'
        self.assertEqual(self.ign(src), set())


class LeverAGlue(unittest.TestCase):
    def test_loads_real_select_affected(self):
        sa = cs.load_lever_a(os.path.join(HERE, "select-affected.py"))
        self.assertIsNotNone(sa, "select-affected.py helpers moved: coverage-shadow keeps every dependent until it is updated")

    def test_missing_lever_a_returns_none(self):
        self.assertIsNone(cs.load_lever_a("/nonexistent/select-affected.py"))

    def test_reaches_follows_lever_a_rule(self):
        pk = {"d": {"Deps": ["x"]}, "e": {"TestImports": ["h"]}, "h": {"Deps": ["x"]}, "f": {}}
        t = {"x"}
        self.assertTrue(cs.reaches(pk["d"], pk, t))
        self.assertTrue(cs.reaches(pk["e"], pk, t))  # one hop through a test import's Deps
        self.assertFalse(cs.reaches(pk["f"], pk, t))

    def test_owning_package_skips_other_modules(self):
        d = {"internal/a": "pkg/a"}
        self.assertEqual(cs.owning_package("internal/a/sub/x.go", d), "pkg/a")
        self.assertIsNone(cs.owning_package("cli/internal/a/x.go", d))

    def test_run_level_rules_only_ever_downgrade_to_keep(self):
        def rec(**kw):
            return {"verdict": "SKIPPABLE", "basis": "uncovered", "tests": {"skip": 0}, **kw}

        r = cs.apply_run_level_rules(rec(), "d", set(), set(), True)
        self.assertEqual(r["verdict"], "SKIPPABLE")
        for name, args, basis in (
            ("tree", ("d", set(), set(), False), "tree-mismatch"),
            ("taint", ("d", {"d"}, set(), True), "non-go-input"),
            ("exec", ("d", set(), {"d"}, True), "spawns-subprocess"),
        ):
            r = cs.apply_run_level_rules(rec(), *args)
            self.assertEqual((r["verdict"], r["basis"], r["coverage_verdict"]), ("KEEP", basis, "SKIPPABLE"), name)
        r = cs.apply_run_level_rules(rec(tests={"skip": 2}), "d", set(), set(), True)
        self.assertEqual((r["verdict"], r["basis"], r["verdict_if_skips_ignored"]), ("KEEP", "tests-skipped", "SKIPPABLE"))
        r = cs.apply_run_level_rules({"verdict": "KEEP", "basis": "covered"}, "d", {"d"}, set(), False)
        self.assertEqual(r, {"verdict": "KEEP", "basis": "covered"})


DECLS_GO = """package pkg

const unusedLimit = 3

const onlyInUncovered = 4

const inCovered = 5

func Covered() int {
\treturn inCovered
}

func Uncovered() int {
\treturn onlyInUncovered
}

type neverUsed struct{ n int }

type holder struct{ n int }

func (h holder) Header(
\ta int,
) int {
\treturn a
}

var sentinel = errors.New("x")

var computed = compute()

func compute() int {
\treturn 1
}

const (
\tmodeA = iota
\tmodeB
\tmodeC
)

func UsesModeC() int {
\treturn modeC
}
"""
# Profile of a run in which Covered ran and Uncovered, Header, compute and UsesModeC did not.
DECLS_BLOCKS = [(10, 10, 1), (14, 14, 0), (24, 24, 0), (32, 32, 0), (42, 42, 0)]
DECLS_FILE = "pkg/decls.go"


class RemovedLines(unittest.TestCase):
    DIFF = (
        "diff --git a/p/a.go b/p/a.go\n--- a/p/a.go\n+++ b/p/a.go\n"
        "@@ -5 +4,0 @@\n-\t\"slices\"\n"          # cut: a plain import removed
        "@@ -20,2 +18,0 @@\n-\tx := f()\n-\treturn x\n"  # cut: real code removed
        "@@ -30 +26 @@\n-\tx := f()\n+\t// x := f()\n"  # code replaced by a comment
        "@@ -40 +36 @@\n-// old note\n+// new note\n"
    )

    def test_inert_cut_stops_being_a_deletion_marker_and_real_code_stays(self):
        ranges, _ = cs.parse_diff(self.DIFF)
        new, noignore = cs.apply_removed(ranges, cs.hunk_removed(self.DIFF))
        got = new["p/a.go"]
        self.assertEqual([d for _, _, d in got], [False, True, False, False])
        # only the hunk that replaced body code; it removed nothing top-level, so not forced
        self.assertEqual(noignore["p/a.go"], [(26, 26, False)])
        self.assertEqual(cs.withheld_lines(noignore["p/a.go"], {26}), {26})  # a comment-only replacement is withheld

    def test_misaligned_hunks_keep_every_marker_and_forbid_ignoring(self):
        new, noignore = cs.apply_removed({"p/a.go": [(1, 2, True)]}, {})
        self.assertEqual(new["p/a.go"], [(1, 2, True)])
        self.assertEqual(cs.withheld_lines(noignore["p/a.go"], {1, 2}), {1, 2})

    def diff_of(self, removed, added, start=10):
        body = "".join(f"-{x}\n" for x in removed) + "".join(f"+{x}\n" for x in added)
        d = f"diff --git a/p/a.go b/p/a.go\n--- a/p/a.go\n+++ b/p/a.go\n@@ -{start},{len(removed)} +{start},{len(added)} @@\n{body}"
        ranges, _ = cs.parse_diff(d)
        return cs.apply_removed(ranges, cs.hunk_removed(d))[1]["p/a.go"]

    def test_comment_next_to_replacement_code_is_not_withheld(self):
        hunks = self.diff_of(["\treturn nil, fmt.Errorf(\"x\")"], ["\t// why", "\t// why 2", "\treturn nil, ErrX"])
        self.assertEqual(hunks, [(10, 12, False)])
        # lines 10, 11 are comments; 12 is code, so the hunk added real code: nothing withheld
        self.assertEqual(cs.withheld_lines(hunks, {10, 11}), set())

    def test_comment_only_replacement_is_still_withheld(self):
        hunks = self.diff_of(["\tx := f()"], ["\t// x := f()", "\t// y"])
        self.assertEqual(cs.withheld_lines(hunks, {10, 11}), {10, 11})

    def test_removed_top_level_declaration_always_withholds(self):
        # a deleted method changes the method set (interface satisfaction, reflection)
        # even if the hunk also adds code: never trade it for a nearby real line
        for gone in ("func (h holder) Close() error {", "func init() {", "var registry = build()", "type T struct{}", "const K = 1"):
            hunks = self.diff_of([gone, "\treturn nil", "}"], ["\t// replaced", "\tx := 1"])
            self.assertEqual(hunks, [(10, 11, True)], gone)
            self.assertEqual(cs.withheld_lines(hunks, {10}), {10, 11}, gone)

    def test_body_level_removed(self):
        for line in ("\tx := 1", "    y()", "\t}", "", "// c"):
            self.assertTrue(cs.body_level_removed(line), repr(line))
        for line in ("func f() {", "func (t T) M() {", "var a = 1", "type T int", "init()"):
            self.assertFalse(cs.body_level_removed(line), repr(line))

    def test_inert_removed_lines(self):
        for line in ("", "  ", "\t}", "// note", '\t"slices"', '\talias "x/y"'):
            self.assertTrue(cs.inert_removed(line), repr(line))
        for line in ("\tx := 1", "//go:build linux", '\t_ "x/y"', "const A = 1", "/* c */"):
            self.assertFalse(cs.inert_removed(line), repr(line))


class DeclarationRefinement(unittest.TestCase):
    """Real Go source through the real scripts/ci/declrefs helper (go/ast), then
    the same matcher + refinement the shadow runs. Profile blocks are written by
    hand to describe one dependent's run."""

    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.mkdtemp(prefix="cs-declrefs-")
        cls.binary = os.path.join(cls.work, "declrefs")
        import subprocess
        built = subprocess.run(["go", "build", "-o", cls.binary, os.path.join(HERE, "declrefs")], cwd=HERE, capture_output=True, text=True)
        if built.returncode != 0:
            raise unittest.SkipTest("cannot build declrefs: " + built.stderr[:200])

    @classmethod
    def tearDownClass(cls):
        __import__("shutil").rmtree(cls.work, ignore_errors=True)

    def classify(self, lines, tree=None, blocks=None, profile_extra=None, dependent=f"{MOD}/dep", closure=None,
                 relaxed=False, deletion=(), path=DECLS_FILE, compiled=True):
        import subprocess
        tree = dict(tree or {})
        tree.setdefault(DECLS_FILE, DECLS_GO)
        root = tempfile.mkdtemp(prefix="tree-", dir=self.work)
        for name, body in tree.items():
            os.makedirs(os.path.dirname(os.path.join(root, name)), exist_ok=True)
            with open(os.path.join(root, name), "w") as fh:
                fh.write(body)
        req = {"root": root, "module": MOD, "files": {path: sorted(lines)}}
        ans = json.loads(subprocess.run([self.binary], input=json.dumps(req), capture_output=True, text=True, check=True).stdout)
        dir_to_pkg = {"pkg": f"{MOD}/pkg", "pkg2": f"{MOD}/pkg2", "dep": dependent}
        profile = {path: DECLS_BLOCKS if blocks is None else blocks, **(profile_extra or {})}
        ranges = [(ln, ln, ln in deletion) for ln in sorted(lines)]
        res = cs.match_file(ranges, profile[path], cs.ignorable_lines(tree[path]))
        ev = cs.DeclEval(ans["refs"], lambda p: cs.owning_package(p, dir_to_pkg), closure, dependent, profile)
        linked = None if closure is None else f"{MOD}/pkg" in closure
        res2, notes = cs.refine_file(path, res, cs.expand(ranges), profile[path], ans["lines"].get(path), linked, compiled, ev, relaxed)
        return res2, notes, cs.verdict_from_match({path: res2})

    LINKED = {f"{MOD}/pkg", f"{MOD}/dep"}

    def test_unused_const_is_skippable_eligible(self):
        res, notes, verdict = self.classify([3], closure=self.LINKED)
        self.assertEqual(res["uncovered"], [3])
        self.assertEqual(notes, {"decl-unreferenced": [3]})
        self.assertEqual(verdict, ("SKIPPABLE", "uncovered"))

    def test_const_used_only_in_an_uncovered_function_stays_undetermined(self):
        res, notes, verdict = self.classify([5], closure=self.LINKED)
        self.assertEqual((res["undetermined"], notes), ([5], {}))
        self.assertEqual(verdict, ("KEEP", "undetermined-lines"))

    def test_the_relaxed_what_if_calls_that_const_uncovered(self):
        res, notes, verdict = self.classify([5], closure=self.LINKED, relaxed=True)
        self.assertEqual(notes, {"decl-referenced-only-uncovered": [5]})
        self.assertEqual(verdict, ("SKIPPABLE", "uncovered"))

    def test_const_used_in_a_covered_function_is_covered_and_kept(self):
        res, notes, verdict = self.classify([7], closure=self.LINKED)
        self.assertEqual((res["covered"], notes), ([7], {"decl-referenced-covered": [7]}))
        self.assertEqual(verdict, ("KEEP", "covered"))
        self.assertEqual(self.classify([7], closure=self.LINKED, relaxed=True)[2], ("KEEP", "covered"))

    def test_unreferenced_type_is_unreachable_but_a_type_named_in_a_signature_is_not_proven(self):
        self.assertEqual(self.classify([17], closure=self.LINKED)[2], ("SKIPPABLE", "uncovered"))
        # `holder` appears in a method header, a line with no block of its own: unknown
        self.assertEqual(self.classify([19], closure=self.LINKED)[0]["undetermined"], [19])

    def test_function_header_follows_its_body(self):
        res, notes, verdict = self.classify([9, 13, 21, 22, 23], closure=self.LINKED)
        self.assertEqual(res["covered"], [9])  # `func Covered() int {`: its body ran
        self.assertEqual(res["uncovered"], [13, 21, 22, 23])
        self.assertEqual(notes["func-header"], [9, 13, 21, 22, 23])
        # a multi-line signature belongs to the same function
        self.assertEqual(self.classify([21, 22, 23], closure=self.LINKED)[1].get("func-header"), [21, 22, 23])

    def test_covered_function_header_keeps(self):
        self.assertEqual(self.classify([9], closure=self.LINKED)[2], ("KEEP", "covered"))
        self.assertEqual(self.classify([13], closure=self.LINKED)[2], ("SKIPPABLE", "uncovered"))

    def test_var_with_init_effects_is_never_refined(self):
        self.assertEqual(self.classify([29], closure=self.LINKED)[0]["undetermined"], [29])  # var computed = compute()
        self.assertEqual(self.classify([27], closure=self.LINKED)[2], ("SKIPPABLE", "uncovered"))  # var sentinel = errors.New

    def test_iota_group_judged_as_a_whole(self):
        # editing modeB (line 37) renumbers modeC, which UsesModeC (uncovered) reads: strict keeps it
        self.assertEqual(self.classify([37], closure=self.LINKED)[0]["undetermined"], [37])
        self.assertEqual(self.classify([37], closure=self.LINKED, relaxed=True)[2], ("SKIPPABLE", "uncovered"))
        # the same edit when UsesModeC ran: covered
        blocks = DECLS_BLOCKS[:-1] + [(42, 42, 1)]
        self.assertEqual(self.classify([37], closure=self.LINKED, blocks=blocks)[2], ("KEEP", "covered"))

    def test_package_not_in_the_test_binary_is_never_executed(self):
        res, notes, verdict = self.classify([3, 5, 7, 17, 29], closure={f"{MOD}/dep"}, blocks=[])
        self.assertEqual((res["uncovered"], res["undetermined"]), ([3, 5, 7, 17, 29], []))
        self.assertEqual(notes, {"unlinked": [3, 5, 7, 17, 29]})
        self.assertEqual(verdict, ("SKIPPABLE", "uncovered"))

    def test_pure_deletion_marker_is_never_refined_even_unlinked(self):
        res, _, verdict = self.classify([3, 4], closure={f"{MOD}/dep"}, blocks=[], deletion=(3, 4))
        self.assertEqual(res["undetermined"], [3, 4])
        self.assertEqual(verdict, ("KEEP", "undetermined-lines"))
        self.assertEqual(self.classify([3], closure=self.LINKED, deletion=(3,))[0]["undetermined"], [3])

    # --- cut-in-function: a pure deletion strictly inside one function body ---
    # Marker lines that already sit inside a profile block are classified by that block;
    # the lines this refinement is for are the ones between blocks (the blank line after
    # an `if` closes), which have no block of their own.
    BODY_GO = (
        "package pkg\n\n"                                                                 # 1-2
        "func Ran() int {\n\ta := 1\n\tif a > 0 {\n\t\ta++\n\t}\n\n\treturn a\n}\n\n"     # 3-11
        "func NotRan() int {\n\ta := 1\n\tif a > 0 {\n\t\ta++\n\t}\n\n\treturn a\n}\n\n"  # 12-20
        "type holder struct{}\n\n"                                                        # 21-22
        "func (holder) Close() error {\n\tif false {\n\t\treturn nil\n\t}\n\n\treturn nil\n}\n"  # 23-29
    )
    BODY_BLOCKS = [(4, 5, 1), (5, 7, 1), (9, 9, 1),        # Ran ran
                   (13, 14, 0), (14, 16, 0), (18, 18, 0),  # NotRan did not
                   (24, 24, 0), (24, 26, 0), (28, 28, 0)]  # Close did not

    def cut(self, lines, blocks=None, **kw):
        return self.classify(lines, tree={DECLS_FILE: self.BODY_GO}, blocks=self.BODY_BLOCKS if blocks is None else blocks,
                             closure=self.LINKED, deletion=lines, **kw)

    def test_legacy_verdict_is_the_old_rules_on_the_same_profile(self):
        # a cut with no block of its own: old rules KEEP (undetermined), new rules SKIPPABLE
        ranges = [(16, 17, True)]
        prof = {DECLS_FILE: self.BODY_BLOCKS}
        old = cs.match_file(ranges, self.BODY_BLOCKS, cs.ignorable_lines(self.BODY_GO))
        self.assertEqual(cs.verdict_from_match({DECLS_FILE: old}), ("KEEP", "undetermined-lines"))
        self.assertEqual(self.cut([16, 17])[2], ("SKIPPABLE", "uncovered"))
        # run-level rules demote the logged legacy verdict exactly like the real one
        rec = {"verdict": "SKIPPABLE", "basis": "uncovered", "tests": {"skip": 1}, "legacy": {"verdict": "SKIPPABLE", "basis": "uncovered"}}
        cs.apply_run_level_rules(rec, "d", set(), set(), True)
        cs.legacy_after_run_level(rec, "d", set(), set(), True)
        self.assertEqual((rec["verdict"], rec["legacy"]["verdict"], rec["legacy"]["basis"]), ("KEEP", "KEEP", "tests-skipped"))

    def test_cut_inside_a_function_that_ran_is_covered(self):
        res, notes, verdict = self.cut([7, 8])
        self.assertEqual((res["covered"], notes, verdict), ([7, 8], {"cut-in-function": [8]}, ("KEEP", "covered")))

    def test_cut_inside_a_function_that_never_ran_is_uncovered(self):
        res, notes, verdict = self.cut([16, 17])
        self.assertEqual((res["uncovered"], notes, verdict), ([16, 17], {"cut-in-function": [17]}, ("SKIPPABLE", "uncovered")))

    def test_cut_touching_the_function_braces_or_between_declarations_stays(self):
        # (9, 10): the `}` of Ran; (10, 11): `}` and the blank after the function;
        # (2, 3): the blank above a header and the header itself; (19, 20): NotRan's `}`
        for lines in ([10], [10, 11], [2, 3], [3], [19], [19, 20], [11, 12], [20, 21]):
            res, notes, verdict = self.cut(lines)
            self.assertTrue(res["undetermined"], lines)
            self.assertEqual(notes, {}, lines)

    def test_cut_next_to_a_removed_method_is_not_attributed_to_a_neighbour(self):
        # a method deleted after NotRan: the cut is on the blank after its `}` and the
        # next declaration, neither strictly inside a body
        res, _, verdict = self.cut([20, 21])
        self.assertEqual((res["undetermined"], verdict), ([20, 21], ("KEEP", "undetermined-lines")))

    def test_cut_in_a_function_without_profile_blocks_stays(self):
        res, _, verdict = self.cut([17], blocks=[])
        self.assertEqual((res["undetermined"], verdict), ([17], ("KEEP", "undetermined-lines")))

    def test_a_function_run_by_reflection_or_an_interface_is_covered_by_its_own_blocks(self):
        # Close() is only ever reached through an interface or reflect.Call: the profile
        # still counts its body, so a cut inside it is covered, not "unreferenced"
        blocks = self.BODY_BLOCKS[:6] + [(24, 24, 1), (24, 26, 0), (28, 28, 1)]
        res, notes, verdict = self.cut([27], blocks=blocks)
        self.assertEqual((res["covered"], notes, verdict), ([27], {"cut-in-function": [27]}, ("KEEP", "covered")))
        # and when it did not run, the same cut is uncovered
        self.assertEqual(self.cut([27])[2], ("SKIPPABLE", "uncovered"))

    def test_generated_file_is_refined_like_an_uncompiled_one_so_not_at_all(self):
        # build_refiner passes compiled=False for a generated file ("Code generated ... DO NOT EDIT")
        res, notes, verdict = self.cut([17], compiled=False)
        self.assertEqual((res["undetermined"], notes, verdict), ([17], {}, ("KEEP", "undetermined-lines")))
        res, notes, verdict = self.classify([3], closure=self.LINKED, compiled=False)
        self.assertEqual((res["undetermined"], notes), ([3], {}))

    def test_no_closure_information_means_no_unlinked_claim(self):
        # closure None: the const is still judged by its references, never as unlinked
        res, notes, _ = self.classify([5], closure=None)
        self.assertEqual(res["undetermined"], [5])
        self.assertNotIn("unlinked", notes)

    def test_file_not_compiled_here_is_left_alone(self):
        res, notes, verdict = self.classify([3, 13], closure=self.LINKED, compiled=False)
        self.assertEqual((res["undetermined"], notes, verdict), ([3, 13], {}, ("KEEP", "undetermined-lines")))

    def test_mentions_in_tests_and_other_packages(self):
        const_only = "package pkg\n\nconst limit = 1\n"
        # the dependent's own test uses it: that test code runs, no profile can say
        own = {"pkg/decls.go": const_only, "dep/x_test.go": "package dep\n\nimport \"testing\"\n\nimport p \"" + MOD + "/pkg\"\n\nfunc TestX(t *testing.T) { _ = p.limit }\n"}
        res = self.classify([3], tree=own, closure=self.LINKED, blocks=[])[0]
        self.assertEqual(res["undetermined"], [3])
        # another package's test does not run in the dependent's test binary
        other = {"pkg/decls.go": const_only, "pkg2/y_test.go": "package pkg2\n\nimport p \"" + MOD + "/pkg\"\n\nvar _ = p.limit\n"}
        self.assertEqual(self.classify([3], tree=other, closure=self.LINKED, blocks=[])[0]["uncovered"], [3])
        # non-test code of a package the binary links, outside the profile: unknown
        linked = {"pkg/decls.go": const_only, "pkg2/y.go": "package pkg2\n\nimport p \"" + MOD + "/pkg\"\n\nvar v = p.limit\n"}
        self.assertEqual(self.classify([3], tree=linked, closure=self.LINKED | {f"{MOD}/pkg2"}, blocks=[])[0]["undetermined"], [3])
        # the same code in a package the binary does not link cannot run
        self.assertEqual(self.classify([3], tree=linked, closure=self.LINKED, blocks=[])[0]["uncovered"], [3])

    def test_mention_packages_are_the_non_test_mentions_in_known_packages(self):
        refs = {"a.go#X": [{"file": "pkg/a.go", "line": 1, "test": False}, {"file": "pkg2/b_test.go", "line": 2, "test": True},
                           {"file": "other/mod.go", "line": 3, "test": False}],
                "a.go#Y": [{"file": "pkg3/c.go", "line": 4, "test": False}]}
        owning = {"pkg/a.go": f"{MOD}/pkg", "pkg3/c.go": f"{MOD}/pkg3"}.get
        self.assertEqual(cs.mention_packages(refs, owning), {f"{MOD}/pkg", f"{MOD}/pkg3"})
        self.assertEqual(cs.mention_packages({}, owning), set())

    def test_missing_reference_answer_stays_undetermined(self):
        ev = cs.DeclEval({}, lambda p: None, set(), "d", {})
        self.assertEqual(ev.verdict("a.go", {"names": ["x"]}, True), ("undetermined", None))


FAKE_GO = """#!/bin/sh
for a in "$@"; do case "$a" in -coverprofile=*) P="${a#-coverprofile=}";; esac; done
case "$FAKE_MODE" in
ok)
  printf 'mode: set\\n__MOD__/pkg/c.go:1.1,2.2 1 1\\n__MOD__/pkg/c.go:5.1,6.2 1 0\\n' > "$P"
  printf '%s\\n' '{"Action":"pass","Test":"TestA"}'
  printf '%s\\n' '{"Action":"pass","Package":"d"}'
  ;;
skips)
  printf 'mode: set\\n__MOD__/pkg/c.go:5.1,6.2 1 0\\n' > "$P"
  printf '%s\\n' '{"Action":"skip","Test":"TestPG"}'
  ;;
notests)
  printf '%s\\n' '{"Action":"output","Package":"d","Output":"?   \\td\\t[no test files]\\n"}'
  printf '%s\\n' '{"Action":"skip","Package":"d"}'
  ;;
fail)
  printf 'mode: set\\n' > "$P"
  printf '%s\\n' '{"Action":"fail","Test":"TestA"}'
  exit 1
  ;;
build)
  printf '%s\\n' '{"Action":"output","Package":"d","Output":"FAIL\\td [build failed]\\n"}'
  exit 2
  ;;
gotimeout)
  printf 'mode: set\\n' > "$P"
  printf '%s\\n' '{"Action":"output","Package":"d","Output":"panic: test timed out after 10m0s\\n"}'
  exit 2
  ;;
hang)
  printf 'mode: set\\n' > "$P"
  sleep 60
  ;;
esac
"""


class RunAndCleanup(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.mkdtemp(prefix="cs-unittest-")
        self.addCleanup(lambda: __import__("shutil").rmtree(self.work, ignore_errors=True))
        self.fake = os.path.join(self.work, "fakego")
        with open(self.fake, "w") as fh:
            fh.write(FAKE_GO.replace("__MOD__", MOD))
        os.chmod(self.fake, os.stat(self.fake).st_mode | stat.S_IXUSR)
        self.tmp = os.path.join(self.work, "tmp")
        os.makedirs(self.tmp)
        self.run_ = cs.Run(self.tmp)
        self.changes = {"pkg/c.go": [(1, 1, False)]}

    def measure(self, mode, ranges=None, timeout="1s", grace=0.5):
        os.environ["FAKE_MODE"] = mode
        self.addCleanup(os.environ.pop, "FAKE_MODE", None)
        changes = {"pkg/c.go": ranges or [(1, 1, False)]}
        orig = cs.parse_duration_s
        cs.parse_duration_s = lambda t: float(t.rstrip("s"))  # kill_after = timeout + 120 normally
        self.addCleanup(setattr, cs, "parse_duration_s", orig)
        rec = cs.measure_dependent(self.run_, self.fake, "d", [f"{MOD}/pkg"], changes, {}, timeout, grace=grace)
        return rec

    def leftovers(self):
        return sorted(os.listdir(self.run_.root))

    def test_success_keep_and_profile_removed(self):
        rec = self.measure("ok")
        self.assertEqual((rec["verdict"], rec["basis"]), ("KEEP", "covered"))
        self.assertEqual(self.leftovers(), ["gotmp"])

    def test_success_skippable_when_changed_lines_uncovered(self):
        rec = self.measure("ok", ranges=[(5, 6, False)])
        self.assertEqual((rec["verdict"], rec["basis"]), ("SKIPPABLE", "uncovered"))
        self.assertEqual(rec["files"]["pkg/c.go"], {"uncovered": ["5-6"]})
        self.assertEqual(self.leftovers(), ["gotmp"])

    def test_no_test_files_keeps_and_leaves_nothing(self):
        rec = self.measure("notests")
        self.assertEqual((rec["verdict"], rec["basis"]), ("KEEP", "no-test-files"))
        self.assertEqual(self.leftovers(), ["gotmp"])

    def test_failed_tests_and_build_failure_keep(self):
        rec = self.measure("fail")
        self.assertEqual((rec["verdict"], rec["basis"]), ("KEEP", "test-failed"))
        rec = self.measure("build")
        self.assertEqual((rec["verdict"], rec["basis"]), ("KEEP", "build-failed"))
        self.assertEqual(self.leftovers(), ["gotmp"])

    def test_timeout_kills_the_group_keeps_and_removes_profile(self):
        rec = self.measure("hang", timeout="1s", grace=0.2)
        self.assertEqual((rec["verdict"], rec["basis"]), ("KEEP", "timeout"))
        self.assertEqual(self.leftovers(), ["gotmp"])
        self.assertLess(rec["duration_s"], 30)

    def test_gos_own_timeout_is_a_timeout_not_a_failed_test(self):
        rec = self.measure("gotimeout")
        self.assertEqual((rec["verdict"], rec["basis"]), ("KEEP", "timeout"))
        self.assertEqual(self.leftovers(), ["gotmp"])

    def test_skips_then_downgrade(self):
        rec = self.measure("skips", ranges=[(5, 6, False)])
        self.assertEqual((rec["verdict"], rec["tests"]["skip"]), ("SKIPPABLE", 1))
        rec = cs.apply_run_level_rules(rec, "d", set(), set(), True)
        self.assertEqual((rec["verdict"], rec["basis"]), ("KEEP", "tests-skipped"))

    def test_run_cleanup_removes_the_root(self):
        root = self.run_.root
        self.run_.cleanup()
        self.assertFalse(os.path.exists(root))
        self.assertEqual(os.listdir(self.tmp), [])


class MainPaths(unittest.TestCase):
    """main() on the paths that decide before touching git or go."""

    def run_main(self, decision):
        work = tempfile.mkdtemp(prefix="cs-main-")
        self.addCleanup(lambda: __import__("shutil").rmtree(work, ignore_errors=True))
        dpath, lpath, tmp = (os.path.join(work, n) for n in ("decision.json", "log.jsonl", "tmp"))
        os.makedirs(tmp)
        with open(dpath, "w") as fh:
            json.dump(decision, fh)
        code = cs.main(["--base", "deadbeef", "--decision", dpath, "--log", lpath, "--tmpdir", tmp, "--pr", "1"])
        with open(lpath) as fh:
            recs = [json.loads(line) for line in fh]
        self.assertEqual(os.listdir(tmp), [], "temp root must be gone")
        return code, recs

    def test_lever_a_zero_dependents_skips_entirely(self):
        code, recs = self.run_main({"mode": "selected", "seeds": {"p": "code file x"}, "affected": ["p"]})
        self.assertEqual(code, 0)
        self.assertEqual([(r["type"], r["reason"]) for r in recs], [("skip", "lever-a-zero-dependents")])

    def test_lever_a_full_mode_skips(self):
        code, recs = self.run_main({"mode": "full", "reason": "go.mod changed"})
        self.assertEqual((code, recs[0]["reason"]), (0, "lever-a-mode-full"))

    def test_internal_error_is_logged_exit_zero_and_cleans_up(self):
        code, recs = self.run_main({"mode": "selected", "seeds": {}, "affected": ["a", "b"]})  # git rev-parse deadbeef fails
        self.assertEqual(code, 0)
        self.assertEqual(recs[-1]["type"], "error")


if __name__ == "__main__":
    unittest.main()
