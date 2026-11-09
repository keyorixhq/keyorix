"""Unit tests for check-weights-drift.py and logs-to-timings.py (WEIGHTS-DRIFT-1).

Run by scripts/ci/weights_drift_test.go (or: python3 scripts/ci/weights_drift_unittest.py
from the repo root).

Calibration both ways, from real data (testdata/weights-drift/):
  * timings-run-42522635702.tsv: verbose main run 42522635702 (3168ca1e8, 2026-11-08),
    made from its job logs by logs-to-timings.py; weights-at-3168ca1e8.tsv is the file
    at that commit. The check must fire on the faultops pole and the core pole.
  * timings-run-42586426128.tsv: the newest verbose main run (654ac2097, 2026-11-09, after
    the weights PR and the two sweep PRs); weights-main-2026-11-09.tsv is main's file
    after the weights PR. The check must not report a drift.
No test reads the clock or the live weights file: a regeneration must not turn this red.
"""
import importlib.util
import io
import os
import contextlib
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "testdata", "weights-drift")


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, filename))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


import sys  # noqa: E402

sys.path.insert(0, HERE)
cwd = load("check_weights_drift", "check-weights-drift.py")
ltt = load("logs_to_timings", "logs-to-timings.py")
layout = cwd.weights_layout

OLD_TIMINGS = os.path.join(DATA, "timings-run-42522635702.tsv")
NEW_TIMINGS = os.path.join(DATA, "timings-run-42586426128.tsv")
OLD_WEIGHTS = os.path.join(DATA, "weights-at-3168ca1e8.tsv")
MAIN_WEIGHTS = os.path.join(DATA, "weights-main-2026-11-09.tsv")


def run(timings, weights):
    rows = cwd.read_timings(timings)
    return cwd.analyse(rows, weights)


def rule_a(findings):
    return {(f["package"], f["test"]): f for f in findings if f["rule"] == "A"}


def rule_b(findings):
    return {(f["package"], f["shard"]): f for f in findings if f["rule"] == "B"}


class LayoutTest(unittest.TestCase):
    def test_layout_comes_from_sharded_legs(self):
        pk = layout.sharded_packages()
        self.assertEqual(pk["server/faultops"]["shards"], 5)
        self.assertEqual(pk["internal/core"]["shards"], 4)
        self.assertEqual(pk["server/faultops"]["prefix"], "faultops")
        self.assertNotIn("internal/storage/store", pk, "a one-shard row is not a split")

    def test_leg_package(self):
        self.assertEqual(layout.leg_package("faultops-4"), ("server/faultops", 4))
        self.assertIsNone(layout.leg_package("root-1"))
        self.assertIsNone(layout.leg_package("faultops-6"))

    def test_layout_reproduces_the_leg_column_of_the_measuring_run(self):
        # The run used the file at its own commit: the repo's packer under that file
        # must put every test on the leg it really ran on, or the layout is not CI's.
        _pk, _f, notes = run(OLD_TIMINGS, OLD_WEIGHTS)
        self.assertEqual(notes, [])


class CalibrationOldRunTest(unittest.TestCase):
    """Run 42522635702 under the weights file it ran with: the 28 Oct - 8 Nov pole."""

    @classmethod
    def setUpClass(cls):
        cls.packages, cls.findings, cls.notes = run(OLD_TIMINGS, OLD_WEIGHTS)

    def test_rule_a_fires_on_the_unweighted_heavy_tests(self):
        a = rule_a(self.findings)
        mfa = a[("server/faultops", "TestMFAResetOpsFaultSweep")]
        self.assertAlmostEqual(mfa["seconds"], 1346.28, places=2)
        self.assertEqual(mfa["shard"], 4)
        self.assertAlmostEqual(mfa["default"], 0.2696, places=4)
        fake = a[("internal/core", "TestFakeClockExtremes_Cross")]
        self.assertAlmostEqual(fake["seconds"], 1498.4, places=1)

    def test_authorize_secrets_batch_had_a_row_so_rule_a_is_silent(self):
        # The brief expected Rule A here, but the old file DOES have a row for it
        # (208.9 s against 675.7 s measured): it was stale, not missing. Rule A is
        # "no explicit row", as designed; the stale row shows up through Rule B.
        explicit, _ = layout.read_weights(OLD_WEIGHTS)
        self.assertEqual(explicit["internal/core"]["TestAuthorizeSecretsBatch_EqualsPerRow"], 208.9)
        self.assertNotIn(("internal/core", "TestAuthorizeSecretsBatch_EqualsPerRow"), rule_a(self.findings))

    def test_rule_b_fires_on_faultops_4_with_predicted_vs_measured(self):
        b = rule_b(self.findings)[("server/faultops", 4)]
        self.assertEqual(b["kind"], "drift")
        self.assertAlmostEqual(b["predicted"], 545.5, delta=1.0)
        self.assertGreater(b["measured"], 1900)
        self.assertGreater(b["measured"], cwd.RULE_B_RATIO * b["median"])
        self.assertIn("predicted/measured per shard", b["msg"])
        self.assertNotIn("dominated", b["msg"], "an unweighted test is drift, not 'split the test'")

    def test_only_the_heavy_shards_are_flagged(self):
        flagged = set(rule_b(self.findings))
        self.assertIn(("internal/core", 4), flagged)
        self.assertNotIn(("server/faultops", 1), flagged)
        self.assertNotIn(("server/faultops", 5), flagged)


class CalibrationNewWeightsTest(unittest.TestCase):
    def test_main_weights_on_the_newest_run_report_no_drift(self):
        _pk, findings, notes = run(NEW_TIMINGS, MAIN_WEIGHTS)
        self.assertEqual(rule_b(findings), {}, "no shard may be over 1.30 x median")
        # One true Rule A, 4 s over the line: a 64 s test that has no row yet. It is
        # pinned so that a threshold change that hides or multiplies it is seen.
        self.assertEqual(sorted(t for _p, t in rule_a(findings)), ["TestMFAResetSweepReuseMatchesFreshWorlds"])
        # The run ran under this very file, so the repo's packer must reproduce its legs.
        self.assertEqual(notes, [])

    def test_old_run_under_main_weights_is_the_dominated_form(self):
        # The same measuring run judged by the regenerated file: TestMFAResetOpsFaultSweep
        # is 1346 s on a shard of its own, so the weights are right and cannot balance it.
        _pk, findings, _n = run(OLD_TIMINGS, MAIN_WEIGHTS)
        self.assertEqual(rule_a(findings), {})
        b = rule_b(findings)
        self.assertEqual(set(b), {("server/faultops", 1)})
        self.assertEqual(b[("server/faultops", 1)]["kind"], "dominated")
        self.assertIn("dominated by TestMFAResetOpsFaultSweep", b[("server/faultops", 1)]["msg"])
        self.assertIn("split the test", b[("server/faultops", 1)]["msg"])
        self.assertTrue(all(f["kind"] == "dominated" for f in b.values()))


class SyntheticRulesTest(unittest.TestCase):
    """Edges of the rules on a tiny weights file (hand-made: the rule logic, not a gate)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def weights(self, text):
        path = os.path.join(self.tmp.name, "w.tsv")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        return path

    def timings(self, rows):
        path = os.path.join(self.tmp.name, "t.tsv")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("# package\ttest\tseconds\tleg\n")
            for pkg, test, secs in rows:
                fh.write(f"{pkg}\t{test}\t{secs}\t\n")
        return path

    def test_exactly_60_seconds_is_not_over_the_line(self):
        w = self.weights("server/faultops\t*\t1\n")
        rows = [("server/faultops", f"TestA{i}", 1) for i in range(10)] + [("server/faultops", "TestEdge", 60.0)]
        _p, f, _n = run(self.timings(rows), w)
        self.assertEqual(rule_a(f), {})
        rows[-1] = ("server/faultops", "TestEdge", 60.5)
        _p, f, _n = run(self.timings(rows), w)
        self.assertIn(("server/faultops", "TestEdge"), rule_a(f))

    def test_explicit_row_silences_rule_a(self):
        w = self.weights("server/faultops\t*\t1\nserver/faultops\tTestHeavy\t10\n")
        rows = [("server/faultops", "TestHeavy", 500)] + [("server/faultops", f"TestA{i}", 1) for i in range(10)]
        _p, f, _n = run(self.timings(rows), w)
        self.assertEqual(rule_a(f), {})

    def test_unsharded_package_is_ignored(self):
        w = self.weights("internal/storage/store\t*\t1\n")
        _p, f, _n = run(self.timings([("internal/storage/store", "TestBig", 900)]), w)
        self.assertEqual(f, [])
        self.assertEqual(_p, [])

    def test_missing_default_row_weighs_one_like_the_packer(self):
        w = self.weights("# no row for the package\n")
        rows = [("server/faultops", "TestBig", 200)] + [("server/faultops", f"TestA{i}", 1) for i in range(9)]
        _p, f, _n = run(self.timings(rows), w)
        self.assertEqual(rule_a(f)[("server/faultops", "TestBig")]["default"], 1.0)


class ConverterTest(unittest.TestCase):
    EXCERPT = os.path.join(DATA, "faultops-4-excerpt.log")

    def test_real_log_excerpt_gives_top_level_tests_only(self):
        rows = ltt.convert([f"faultops-4={self.EXCERPT}"])
        self.assertEqual(rows, [("server/faultops", "TestMFAResetOpsFaultSweep", 1346.28, "faultops-4")])

    def test_non_sharded_leg_is_an_error(self):
        with self.assertRaises(SystemExit) as cm:
            ltt.convert([f"root-1={self.EXCERPT}"])
        self.assertIn("not a sharded leg", str(cm.exception))

    def test_log_without_test_lines_is_an_error_not_an_empty_table(self):
        with tempfile.NamedTemporaryFile("w", suffix=".log") as fh:
            fh.write("2026-11-08T20:56:40.3Z Current runner version: '2.338.2'\n")
            fh.flush()
            with self.assertRaises(SystemExit) as cm:
                ltt.convert([f"faultops-1={fh.name}"])
        self.assertIn("no '--- PASS", str(cm.exception))

    def test_unreadable_log_is_an_error(self):
        with self.assertRaises(SystemExit):
            ltt.convert(["faultops-1=/nonexistent/faultops-1.log"])


class ExitStatusTest(unittest.TestCase):
    def call(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cwd.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_report_only_exits_0_with_findings(self):
        code, out, _err = self.call([OLD_TIMINGS, "--weights", OLD_WEIGHTS])
        self.assertEqual(code, 0)
        self.assertIn("::warning title=weights-drift rule A::", out)
        self.assertIn("TestMFAResetOpsFaultSweep", out)

    def test_strict_exits_1_on_findings(self):
        self.assertEqual(self.call([OLD_TIMINGS, "--weights", OLD_WEIGHTS, "--strict"])[0], 1)

    def test_unusable_input_is_loud_but_exit_0(self):
        code, out, err = self.call(["/nonexistent/timings.tsv", "--weights", OLD_WEIGHTS])
        self.assertEqual(code, 0)
        self.assertIn("ERROR", err)
        self.assertIn("::warning title=weights-drift input::", out)
        self.assertEqual(self.call(["/nonexistent/timings.tsv", "--weights", OLD_WEIGHTS, "--strict"])[0], 2)

    def test_summary_file_is_appended(self):
        with tempfile.NamedTemporaryFile("w+", suffix=".md") as fh:
            self.call([OLD_TIMINGS, "--weights", OLD_WEIGHTS, "--summary", fh.name])
            fh.seek(0)
            self.assertIn("## Weights drift (report-only)", fh.read())


if __name__ == "__main__":
    unittest.main()
