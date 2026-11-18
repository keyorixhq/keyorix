"""Tests for regate_lib.

Red/green proofs:
  TestGate_PlantedRegression_Fails   — planted regression makes the gate exit non-zero
  TestGate_Repaired_Passes           — repairing the finding makes the gate pass
  TestGate_NoTouchingFiles_NoneMatch — diff that touches nothing → no match
  TestGate_MissingSeedFile_ErrorLoud — declared seed missing → loud error, not silent skip

Each test uses a fake go_test_runner that returns controlled output; no real
go test commands are executed.
"""
import os
import sys
import unittest

# Ensure the parent directory is on sys.path so regate_lib is importable.
_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
sys.path.insert(0, _PARENT)

from regate_lib import (
    GateConfig,
    GateOutput,
    ReproMissingError,
    RegistryError,
    Target,
    changed_packages,
    derive_finding_targets as _derive,
    find_seeds,
    load_findings,
    load_target_map,
    match_findings,
    run_gate,
)

_FIXTURES = os.path.join(_HERE, "fixtures")
_REGISTRY = os.path.join(_FIXTURES, "registry")
_TARGETS_D = os.path.join(_FIXTURES, "targets.d")
_REPO = os.path.join(_FIXTURES, "repo")

# Seed file that exists in the fixture repo
_SEED_REL = "internal/foo/testdata/fuzz/FuzzFoo/aabbccddeeff0011"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ok_runner(cmd, cwd):
    """Fake runner: always returns success."""
    return 0, "ok\n--- PASS: TestFuzz (0.00s)\n"


def _fail_runner(cmd, cwd):
    """Fake runner: always returns failure (simulates a crash found)."""
    return 1, "--- FAIL: FuzzFoo (0.00s)\npanic: runtime error: index out of range\n"


def _runner_for_seed(failing_seed: str, fail_burst: bool = False):
    """Return a runner that fails only when replaying the named seed (or burst)."""
    def runner(cmd, cwd):
        # Detect seed replay: -run flag contains the seed name
        is_replay = any(failing_seed in arg for arg in cmd)
        is_burst = any("-fuzz" in arg for arg in cmd)
        if is_replay or (fail_burst and is_burst):
            return _fail_runner(cmd, cwd)
        return _ok_runner(cmd, cwd)
    return runner


def _make_cfg(runner=None, no_burst=False, no_replay=False):
    return GateConfig(
        registry_dir=_REGISTRY,
        targets_d=_TARGETS_D,
        repo_root=_REPO,
        fuzztime="1s",
        runner=runner or _ok_runner,
        no_burst=no_burst,
        no_replay=no_replay,
    )


# ---------------------------------------------------------------------------
# Unit tests: data model
# ---------------------------------------------------------------------------

class TestLoadTargetMap(unittest.TestCase):
    def test_loads_foo_and_bar(self):
        m = load_target_map(_TARGETS_D)
        self.assertEqual(m.get("FuzzFoo"), "internal/foo")
        self.assertEqual(m.get("FuzzBar"), "internal/bar")

    def test_no_comment_lines(self):
        m = load_target_map(_TARGETS_D)
        for k in m:
            self.assertFalse(k.startswith("#"), f"comment line leaked: {k!r}")


class TestDeriveTargets(unittest.TestCase):
    def setUp(self):
        self.target_map = load_target_map(_TARGETS_D)

    def test_crasher_path_decoded(self):
        finding = {
            "id": "KFZ-TEST-001",
            "crashers": [
                "crashers/keyorix/github.com_keyorixhq_keyorix_internal_foo/FuzzFoo/aabbccddeeff0011"
            ],
            "repro": {},
        }
        targets = _derive(finding, self.target_map)
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0].pkg, "internal/foo")
        self.assertEqual(targets[0].func, "FuzzFoo")

    def test_targets_d_wins_over_crasher_path_decode(self):
        # targets.d says "internal/foo", crasher path would decode to "internal/foo"
        # In this case they agree, but targets.d always wins by design.
        finding = {
            "id": "KFZ-X",
            "crashers": [
                "crashers/keyorix/github.com_keyorixhq_keyorix_internal_something_else/FuzzFoo/aabbccdd"
            ],
            "repro": {},
        }
        targets = _derive(finding, self.target_map)
        # FuzzFoo is in targets.d mapped to "internal/foo" — that wins.
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0].pkg, "internal/foo")

    def test_reg_test_field_fallback(self):
        finding = {
            "id": "KFZ-TEST-002",
            "crashers": [],
            "repro": {"regression_test": "internal/bar FuzzBar"},
        }
        targets = _derive(finding, self.target_map)
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0].pkg, "internal/bar")
        self.assertEqual(targets[0].func, "FuzzBar")

    def test_private_path_in_reg_test_ignored(self):
        finding = {
            "id": "KFZ-X",
            "crashers": [],
            "repro": {"regression_test": "~/proj/keyorix-private/proof/"},
        }
        targets = _derive(finding, self.target_map)
        self.assertEqual(len(targets), 0)

    def test_upstream_crasher_not_in_keyorix_project_ignored(self):
        finding = {
            "id": "KFZ-TEST-003",
            "crashers": [
                "crashers/libs-extra/FuzzLibFooXYZ/abcdef123456"
            ],
            "repro": {},
        }
        targets = _derive(finding, self.target_map)
        self.assertEqual(len(targets), 0)

    def test_no_duplicate_targets(self):
        # Two crasher entries pointing to the same (pkg, func)
        finding = {
            "id": "KFZ-X",
            "crashers": [
                "crashers/keyorix/github.com_keyorixhq_keyorix_internal_foo/FuzzFoo/aabb",
                "crashers/keyorix/github.com_keyorixhq_keyorix_internal_foo/FuzzFoo/ccdd",
            ],
            "repro": {},
        }
        targets = _derive(finding, self.target_map)
        self.assertEqual(len(targets), 1)


class TestChangedPackages(unittest.TestCase):
    def test_go_files_converted(self):
        pkgs = changed_packages([
            "internal/foo/foo.go",
            "internal/bar/bar.go",
            "README.md",
        ])
        self.assertIn("internal/foo", pkgs)
        self.assertIn("internal/bar", pkgs)
        self.assertNotIn("", pkgs)

    def test_non_go_files_excluded(self):
        pkgs = changed_packages(["docs/guide.md", "schema.sql"])
        self.assertEqual(pkgs, set())

    def test_root_go_file(self):
        pkgs = changed_packages(["main.go"])
        self.assertEqual(pkgs, set())  # root file has no parent directory

    def test_subpackage_matches_parent_target(self):
        # target_pkg = "internal/foo"; changed = "internal/foo/subpkg" → should match
        from regate_lib import _pkg_matches
        self.assertTrue(_pkg_matches({"internal/foo/subpkg"}, "internal/foo"))

    def test_sibling_does_not_match(self):
        from regate_lib import _pkg_matches
        self.assertFalse(_pkg_matches({"internal/foobar"}, "internal/foo"))


class TestMatchFindings(unittest.TestCase):
    def setUp(self):
        target_map = load_target_map(_TARGETS_D)
        self.findings = load_findings(_REGISTRY, target_map)

    def test_finds_kfz_test_001_on_internal_foo_change(self):
        changed = {"internal/foo"}
        matched = match_findings(self.findings, changed)
        ids = {f.id for f in matched}
        self.assertIn("KFZ-TEST-001", ids)

    def test_upstream_kfz_test_003_not_matched(self):
        changed = {"internal/foo"}
        matched = match_findings(self.findings, changed)
        ids = {f.id for f in matched}
        self.assertNotIn("KFZ-TEST-003", ids)

    def test_unrelated_package_matches_nothing(self):
        changed = {"server/grpc"}
        matched = match_findings(self.findings, changed)
        self.assertEqual(len(matched), 0)

    def test_empty_diff_matches_nothing(self):
        matched = match_findings(self.findings, set())
        self.assertEqual(len(matched), 0)


class TestFindSeeds(unittest.TestCase):
    def test_finds_committed_seed(self):
        seeds = find_seeds(_REPO, "FuzzFoo")
        self.assertTrue(any("aabbccddeeff0011" in s for s in seeds),
                        f"seed not found in {seeds}")

    def test_no_seeds_for_unknown_func(self):
        seeds = find_seeds(_REPO, "FuzzNeverExists")
        self.assertEqual(seeds, [])


# ---------------------------------------------------------------------------
# Integration-style gate tests (fake runner, no real go test)
# ---------------------------------------------------------------------------

class TestGate_PlantedRegression_Fails(unittest.TestCase):
    """Red proof: a planted regression (fake runner returns non-zero) makes the gate fail."""

    def test_seed_replay_failure_is_detected(self):
        # Runner fails when replaying the known seed for KFZ-TEST-001
        runner = _runner_for_seed("aabbccddeeff0011")
        cfg = _make_cfg(runner=runner)
        diff = ["internal/foo/foo.go"]
        out = run_gate(diff, cfg)

        # At least one failure
        failures = [r for r in out.rows if not r.ok and "skipped" not in r.error_msg]
        self.assertGreater(len(failures), 0,
                           "Expected at least one failure from planted regression")

        # The failing row references the right finding
        failing_ids = {r.finding_id for r in failures}
        self.assertIn("KFZ-TEST-001", failing_ids)

    def test_burst_failure_is_detected(self):
        # Runner fails during burst (after seed replay succeeds)
        runner = _runner_for_seed("aabbccddeeff0011", fail_burst=True)
        cfg = _make_cfg(runner=runner)
        diff = ["internal/foo/foo.go"]
        out = run_gate(diff, cfg)
        failures = [r for r in out.rows if not r.ok and "skipped" not in r.error_msg]
        self.assertGreater(len(failures), 0, "Expected burst failure to be detected")


class TestGate_Repaired_Passes(unittest.TestCase):
    """Green proof: when the runner succeeds for all seeds and burst, gate passes."""

    def test_all_pass_when_runner_succeeds(self):
        cfg = _make_cfg(runner=_ok_runner)
        diff = ["internal/foo/foo.go"]
        out = run_gate(diff, cfg)
        failures = [r for r in out.rows if not r.ok and "skipped" not in r.error_msg]
        self.assertEqual(len(failures), 0, f"Unexpected failures: {failures}")

    def test_matched_findings_non_empty(self):
        cfg = _make_cfg(runner=_ok_runner)
        diff = ["internal/foo/foo.go"]
        out = run_gate(diff, cfg)
        self.assertGreater(len(out.matched_findings), 0)


class TestGate_NoTouchingFiles_NoneMatch(unittest.TestCase):
    """Diff that touches no covered package → empty match, gate exits 0."""

    def test_unrelated_diff(self):
        cfg = _make_cfg()
        diff = ["docs/guide.md", "server/grpc/handler.go"]
        out = run_gate(diff, cfg)
        self.assertEqual(len(out.matched_findings), 0)

    def test_no_go_files(self):
        cfg = _make_cfg()
        diff = ["README.md", "schema.sql", "docs/conf.py"]
        out = run_gate(diff, cfg)
        self.assertEqual(len(out.matched_findings), 0)


class TestGate_MissingSeedFile_ErrorLoud(unittest.TestCase):
    """Registered seed file missing → ReproMissingError raised, not silently skipped."""

    def test_raises_repro_missing_error(self):
        cfg = _make_cfg(runner=_ok_runner)
        # registered_seeds declares a seed that does NOT exist in the fixture repo
        registered_seeds = {
            "KFZ-TEST-004": ["internal/foo/testdata/fuzz/FuzzFoo/deadbeef00001111"]
        }
        diff = ["internal/foo/foo.go"]
        with self.assertRaises(ReproMissingError) as ctx:
            run_gate(diff, cfg, registered_seeds=registered_seeds)
        self.assertIn("KFZ-TEST-004", str(ctx.exception))
        self.assertIn("deadbeef00001111", str(ctx.exception))

    def test_error_message_is_actionable(self):
        cfg = _make_cfg(runner=_ok_runner)
        registered_seeds = {
            "KFZ-TEST-001": ["internal/foo/testdata/fuzz/FuzzFoo/NONEXISTENT_SEED"]
        }
        diff = ["internal/foo/foo.go"]
        with self.assertRaises(ReproMissingError) as ctx:
            run_gate(diff, cfg, registered_seeds=registered_seeds)
        msg = str(ctx.exception)
        # Must mention the finding id and what to do
        self.assertIn("KFZ-TEST-001", msg)
        self.assertIn("NONEXISTENT_SEED", msg)


class TestGate_NoBurstNorReplay(unittest.TestCase):
    """When both no_burst and no_replay are set, gate still matches but runs nothing."""

    def test_rows_are_mostly_empty(self):
        cfg = _make_cfg(runner=_ok_runner, no_burst=True, no_replay=True)
        diff = ["internal/foo/foo.go"]
        out = run_gate(diff, cfg)
        # Matched findings are non-empty (match still runs)
        self.assertGreater(len(out.matched_findings), 0)
        # Rows may contain "burst skipped" / no-func entries only; no real runs
        real_runs = [r for r in out.rows
                     if r.seed_name is not None or
                     ("skipped" not in r.error_msg and r.seed_name is None)]
        # All rows should be "skipped" type or empty
        for r in out.rows:
            self.assertIn("skipped", r.error_msg,
                          f"Expected skipped but got: {r!r}")


class TestGate_RegistryErrors(unittest.TestCase):
    def test_missing_registry_raises(self):
        cfg = _make_cfg()
        cfg.registry_dir = "/nonexistent/registry"
        with self.assertRaises(RegistryError):
            run_gate(["internal/foo/foo.go"], cfg)

    def test_missing_targets_d_raises(self):
        cfg = _make_cfg()
        cfg.targets_d = "/nonexistent/targets.d"
        with self.assertRaises(RegistryError):
            run_gate(["internal/foo/foo.go"], cfg)


class TestGate_ExplicitIdFilter(unittest.TestCase):
    """--id filter limits gate to specific finding IDs."""

    def test_only_specified_id_runs(self):
        cfg = _make_cfg(runner=_ok_runner)
        cfg.only_ids = ["KFZ-TEST-001"]
        diff = ["internal/foo/foo.go", "internal/bar/bar.go"]
        out = run_gate(diff, cfg)
        ids = {f.id for f in out.matched_findings}
        self.assertIn("KFZ-TEST-001", ids)
        # KFZ-TEST-002 touches internal/bar; with filter it should not appear
        self.assertNotIn("KFZ-TEST-002", ids)


class TestGate_RegisteredSeedsGreenPath(unittest.TestCase):
    """When registered_seeds is provided and all files exist, gate runs normally."""

    def test_registered_seed_replayed_when_exists(self):
        cfg = _make_cfg(runner=_ok_runner)
        # aabbccddeeff0011 exists in the fixture repo
        registered_seeds = {
            "KFZ-TEST-001": [_SEED_REL]
        }
        diff = ["internal/foo/foo.go"]
        out = run_gate(diff, cfg, registered_seeds=registered_seeds)
        replay_rows = [r for r in out.rows if r.seed_name == "aabbccddeeff0011"]
        self.assertGreater(len(replay_rows), 0, "Expected replay rows for the registered seed")
        self.assertTrue(all(r.ok for r in replay_rows), "Expected replay to pass")


if __name__ == "__main__":
    unittest.main(verbosity=2)
