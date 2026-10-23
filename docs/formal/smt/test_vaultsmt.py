"""Tests for vaultsmt.py (RD-SMT-SPIKE-1).

Run from the repository root (needs the z3 CLI on PATH; nothing else):

    python3 -m unittest discover -s docs/formal/smt -p 'test_*.py' -v

Three layers, each closing a different gap:

1. Vault ACL semantics on concrete paths (VaultSemanticsTest): the reference evaluator
   (vaultsmt.vault_allows) against the matching rules in Vault's own documentation
   (exact beats glob, "priority matching" for globs and "+" segments, same-path merge,
   deny only within the selected rule). These are the claims the encoding rests on.
2. SMT encoding against the reference evaluator (EncodingDifferentialTest): for many
   (rule set, concrete path) pairs the solver's verdict must equal vault_allows'. This
   catches a wrong regex or a wrong ite-chain order in the SMT-LIB text.
3. Verdicts on the real cases (RealCasesTest): every case under cases/ has an expected
   verdict; every counterexample the solver returns is re-checked by the two concrete
   evaluators (Vault denies, Keyorix allows), so a decoding bug cannot invent one.

What this does NOT check: that the reference evaluator agrees with a running Vault.
That check needs Vault in a container (pending e2e VM; vault_oracle.py is prepared).
"""

import json
import os
import random
import shutil
import unittest

import vaultsmt as vs

HERE = os.path.dirname(os.path.abspath(__file__))
CASES = os.path.join(HERE, "cases")


def rules(*pairs):
    """rules(("secret/data/*", ["read"]), ...) -> merged Vault ACL."""
    return vs.merge_rules([{"policy": "p%d" % i, "path": p, "capabilities": c}
                           for i, (p, c) in enumerate(pairs)])


class VaultSemanticsTest(unittest.TestCase):
    def test_exact_beats_glob(self):
        acl = rules(("secret/data/payments/*", ["read", "list"]),
                    ("secret/data/payments/db", ["deny"]))
        self.assertTrue(vs.vault_allows(acl, "secret/data/payments/stripe", "read"))
        self.assertFalse(vs.vault_allows(acl, "secret/data/payments/db", "read"))

    def test_trailing_star_is_prefix_across_slashes(self):
        acl = rules(("secret/data/*", ["read"]))
        self.assertTrue(vs.vault_allows(acl, "secret/data/a/b/c", "read"))
        self.assertFalse(vs.vault_allows(acl, "secret/metadata/a", "read"))
        self.assertFalse(vs.vault_allows(acl, "secret/data/a", "list"))

    def test_star_mid_segment(self):
        acl = rules(("secret/data/team-*", ["read"]))
        self.assertTrue(vs.vault_allows(acl, "secret/data/team-a/x", "read"))
        self.assertFalse(vs.vault_allows(acl, "secret/data/tea", "read"))

    def test_plus_is_exactly_one_segment(self):
        acl = rules(("auth/+/role", ["list"]))
        self.assertTrue(vs.vault_allows(acl, "auth/approle/role", "list"))
        self.assertFalse(vs.vault_allows(acl, "auth/a/b/role", "list"))

    def test_less_specific_deny_does_not_override_more_specific_allow(self):
        # Vault picks ONE rule (the highest-priority match); a deny on a broader glob
        # does not reach into a narrower allow. (Deny only dominates on the SAME path.)
        acl = rules(("secret/data/org/team-a/*", ["deny"]),
                    ("secret/data/org/team-a/service/*", ["read"]))
        self.assertTrue(vs.vault_allows(acl, "secret/data/org/team-a/service/x", "read"))
        self.assertFalse(vs.vault_allows(acl, "secret/data/org/team-a/other", "read"))

    def test_same_path_merges_and_deny_wins(self):
        acl = rules(("secret/data/*", ["read"]), ("secret/data/*", ["update"]))
        self.assertTrue(vs.vault_allows(acl, "secret/data/x", "read"))
        self.assertTrue(vs.vault_allows(acl, "secret/data/x", "update"))
        acl = rules(("secret/data/*", ["read"]), ("secret/data/*", ["deny"]))
        self.assertFalse(vs.vault_allows(acl, "secret/data/x", "read"))

    def test_priority_first_wildcard_later_wins(self):
        acl = rules(("secret/+/x", ["deny"]), ("secret/data/*", ["read"]))
        self.assertTrue(vs.vault_allows(acl, "secret/data/x", "read"))

    def test_priority_non_star_suffix_wins_on_tie(self):
        acl = rules(("secret/data/*", ["deny"]), ("secret/data/+/foo", ["read"]))
        self.assertTrue(vs.vault_allows(acl, "secret/data/x/foo", "read"))
        self.assertFalse(vs.vault_allows(acl, "secret/data/x/bar", "read"))

    def test_priority_fewer_plus_segments_wins(self):
        acl = rules(("a/+/+/c", ["deny"]), ("a/+/b/c", ["read"]))
        self.assertTrue(vs.vault_allows(acl, "a/x/b/c", "read"))

    def test_priority_longer_wins(self):
        acl = rules(("secret/data/a*", ["deny"]), ("secret/data/ab*", ["read"]))
        self.assertTrue(vs.vault_allows(acl, "secret/data/abc", "read"))
        self.assertFalse(vs.vault_allows(acl, "secret/data/ax", "read"))

    def test_list_on_trailing_slash_matches_exact_rule(self):
        acl = rules(("secret/metadata/team", ["list"]))
        self.assertTrue(vs.vault_allows(acl, "secret/metadata/team/", "list"))

    def test_no_rule_is_deny(self):
        self.assertFalse(vs.vault_allows(rules(), "secret/data/x", "read"))

    def test_templated_path_never_matches_literally(self):
        # The templated policy is evaluated per entity in Vault; the static encoding
        # treats "{{...}}" as a literal, so it matches nothing a real request carries.
        acl = rules(("secret/data/users/{{identity.entity.id}}/*", ["read"]))
        self.assertFalse(vs.vault_allows(acl, "secret/data/users/e-1/x", "read"))


class EncodingDifferentialTest(unittest.TestCase):
    """The SMT encoding must agree with the concrete evaluator, path by path."""

    PATTERNS = ["secret/data/*", "secret/data/payments/*", "secret/data/payments/db",
                "secret/data/+/db", "secret/data/team-*", "secret/+/x", "secret/data/+/+/c",
                "secret/metadata/*", "secret/metadata/team", "secret/data/org/team-a/*",
                "secret/data/org/team-a/service/*", "kv1/*", "kv1/legacy/+"]
    PATHS = ["secret/data/payments/db", "secret/data/payments/stripe", "secret/data/x/db",
             "secret/data/team-a/q", "secret/data/x", "secret/x", "secret/data/a/b/c",
             "secret/metadata/team/", "secret/metadata/team", "secret/data/org/team-a/k",
             "secret/data/org/team-a/service/k", "kv1/legacy/a", "kv1/legacy/a/b", "kv1/"]
    CAPS = ["read", "list", "create", "update", "delete", "deny"]

    @unittest.skipIf(shutil.which("z3") is None, "z3 CLI not on PATH")
    def test_random_rule_sets_agree(self):
        rng = random.Random(20261023)
        checked = 0
        for _ in range(40):
            k = rng.randint(1, 6)
            acl = rules(*[(rng.choice(self.PATTERNS),
                           rng.sample(self.CAPS, rng.randint(1, 2))) for _ in range(k)])
            for path in self.PATHS:
                for cap in ("read", "list", "update"):
                    want = vs.vault_allows(acl, path, cap)
                    got = vs.smt_vault_allows(acl, path, cap)
                    self.assertEqual(want, got, "acl=%s path=%s cap=%s" % (acl, path, cap))
                    checked += 1
        self.assertGreater(checked, 1000)


EXPECTED = {
    # case name -> (verdict, set of operations that MUST appear among counterexamples)
    "testbed-approle-migrator": ("widens", {"list", "read_metadata"}),
    "testbed-glob-plus-deny": ("subset", set()),
    "testbed-templated": ("subset", set()),
    "demo-ci-payments-reader": ("widens", {"read", "list", "read_metadata"}),
    "demo-finance-batch-job": ("subset", set()),
    "demo-k8s-deployer": ("widens", {"read", "create", "update"}),
    "journey4-n4-readonly": ("widens", {"list", "read_metadata"}),
    "healthscan-scanner": ("subset", set()),
    "constructed-exact-path": ("widens", {"read"}),
    "constructed-metadata-list-only": ("widens", {"read"}),
}


@unittest.skipIf(shutil.which("z3") is None, "z3 CLI not on PATH")
class RealCasesTest(unittest.TestCase):
    def test_every_case_has_an_expectation(self):
        names = sorted(f[:-len(".model.json")] for f in os.listdir(CASES)
                       if f.endswith(".model.json"))
        self.assertEqual(sorted(EXPECTED), names)

    def test_verdicts_and_counterexamples(self):
        for name, (verdict, must_ops) in sorted(EXPECTED.items()):
            with self.subTest(case=name):
                with open(os.path.join(CASES, name + ".model.json")) as f:
                    model = json.load(f)
                res = vs.check_case(model)
                self.assertEqual(verdict, res.verdict)
                self.assertEqual([], res.unknown_parts, "undecided parts")
                ops = {cx["op"] for cx in res.counterexamples}
                self.assertTrue(must_ops <= ops, "missing %s in %s" % (must_ops - ops, ops))
                for cx in res.counterexamples:
                    # Independent re-check of every model the solver produced.
                    self.assertFalse(vs.vault_allows(vs.merge_rules(model["vault_rules"]),
                                                     cx["vault_path"], cx["capability"]), cx)
                    self.assertTrue(vs.keyorix_allows(model, cx["op"], cx["mount"], cx["name"]), cx)

    def test_subset_cases_are_not_vacuous(self):
        # A subset verdict on a case with no grants at all is trivially true; it must say so.
        for name, (verdict, _) in EXPECTED.items():
            if verdict != "subset":
                continue
            with open(os.path.join(CASES, name + ".model.json")) as f:
                model = json.load(f)
            res = vs.check_case(model)
            self.assertEqual(res.vacuous, len(model["grants"]) == 0, name)


@unittest.skipIf(shutil.which("z3") is None, "z3 CLI not on PATH")
class SplitEquivalenceTest(unittest.TestCase):
    """The split encoding (default) must give the monolithic encoding's answers: same
    verdict and same set of widened operations, on the real cases and on small
    synthetic ones (the monolithic query is only tractable at small sizes)."""

    def _same(self, model):
        a = vs.check_case(model, mode="split")
        b = vs.check_case(model, mode="monolithic", timeout_s=120)
        self.assertEqual(b.verdict, a.verdict, model["case"])
        self.assertEqual({c["op"] for c in b.counterexamples}, {c["op"] for c in a.counterexamples},
                         model["case"])

    def test_real_cases(self):
        for name in sorted(EXPECTED):
            with self.subTest(case=name), open(os.path.join(CASES, name + ".model.json")) as f:
                self._same(json.load(f))

    def test_nested_imports(self):
        # secret/ imported into (1,11), but secret/team-b/ separately into (2,21): the
        # longer import owns team-b names, so the (1,11) read grant must not reach them.
        model = {"case": "nested-imports", "kv_mounts": [{"path": "secret/", "kv_version": 2}],
                 "vault_rules": [{"policy": "a", "path": "secret/data/*", "capabilities": ["read"]},
                                 {"policy": "a", "path": "secret/data/team-b/*", "capabilities": ["deny"]}],
                 "imports": [{"mount": "secret/", "path_prefix": "", "project_id": 1, "environment_id": 11},
                             {"mount": "secret/", "path_prefix": "team-b/", "project_id": 2, "environment_id": 21}],
                 "grants": [{"permissions": ["secrets.read"], "project_id": 1, "environment_id": 11,
                             "source_ref": "t"}]}
        self._same(model)
        self.assertNotIn("read", {c["op"] for c in vs.check_case(model).counterexamples})

    def test_small_synthetic(self):
        import scale
        for shape in ("prefix", "plus", "compete"):
            for widen in (False, True):
                with self.subTest(shape=shape, widen=widen):
                    self._same(scale.synth(10, shape, widen))


if __name__ == "__main__":
    unittest.main()
