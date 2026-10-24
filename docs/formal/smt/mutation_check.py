#!/usr/bin/env python3
"""Mutation check for the SMT encoding (RD-SMT-SPIKE-1).

Plants one encoding bug at a time (in memory, the source is never edited) and runs the
differential and real-case tests against it. Each mutant must make at least one test
fail; a mutant that survives means the tests do not cover what the encoding claims.

    python3 docs/formal/smt/mutation_check.py
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_vaultsmt  # noqa: E402
import vaultsmt as vs  # noqa: E402


def _reverse_priority():
    orig = vs.smt_vault_allow

    def mutant(acl, p, cap):
        saved = vs.ordered_rules
        vs.ordered_rules = lambda a: (saved(a)[0], list(reversed(saved(a)[1])))
        try:
            return orig(acl, p, cap)
        finally:
            vs.ordered_rules = saved
    vs.smt_vault_allow = mutant
    return lambda: setattr(vs, "smt_vault_allow", orig)


def _plus_crosses_slash():
    orig = vs.SEG
    vs.SEG = "re.allchar"
    return lambda: setattr(vs, "SEG", orig)


def _deny_ignored():
    # A deny rule treated as "no match", so the next-priority rule decides. (Stripping the
    # word "deny" alone is an equivalent mutant: a merged deny rule has no other caps.)
    orig = vs.smt_vault_allow

    def mutant(acl, p, cap):
        return orig([r for r in acl if "deny" not in r["caps"]], p, cap)
    vs.smt_vault_allow = mutant
    return lambda: setattr(vs, "smt_vault_allow", orig)


def _no_list_trailing_slash():
    orig = vs.smt_vault_allow

    def mutant(acl, p, cap):
        out = orig(acl, p, cap)
        return out.replace('/"))', '"))')  # list "foo/" no longer matches exact "foo"
    vs.smt_vault_allow = mutant
    return lambda: setattr(vs, "smt_vault_allow", orig)


def _metadata_is_data():
    orig = vs.emit_part

    def mutant(*a, **kw):
        out = orig(*a, **kw)
        return out and (out[0].replace('"metadata/"', '"data/"'), out[1])
    vs.emit_part = mutant
    return lambda: setattr(vs, "emit_part", orig)


def _env_zero_ignored():
    orig = vs._keyorix_allows_in_scope

    def mutant(model, op, proj, env):
        m = dict(model, grants=[g for g in model["grants"] if g["environment_id"] != 0])
        return orig(m, op, proj, env)
    vs._keyorix_allows_in_scope = mutant
    return lambda: setattr(vs, "_keyorix_allows_in_scope", orig)


def _slice_too_aggressive():
    # Rule slicing that also drops rules whose head is a PREFIX of the part's head
    # (e.g. secret/data/* for part secret/data/p1/e1/): unsound.
    orig = vs._compatible
    vs._compatible = lambda a, b: a.startswith(b)
    return lambda: setattr(vs, "_compatible", orig)


def _longer_import_not_excluded():
    orig = vs.emit_part

    def mutant(*a, **kw):
        out = orig(*a, **kw)
        if not out:
            return out
        lines = [ln for ln in out[0].split("\n") if not ln.startswith("(assert (not (str.prefixof")]
        return "\n".join(lines), out[1]
    vs.emit_part = mutant
    return lambda: setattr(vs, "emit_part", orig)


MUTANTS = [("glob priority order reversed", _reverse_priority),
           ("'+' matches across '/'", _plus_crosses_slash),
           ("deny ignored", _deny_ignored),
           ("list 'foo/' vs exact 'foo' dropped", _no_list_trailing_slash),
           ("KV v2 metadata/ paths treated as data/", _metadata_is_data),
           ("environment-0 grants dropped", _env_zero_ignored),
           ("rule slicing drops a matching rule", _slice_too_aggressive),
           ("longer import not excluded from a part", _longer_import_not_excluded)]


def main():
    survived = 0
    loader = unittest.TestLoader()
    for name, plant in MUTANTS:
        undo = plant()
        try:
            suite = unittest.TestSuite([loader.loadTestsFromTestCase(test_vaultsmt.EncodingDifferentialTest),
                                        loader.loadTestsFromTestCase(test_vaultsmt.RealCasesTest),
                                        loader.loadTestsFromTestCase(test_vaultsmt.SplitEquivalenceTest)])
            res = unittest.TextTestRunner(stream=open(os.devnull, "w"), verbosity=0).run(suite)
        finally:
            undo()
        killed = not res.wasSuccessful()
        survived += not killed
        print("%-40s %s" % (name, "killed" if killed else "SURVIVED"))
    print("%d/%d mutants killed" % (len(MUTANTS) - survived, len(MUTANTS)))
    return 1 if survived else 0


if __name__ == "__main__":
    sys.exit(main())
