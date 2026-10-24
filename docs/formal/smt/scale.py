#!/usr/bin/env python3
"""Size-limit experiment for the subset check (RD-SMT-SPIKE-1).

Generates synthetic but realistically shaped cases with N Vault rules and times the
verdict query (the first query of check_case: the one that decides subset/widens).

Shapes (each N, each shape, a SUBSET instance and a WIDENS instance):
  prefix  - per (project, environment): secret/data/p/e/* and secret/metadata/p/e/*
            allows, plus noise in unrelated projects (exact denies, globs).
  plus    - the same, with the noise as "+"-segment rules
            (secret/data/+/e/shared-k, secret/+/q/k) that compete in priority.
  compete - granted scopes as in prefix, and the other half of the rules are
            higher-priority rules INSIDE those scopes (exact, "+", deeper globs) that are
            all at least as permissive: the hard UNSAT case.
The WIDENS instance adds one exact deny inside one granted scope.

Usage:
    python3 docs/formal/smt/scale.py OUT.tsv [N ...]   (default N: 10 30 100 300 1000 3000)

Each instance is checked with the split encoding (the full check: verdict plus one
witness per widened op) and with the monolithic encoding (verdict query only, stopped
for larger N once it first times out). Env: SCALE_TIMEOUT_S (split, default 600),
SCALE_MONO_TIMEOUT_S (monolithic, default 120).

Writes one TSV row per run. Numbers are machine-specific: they stay out of the
repository docs.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import vaultsmt as vs  # noqa: E402

CAPSETS = [["read", "list"], ["read", "list", "create", "update"],
           ["read", "list", "create", "update", "delete"]]
PERMS = {0: ["secrets.read"], 1: ["secrets.read", "secrets.write"],
         2: ["secrets.delete", "secrets.read", "secrets.write"]}


def synth(n_rules, shape, widen):
    rules, grants, imports = [], [], []
    granted = max(1, n_rules // 4)  # ~half the rules back grants, half are noise
    for i in range(granted):
        proj, env = i // 3 + 1, i % 3 + 1
        pre = "p%d/e%d/" % (proj, env)
        k = i % 3
        rules.append({"policy": "g", "path": "secret/data/%s*" % pre, "capabilities": CAPSETS[k]})
        rules.append({"policy": "g", "path": "secret/metadata/%s*" % pre, "capabilities": ["read", "list"]})
        imports.append({"mount": "secret/", "path_prefix": pre, "project_id": proj,
                        "environment_id": proj * 10 + env})
        grants.append({"permissions": PERMS[k], "project_id": proj, "environment_id": proj * 10 + env,
                       "source_ref": "synthetic"})
    q = 0
    while len(rules) < n_rules:
        q += 1
        if shape == "plus":
            noise = [("secret/data/+/e%d/shared-%d" % (q % 3 + 1, q), ["deny"]),
                     ("secret/+/q%d/k%d" % (q, q), ["read"])]
        else:
            noise = [("secret/data/q%d/x%d" % (q, q), ["deny"]), ("secret/data/q%d/*" % q, ["read", "list"])]
        if shape == "compete":
            break
        for path, caps in noise:
            if len(rules) < n_rules:
                rules.append({"policy": "noise", "path": path, "capabilities": caps})
    if shape == "compete":
        # Higher-priority rules INSIDE the granted scopes, all at least as permissive as the
        # scope glob: the subset proof must visit every region they carve out.
        c = 0
        while len(rules) < n_rules:
            i = c % granted
            pre = "p%d/e%d/" % (i // 3 + 1, i % 3 + 1)
            for path in ("secret/data/%ss%d" % (pre, c), "secret/data/%s+/k%d" % (pre, c),
                         "secret/data/%sd%d/*" % (pre, c)):
                rules.append({"policy": "compete", "path": path, "capabilities": CAPSETS[2]})
            c += 1
        rules = rules[:n_rules] if len(rules) > n_rules else rules
    if widen:
        target = "secret/data/p1/e1/s0" if shape == "compete" else "secret/data/p1/e1/locked"
        rules = [r for r in rules if r["path"] != target]
        rules.append({"policy": "deny", "path": target, "capabilities": ["deny"]})
    return {"case": "scale-%s-%d" % (shape, n_rules), "kv_mounts": [{"path": "secret/", "kv_version": 2}],
            "vault_rules": rules, "imports": imports, "grants": grants}


def main(argv):
    if not argv:
        raise SystemExit(__doc__)
    out = argv[0]
    sizes = [int(x) for x in argv[1:]] or [10, 30, 100, 300, 1000, 3000]
    split_timeout = int(os.environ.get("SCALE_TIMEOUT_S", "600"))
    mono_timeout = int(os.environ.get("SCALE_MONO_TIMEOUT_S", "120"))
    cols = ["mode", "shape", "variant", "rules", "grants", "imports", "smt_bytes", "verdict",
            "seconds", "queries", "max_part_s", "max_part_rules"]
    with open(out, "w") as f:
        f.write("\t".join(cols) + "\n")
        for shape in ("prefix", "plus", "compete"):
            mono_dead = set()
            for n in sizes:
                for widen in (False, True):
                    model = synth(n, shape, widen)
                    want = "widens" if widen else "subset"
                    rows = []
                    # split: the full check (verdict + one witness per widened op)
                    r = vs.check_case(model, timeout_s=split_timeout)
                    rows.append(["split", r.verdict, r.total_s, r.queries, r.max_part_s, r.max_part_rules,
                                 r.smt_bytes])
                    # monolithic: the verdict query alone, until it first times out
                    if widen not in mono_dead:
                        smt = vs.emit_case(model)
                        st, _, wall = vs.run_solver(smt, timeout_s=mono_timeout)
                        verdict = {"sat": "widens", "unsat": "subset"}.get(st, "unknown")
                        rows.append(["monolithic", verdict, wall, 1, wall, len(model["vault_rules"]), len(smt)])
                        if verdict == "unknown":
                            mono_dead.add(widen)
                    for mode, verdict, secs, q, mp, mpr, nbytes in rows:
                        row = [mode, shape, want, len(model["vault_rules"]), len(model["grants"]),
                               len(model["imports"]), nbytes, verdict, "%.3f" % secs, q, "%.3f" % mp, mpr]
                        f.write("\t".join(str(x) for x in row) + "\n")
                        f.flush()
                        print("\t".join(str(x) for x in row), file=sys.stderr)
                        if verdict not in (want, "unknown"):
                            raise SystemExit("generator or encoding bug: %s %s expected %s, got %s"
                                             % (mode, model["case"], want, verdict))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
