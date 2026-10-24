#!/usr/bin/env python3
"""Check "Keyorix grants are a subset of the Vault policy" for each case model.

Usage (repository root):
    python3 docs/formal/smt/check.py                    # every docs/formal/smt/cases/*.model.json
    python3 docs/formal/smt/check.py CASE.model.json    # selected cases
    python3 docs/formal/smt/check.py --json OUT.json    # also write machine-readable results
    python3 docs/formal/smt/check.py --emit CASE.model.json  # print the SMT-LIB text only
    python3 docs/formal/smt/check.py --solver cvc5      # same SMT-LIB, cvc5 instead of z3
    python3 docs/formal/smt/check.py --probe CASE.model.json OP MOUNT NAME  # one concrete request

Prints one line per case (verdict, solver time) and one line per counterexample.
Exit status: 0 when every case is decided (subset or widens), 1 on solver "unknown",
2 on a usage or solver error. A "widens" verdict is a finding, not a tool failure.
"""

import glob
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import vaultsmt as vs  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))


def main(argv):
    args = list(argv)
    out_json = None
    if "--emit" in args:
        args.remove("--emit")
        for path in args:
            sys.stdout.write(vs.emit_case(vs.load(path)))
        return 0
    if "--probe" in args:
        # --probe CASE.model.json OP MOUNT NAME: both concrete evaluators on one request.
        i = args.index("--probe")
        path, op, mount, name = args[i + 1:i + 5]
        model = vs.load(path)
        ver = next(m["kv_version"] for m in model["kv_mounts"] if m["path"] == mount)
        vpath, cap = vs.vault_request(ver, mount, op, name)
        v = vs.vault_allows(vs.merge_rules(model["vault_rules"]), vpath, cap)
        k = vs.keyorix_allows(model, op, mount, name)
        print("%s %s%s: Vault %s %s on %s; Keyorix %s (%s)%s"
              % (op, mount, name, "allows" if v else "denies", cap, vpath,
                 "allows" if k else "denies", vs.KEYORIX_PERM[op],
                 "  <- WIDENS" if k and not v else ""))
        return 0
    solver = "z3"
    if "--solver" in args:
        i = args.index("--solver")
        solver = args[i + 1]
        del args[i:i + 2]
    if "--json" in args:
        i = args.index("--json")
        out_json = args[i + 1]
        del args[i:i + 2]
    paths = args or sorted(glob.glob(os.path.join(HERE, "cases", "*.model.json")))
    if not paths:
        print("no case models found", file=sys.stderr)
        return 2
    print("checking %d case(s) with %s; each counterexample is re-checked concretely" % (len(paths), solver),
          file=sys.stderr)
    results, undecided = [], 0
    for path in paths:
        model = vs.load(path)
        try:
            res = vs.check_case(model, solver=solver)
        except vs.SolverError as e:
            print("%s: solver error: %s" % (path, e), file=sys.stderr)
            return 2
        acl = vs.merge_rules(model["vault_rules"])
        for cx in res.counterexamples:
            if vs.vault_allows(acl, cx["vault_path"], cx["capability"]) or \
                    not vs.keyorix_allows(model, cx["op"], cx["mount"], cx["name"]):
                print("%s: counterexample failed the concrete re-check: %s" % (path, cx), file=sys.stderr)
                return 2
        tag = " (vacuous: no grants proposed)" if res.vacuous and res.verdict == "subset" else ""
        kind = "constructed" if model.get("constructed") else "real"
        print("%-32s %-11s %-7s rules=%-3d grants=%-2d first=%.3fs total=%.3fs queries=%d%s"
              % (model["case"], kind, res.verdict, len(model["vault_rules"]), len(model["grants"]),
                 res.first_query_s, res.total_s, res.queries, tag))
        for cx in res.counterexamples:
            print("    widens: " + vs.explain(cx))
        for mount, op, pre in res.unknown_parts:
            print("    UNDECIDED (solver timeout): %s on %s%s*" % (op, mount, pre))
        undecided += res.verdict == "unknown" or bool(res.unknown_parts)
        results.append({"case": model["case"], "constructed": bool(model.get("constructed")),
                        "verdict": res.verdict, "vacuous": res.vacuous,
                        "rules": len(model["vault_rules"]), "grants": len(model["grants"]),
                        "first_query_s": res.first_query_s, "total_s": res.total_s,
                        "queries": res.queries, "smt_bytes": res.smt_bytes,
                        "unknown_parts": res.unknown_parts,
                        "counterexamples": res.counterexamples})
    if out_json:
        with open(out_json, "w") as f:
            json.dump(results, f, indent=2)
    print("done: %d case(s), %d widen, %d subset, %d unknown"
          % (len(results), sum(r["verdict"] == "widens" for r in results),
             sum(r["verdict"] == "subset" for r in results), undecided), file=sys.stderr)
    return 1 if undecided else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
