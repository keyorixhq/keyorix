# Formal models

TLA+ models of Keyorix protocols, checked with TLC, and SMT-LIB models checked with z3 or cvc5. They are R&D artefacts:
not run by CI, and each model's README says what it covers and what it does not.

| Model | What | Run |
|---|---|---|
| [`owed-audit/`](owed-audit/README.md) | revocations, grants, the mixed-request split, break-glass and the owed-audit backfill while the audit log refuses writes (ADR-112 Amendment 6) | `docs/formal/owed-audit/run-tlc.sh` |
| [`rd-aat-smt/`](rd-aat-smt/README.md) | SMT-LIB (z3/cvc5) soundness of the AAT draft-02 I4 rules: core subsumption table, `all`/`any` matching, constraint-map key rules with the published `"*"` carve-out; each rule shown load-bearing (ADR-120) | `python3 docs/formal/rd-aat-smt/run.py` |
