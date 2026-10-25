# SMT check: migrated Keyorix grants vs. the Vault policy (R&D spike)

Asks an SMT solver, for one migrated Vault role at a time: *is there any request
(operation, KV mount, secret name) that Keyorix would allow and Vault would deny?*
UNSAT proves the migrated grants are a subset of the Vault policy for **every** secret
name. SAT returns a concrete request that widens access. Design, encoding choices,
results, risks: [docs/design/smt-vault-policy-equivalence.md](../../design/smt-vault-policy-equivalence.md).

Spike status (RD-SMT-SPIKE-1): not wired into `keyorix-migrate` and not run in CI,
except the Go test that keeps the case models in sync with the code.

## Requirements

- `z3` on PATH (`brew install z3`, or `pip install z3-solver`, which ships the binary).
  Optional: `cvc5` (`--solver cvc5`). Python 3 standard library only.
- Go, to regenerate case models.

## Files

| File | What it is |
|---|---|
| `cases/<case>.input.json` | Hand-written: which seeded policies (file + name), KV mounts, Keyorix projects/environments, `--path-map`, and the value-import runs. `constructed: true` marks the two cases not taken from a seeded Vault. |
| `cases/<case>.model.json` | Generated: the Vault rules and the grants `accessplan` proposes. Producer: `migrate/internal/accessplan/smt_model_export_test.go`. |
| `vaultsmt.py` | Encoder (SMT-LIB 2.6, `QF_SLIA`), concrete reference evaluators, solver driver. |
| `check.py` | Runs every case and prints the verdict and witnesses. Also has `--emit`, `--probe` and `--solver`. |
| `test_vaultsmt.py` | Vault semantics, encoding vs. reference (differential), split vs. single-query, expected verdicts. |
| `mutation_check.py` | Plants 8 encoding bugs and requires that the tests catch each one. |
| `scale.py` | Size-limit experiment (synthetic policies, both encodings). Writes a TSV outside the repo. |
| `vault_oracle.py` | Compares the reference evaluator with a running Vault (`sys/capabilities-self`). Needs a throwaway Vault container. |
| `demo.sh` | About a one-minute walkthrough. |

## Commands (repository root)

```sh
docs/formal/smt/demo.sh                                   # the walkthrough
python3 docs/formal/smt/check.py                          # all cases
python3 -m unittest discover -s docs/formal/smt -p 'test_*.py'
python3 docs/formal/smt/mutation_check.py
(cd migrate && GOWORK=off go test ./internal/accessplan -run TestSMTModels -update-smt-models)  # after a mapping/seed change
```

`check.py` exits 0 when every case is decided. A `widens` verdict is a finding, not a
tool error. It exits 1 if any part of a case comes back `unknown` (solver timeout) with
no widening found. That case is undecided, and the tool never reports it as a subset.
