#!/usr/bin/env bash
# RD-SMT-SPIKE-1 demo (about 1 minute; needs Go and the z3 CLI, cvc5 optional).
# Proves or refutes "Keyorix grants are a subset of the Vault policy" for real seeded
# Vault policies, and shows a migration that widens access.
#
#   docs/formal/smt/demo.sh        (from the repository root)
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
SMT="${ROOT}/docs/formal/smt"
step() { printf '\n\033[1m▶ %s\033[0m\n' "$*" >&2; }

command -v z3 >/dev/null || { echo "z3 not found: brew install z3 (or pip install z3-solver)" >&2; exit 2; }

step "1/5  Derive each case from the real code: policies from the seed scripts, grants from accessplan"
(cd "${ROOT}/migrate" && GOWORK=off GOFLAGS= go test ./internal/accessplan -run TestSMTModels -count=1)
echo "models up to date: $(ls "${SMT}"/cases/*.model.json | wc -l | tr -d ' ') cases" >&2

step "2/5  What one question looks like in SMT-LIB (the demo's ci-payments-reader, first lines)"
python3 "${SMT}/check.py" --emit "${SMT}/cases/demo-ci-payments-reader.model.json" | head -12

step "3/5  Ask z3 every case: subset (proved for ALL secret names) or widens (with a witness)"
python3 "${SMT}/check.py"

step "4/5  The witness on the demo's own data: ci-payments-reader may read only secret/data/payments/*"
python3 "${SMT}/check.py" --probe "${SMT}/cases/demo-ci-payments-reader.model.json" read secret/ payments/stripe
python3 "${SMT}/check.py" --probe "${SMT}/cases/demo-ci-payments-reader.model.json" read secret/ mobile-app/firebase
python3 "${SMT}/check.py" --probe "${SMT}/cases/demo-k8s-deployer.model.json" update secret/ payments/db

step "5/5  Same SMT-LIB, second solver (if cvc5 is on PATH)"
if command -v cvc5 >/dev/null; then
  python3 "${SMT}/check.py" --solver cvc5 2>&1 | grep -v '^    widens'
else
  echo "cvc5 not on PATH: skipped (the files are plain SMT-LIB 2.6, QF_SLIA)" >&2
fi
echo "done" >&2
