### Internal
- **Added `tools/oraclehealth`, a stdlib-only fuzz-oracle health harness.** It plants
  small AST mutants (comparison flips, condition negation, dropped error guards,
  moved bound constants, swapped boolean logic, skipped constant-time compares) in the
  code a Go fuzz target exercises, runs the target against each mutant in an isolated
  module copy, and reports KILLED / SURVIVED so a weak oracle is visible instead of
  assumed. Keyorix-import-free, so it runs on any Go module checkout; carries its own
  committed red/green self-proof (`TestOracleHealth_RedProof`). Dev tooling only — no
  production or runtime change.

### Testing
- **Audited five security fuzz oracles with `oraclehealth`** (PAT restriction algebra,
  AEAD tamper, SSRF encoding-parity, backup-archive path safety, bundle path
  containment). Every survivor was explained as an equivalent/defense-in-depth mutant,
  a property the target intentionally does not assert, or one covered by a sibling
  target or unit test — no unguarded defect found. Full write-up archived with the run
  artefacts; no test behaviour was changed.
