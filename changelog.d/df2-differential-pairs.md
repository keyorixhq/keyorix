### Testing
- **Added `FuzzYAMLV4Differential` (`internal/libconformance`), a differential fuzz target
  over the YAML v3→v4 major rewrite** (`go.yaml.in/yaml/v3` v3.0.5 vs `go.yaml.in/yaml/v4`
  v4.0.0). Three oracles on the same input: bounded-work (resguard alloc/malloc absolute
  ceiling), accept/reject parity, and decoded-value equality, each gated by a committed
  `EXPECTED-DIFFERENCES-yaml-v3-v4-differential.md` table with red/green proofs
  (`TestYAMLV4DifferentialRedGreen`). Complements `FuzzYAMLSiblingDifferential`, which covers
  only the v3.0.1↔v3.0.5 patch gap. The run found one divergence (`nonspecific-tag-empty-scalar`:
  the non-specific tag `!` on an empty scalar resolves to `null` in v3 but the empty string in
  v4) — a deliberate, more-spec-aligned v4 change, documented as a forward-looking migration
  hazard (v4 has no live Keyorix caller today). Enforced by
  `INV-LIBCONF-yaml-v4-differential`.
