- **INV-VAULTSOURCE-walk-conserves-and-reports** `vaultsource.Client.Walk` returns exactly one
  `Entry` per live KV field (non-empty key, non-empty value, duplicate JSON keys collapsed
  last-wins by `encoding/json`), and reports every leaf it will not import — a soft-deleted or
  destroyed KV v2 latest version, an empty-data leaf, an empty value, or an empty field name —
  as a `Skipped` with a reason, never as a silent absence. Why: the migrate importer's whole
  fidelity guarantee rests on "nothing silently dropped, nothing duplicated" — an absent row is
  indistinguishable from a path that never existed, and a soft-deleted secret's data must never
  be resurrected (Andrei's 2026-09-25 decision; `readLeaf`/`read`). Guard: the count-conservation
  leg of `FuzzVaultImportRoundTrip` (migrate/cmd, task MGV1) asserts `len(entries)` equals the
  model's live importable-field count over a generated KV v1/v2 tree (soft-deleted/destroyed/
  empty/duplicate-key/multi-field shapes), and `O-RT6` asserts every soft-deleted/destroyed/
  empty leaf appears in `Skipped`; `TestIntegration_KVv2_RecursiveWalk` pins the same against a
  real Vault.
