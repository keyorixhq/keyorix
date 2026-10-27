- **INV-PQWRAP-legacy-60-readable-forever** `OpenKeyFile` opens every legacy-60 `dek.key`
  (nonce ‖ AES-256-GCM(KEK, DEK) ‖ tag, no AAD) written by an older binary, to the same DEK,
  for as long as Keyorix exists. Every committed fixture under `testdata/legacy-60/` is pinned
  by its SHA-256 and must keep loading; fixtures are never edited or regenerated, only added.
  `SealLegacy` writes the same layout for `rewrap --to legacy` and drops every hybrid slot by
  construction. Why: pq-key-wrapping.md §13, Q9 (keep the legacy reader indefinitely). Guard:
  `TestLegacyKeyFileFixtures_StillLoad` (fails if a fixture stops loading, changes, or the set
  is empty), `TestSealLegacy_RoundTrip`, `TestFIPS140OnlyMode` (legacy read/write in the child).
<!-- section: Legacy reader -->
