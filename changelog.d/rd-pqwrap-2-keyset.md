### Internal
- **Keyset key-file codec for hybrid post-quantum key wrapping (RD-PQWRAP-2).** `internal/pqwrap`
  now has the self-describing keyset that will replace the bare 60-byte `dek.key`
  (docs/design/pq-key-wrapping.md §7): a KEK slot plus optional X25519 + ML-KEM-1024 recipient
  slots, authenticated at boot by a KEK-derived keyset MAC and a DEK key-check value, so a
  key-directory writer holding only recipient public keys cannot substitute the DEK. The legacy-60
  reader is kept indefinitely and guarded by frozen fixtures. Nothing writes the new format yet:
  key files on disk are unchanged by this release.
