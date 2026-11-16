# internal/keyfiles invariants

Read this before changing anything in `internal/keyfiles` — the key-set manifest (#2900,
ADR-112): a per-file SHA-256 ledger written by every operation that changes the key set and
verified/reconciled at boot (`VerifyKeySetConsistency`, `ReconcileKeySet`) before the DEK is
loaded. See `manifest.go` and `consistency.go` for the design and trust model (notably:
the manifest is NOT an authenticator — its hashes are unkeyed and detect accidents and
interrupted operations, not an attacker with write access to the key directory).

Format: `INV-KEYFILES-NN <rule>. Why: <source>. Guard: <test> | UNGUARDED (#issue)`.

New invariants go in `INVARIANTS.d/INV-KEYFILES-<kebab-slug>.md` (one per file), not appended
here — see `docs/invariants-fragments.md`.
