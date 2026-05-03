# ADR-010 — KEK Rotation with Full Re-encryption Sweep

**Status:** Decided (May 2026)
**Author:** Andrei Beshkov
**Replaces:** The undocumented behaviour of `RotateDEK()` which was key proliferation, not rotation.

---

## Context

### The Problem: Key Proliferation

`RotateDEK()` in `keymanager.go` does the following:

1. Generates a new random DEK.
2. Wraps the new DEK with the current KEK.
3. Backs up the old wrapped DEK to `keys/dek.key.backup.<timestamp>`.
4. Writes the new wrapped DEK to `keys/dek.key`.
5. Updates the in-memory `currentDEK` to the new DEK.

This is **not key rotation**. It is **key proliferation**:

- Every `SecretVersion` row in the database was encrypted under the old DEK. After `RotateDEK()`, those rows cannot be decrypted with the new in-memory DEK.
- The server would silently fail to decrypt any existing secret on the next read.
- Old backup DEK files accumulate indefinitely. An attacker who exfiltrated any backup file and knows `KEYORIX_MASTER_PASSWORD` can derive the KEK and unwrap the old DEK — giving them access to secrets encrypted under that generation.

### What Must Happen

True key rotation requires:

1. The old DEK is kept in memory long enough to decrypt all existing ciphertext.
2. Every encrypted row is re-encrypted under the new DEK within a single transaction.
3. Only after all rows are committed does the old DEK leave memory.
4. Old backup files are deleted after a verified successful sweep.

### Scope of Encrypted Data

Three tables carry DEK-encrypted data:

| Table | Column | Encrypted by |
|---|---|---|
| `secret_versions` | `encrypted_value` | `SecretEncryption` / `integration.go` |
| `sessions` | `encrypted_session_token` | `AuthEncryption` |
| `api_tokens` | `encrypted_token` | `AuthEncryption` |
| `api_clients` | `encrypted_client_secret` | `AuthEncryption` |
| `password_resets` | `encrypted_token` | `AuthEncryption` |

`RotateAuthEncryption()` already exists and sweeps sessions, api_tokens, and api_clients. It re-encrypts using the current in-memory DEK — so it works correctly only if called while the old DEK is still in memory, before `currentDEK` is replaced.

There is no equivalent sweep for `secret_versions`.

---

## Decision

### Introduce `RotateDEKWithSweep`

Replace the broken `RotateDEK()` semantics with a new method `RotateDEKWithSweep` in `service.go`. The old `RotateDEK()` is retained but marked deprecated and logs a loud warning.

The new function's invariant: **on success, no row in the database references ciphertext encrypted under the old DEK.**

### Algorithm

```
RotateDEKWithSweep(passphrase, db):
  1. Verify initialization
  2. Read salt from disk
  3. Derive KEK from passphrase + salt (memory, wiped after use)
  4. Generate new random DEK (newDEK)
  5. Wrap newDEK with KEK → store as keys/dek.key.pending
  6. Begin database transaction (tx)
  7.   Re-encrypt all secret_versions rows (old DEK → new DEK)
  8.   Re-encrypt all sessions rows (old DEK → new DEK)
  9.   Re-encrypt all api_tokens rows (old DEK → new DEK)
  10.  Re-encrypt all api_clients rows (old DEK → new DEK)
  11.  Re-encrypt all password_resets rows (old DEK → new DEK)
  12. Commit transaction
  13. On commit success:
       a. Rename keys/dek.key.pending → keys/dek.key (atomic on POSIX)
       b. Wipe old DEK from memory
       c. Replace currentDEK with newDEK
       d. Update keyVersion
       e. Recreate EncryptionService with newDEK
       f. Delete all keys/dek.key.backup.* files
  14. On any error: rollback tx, delete keys/dek.key.pending, keep old DEK active
```

### Secret version re-encryption — AAD handling

Secret versions encrypted under the new AAD scheme (`aad_version: v1`) must be re-encrypted with the correct AAD reconstructed from their row data. The sweep reads `SecretNodeID` and `VersionNumber` from each row and fetches `NamespaceID` from the parent `SecretNode` to rebuild `SecretAAD(secretID, namespaceID, versionNumber)`.

Legacy rows (no `aad_version` in metadata) are decrypted without AAD and re-encrypted **with** AAD — this sweep serves double duty as the M2 legacy re-encryption migration.

### Batch processing

For installations with large numbers of secrets, the sweep processes `secret_versions` in configurable batches (default: 500 rows per batch) within the same transaction. This avoids loading all ciphertext into memory simultaneously. Sessions, api_tokens, api_clients, and password_resets are small tables — no batching required.

### KEK rotation (passphrase change)

Changing `KEYORIX_MASTER_PASSWORD` is a separate concern: new salt + new PBKDF2 derivation → new KEK → re-wrap same DEK with new KEK. This does **not** require a database re-encryption sweep (the DEK is unchanged; only its wrapper changes). Implement as `RotateKEK(oldPassphrase, newPassphrase)` in `keymanager.go`. This ADR covers DEK rotation (the sweep). KEK rotation (passphrase change) is a follow-on item.

### CLI surface

```
keyorix-server key rotate-dek   # triggers RotateDEKWithSweep; requires KEYORIX_MASTER_PASSWORD
keyorix-server key rotate-kek   # future: passphrase change
```

Alternatively exposed as a protected admin API endpoint (operator-only, no user-facing exposure).

---

## Consequences

### Positive

- **True rotation:** after a successful sweep, the old DEK is gone from memory and disk. Old backup files are deleted. The attack window from a previously exfiltrated DEK backup is closed.
- **Legacy AAD migration:** the sweep simultaneously upgrades legacy (no-AAD) rows to AAD-bound rows, completing the M2 migration deferred from ADR-004.
- **Atomicity:** the database transaction ensures the system is never in a split state where some rows are encrypted under the new DEK and some under the old.

### Negative / Trade-offs

- **Downtime:** the sweep holds a long-running write transaction. For large installations, this will block concurrent secret reads/writes for the duration. Acceptable at v0.x scale (hundreds of secrets). Document in operator guide. Hot-swap streaming rotation is a v2 concern.
- **Memory pressure:** batched sweep keeps at most 500 plaintext values in memory at once. Acceptable trade-off between memory pressure and transaction duration.
- **Failure mode:** if the server crashes mid-sweep (after `keys/dek.key.pending` is written but before rename), the pending file is orphaned. Recovery: re-run `key rotate-dek`. The pending file is detected and cleaned up at startup.

### Not in scope for this ADR

- Streaming / hot-swap rotation without downtime (requires version field on every row + dual-key read path — v2)
- KEK rotation (passphrase change) — follow-on item
- Shamir's Secret Sharing for KEK (enterprise, KeyProvider Tier 2)

---

## Implementation Plan

### Files to change

| File | Change |
|---|---|
| `internal/encryption/keymanager.go` | Add `RotateDEKWithSweep` (core algorithm). Mark `RotateDEK` deprecated. Add `GetOldDEKForSweep() []byte` helper (returns copy of current DEK before rotation). |
| `internal/encryption/service.go` | Add `RotateDEKWithSweep(passphrase string, db *gorm.DB) error`. Wire it through from `keymanager`. |
| `internal/encryption/sweep.go` | **New file.** `SweepSecretVersions`, `SweepAuthTokens`. Handles batched re-encryption, AAD reconstruction for secret_versions, and the auth token tables. |
| `internal/cli/system/system.go` | Add `key` subcommand with `rotate-dek` action. |

### Test plan

1. **Unit: `TestRotateDEKWithSweep_ReEncryptsAllRows`** — seed DB with N secret versions + sessions + api tokens, call sweep, verify every row decrypts correctly with new DEK and fails with old DEK.
2. **Unit: `TestRotateDEKWithSweep_UpgradesLegacyAAD`** — seed with legacy (no-AAD) rows, call sweep, verify all rows are now AAD-bound.
3. **Unit: `TestRotateDEKWithSweep_RollbackOnError`** — inject a DB error mid-sweep, verify old DEK remains active and no rows were modified.
4. **Unit: `TestRotateDEKWithSweep_PendingFileCleanup`** — simulate crash after pending file write, verify recovery on re-run.
5. **Integration: `TestRotateDEKWithSweep_EndToEnd`** — full server with real DB, create secrets, rotate, read secrets back. All reads must succeed.

---

## Alternatives Considered

### A: Dual-key read path (hot rotation)

Store `dek_version` in every `SecretVersion` row. Server maintains a map of `version → DEK`. Rotation writes a new DEK and updates new writes to use it. Old rows are lazily re-encrypted on read. No downtime.

**Rejected for now:** Requires a migration to add `dek_version` column to three tables, significantly more complexity in the decryption path, and perpetuates the key proliferation problem during the lazy window. Appropriate when Keyorix has high-traffic customers who cannot accept any write-lock. Revisit at v1.0.

### B: Rotate only secret_versions; invalidate auth tokens

Sessions are short-lived. On DEK rotation, delete all sessions and API tokens (force re-login). Only sweep `secret_versions`.

**Rejected:** Forced re-login is disruptive to CI/CD pipelines that use long-lived API tokens. The existing `RotateAuthEncryption()` already has the machinery — use it correctly rather than sidestep it.

### C: Keep `RotateDEK` as-is; accept key proliferation

**Rejected explicitly.** This is what the backlog item exists to fix. Key proliferation violates the security promise of the product. An enterprise security customer asking about key rotation and receiving an answer that amounts to "we keep all old keys forever" is a sales-blocker.
