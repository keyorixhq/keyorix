# Design: offline backup and restore (ADR-108 §B3)

**Status:** Draft for review
**Scope:** `keyorix-server admin backup` and `keyorix-server admin restore` —
a consistent, backend-neutral, confidentiality-preserving, integrity-verified
full-state export/import of a Keyorix database, run without a live server
attached to the target. Plugs into the `server/admin` framework
(`internal/serverguard`, PR 11) the same way `admin verify-audit`
(design-b4) and `admin recover-admin` (design-b2) do.

ADR-108 decision 3 scopes two more capabilities onto this **same**
mechanism, not separate tooling: *"version-skipping upgrades (air-gapped
customers)"* and *"the SQLite → PostgreSQL move."* §8 below explains why
both fall out of `admin backup`/`admin restore` for free, with no dedicated
code, once the format is backend-neutral and schema-tolerant by
construction. A full KEK re-encryption sweep (also named in that ADR bullet)
is explicitly **out of scope** here — it operates on a live, already-decrypted
DEK in place (`internal/encryptionops`'s existing rotate/rewrap machinery)
and has nothing to do with exporting or importing row data.

## 1. Why this exists, and what it is not

Nothing in this repo does this today. The Step 0 inventory for the
TRACK OFFLINE-FUZZ program searched for `internal/backup`, any
`Backup`/`Restore`/`Snapshot`/`ExportState` function shaped like a
full-state export, and found none — what exists under those names is
unrelated (`internal/encryptionops.RestoreBackup` restores a same-host
leftover wrapped-DEK file after a failed key-provider migration;
`internal/cli/secret/recycle.go`'s `restore` un-deletes a single
soft-deleted secret). A regulated, air-gapped customer has no supported way
to take their whole system offline, hold a portable artifact of it, and
reconstitute it later or elsewhere. This design is that mechanism.

What this is **not**:

- **Not a live/hot backup.** §6 picks an exclusive lock over a live
  snapshot; the server cannot be running against the source (backup) or
  target (restore) database while this runs. ADR-108 already frames these as
  "operations that need the database to themselves" — the availability cost
  is accepted by that decision, not introduced here.
- **Not partial or selective.** v1 backs up everything or nothing — no
  per-project, per-table, or time-range export. §12 Q7 asks whether that
  should change.
- **Not a KEK rotation tool.** Confidentiality (§4) requires the *same*
  passphrase/KMS access at restore time as at backup time; it does not
  re-encrypt anything.
- **Not a replication or HA mechanism.** It produces one artifact at one
  point in time, verified once at restore. It is not a substitute for
  streaming replication or a hot standby.

## 2. Threat model

| Actor / scenario | Can they compromise confidentiality or integrity? | Why / mitigation |
|---|---|---|
| Someone steals the backup file | No secret plaintext | Secret values are copied ciphertext-verbatim (§4); the DEK travels only *wrapped* under the KEK — stealing the file alone reveals nothing decryptable. |
| Someone steals the backup file **and** the passphrase/KMS access | Yes, fully | Same trust boundary as the live system today: whoever can unwrap the KEK there can already read everything. This design does not, and cannot, improve on that — stated explicitly, not silently assumed. |
| Backup file tampered (any single byte, anywhere) | Detected, restore refuses | Manifest carries a signed per-table hash + row count (§5); restore recomputes and compares before touching the target. |
| Backup file truncated (mid-row, mid-table, or before the trailing manifest) | Detected, restore refuses, nothing loaded | The manifest is a trailer (§3); a truncated stream never produces one. Each table section also declares its own row count, so truncation is caught at the section boundary too, not only at EOF. |
| An older, validly-signed backup is restored in place of a newer one (rollback / replay) | **Not detected by signature alone** — only if an external anchor is supplied | A validly-signed old backup is, in isolation, indistinguishable from an intentional "restore to an earlier point in time," which is a legitimate DR action. §9 explains the opt-in anchor-based defense, mirroring design-b4's own "no anchor ⇒ can't rule out truncation" honesty. |
| Wrong passphrase / no KMS access supplied at restore | Detected, restore refuses before touching the target | DEK-unwrap is a decrypt probe (§4) and the manifest signature check (§5) both depend on the correct KEK; a wrong key fails both independently. |
| Backup taken from a newer schema epoch than the restoring binary | Detected, restore refuses | Manifest carries `schema_epoch`; restore reuses `checkSchemaEpoch`'s exact refusal logic (`internal/storage/factory.go:536`). |
| Restore target already has data | Detected, restore refuses | §7's empty-target check. |
| A host admin holding both the target database and its KEK | Can fabricate a fully self-consistent, validly-signed backup | Same caveat design-b4 states for its own trust model (`Result.NotProven`) — this design does not attempt to close it, and says so. |

## 3. Format: backend-neutral logical export

**Why not a raw SQLite file copy or `pg_dump`:** neither is restorable onto
the other backend, and §8's SQLite↔Postgres move requires exactly that. The
format instead is a **logical export**: rows read through the same
backend-neutral `storage.Storage` interface
(`internal/core/storage/interface.go:23`) both `createLocalStorage` and
`createPostgresStorage` already implement identically
(`internal/storage/factory.go:404`, both end in `store.NewLocalStorage(db)`
over a dialect-only-different `*gorm.DB`). A row read from SQLite and a row
read from Postgres are the same Go struct; the export format never needs to
know which backend produced or will consume it.

**Container shape**, in write order:

1. A fixed magic string + format version (e.g. `KYXBKP1\n`), so a corrupt or
   foreign file is rejected in the first few bytes, before any parsing.
2. A sequence of per-table sections, one per GORM model in
   `internal/storage/models`, each: table name, declared row count, then
   that many NDJSON lines (one JSON object per row, field names matching the
   model's own JSON tags). Rows are streamed via the same keyset-pagination
   idiom `internal/auditverify.DB.StreamAuditEvents` already uses (bounded
   batches by primary key, never a whole table buffered in memory).
3. A trailing **signed manifest** (§5) — written last because its per-table
   hashes can only be known once each table has actually streamed past.

**Section order is FK-safe and derived, not hand-maintained.** The model
package has on the order of 90 structs; hand-authoring and maintaining a
topological order for all of them is exactly the kind of artifact that rots
silently as models are added (CLAUDE.md's own core principle). The order
must instead be computed from GORM's own relationship metadata
(`*gorm.Statement.Schema.Relationships`) at backup time, and the file's own
physical section order **is** the load order restore replays — no separate
ordering table to keep in sync. A few concrete constraints this ordering
must satisfy, confirmed from the model inventory: `Project` before
`Environment`/`ProjectMembership`/`ConnectorProjectBinding`; `User`/`Role`/
`Group` before their join tables (`UserRole`, `GroupRole`, `UserGroup`);
`SecretNode` before `SecretVersion`/`SecretACL`/`SecretDependency`/tags;
`MachineIdentity` before its credentials/roles/OIDC bindings; `AuditEvent`
in strict ascending-`id` order, with `AuditCheckpoint` after the range of
events it certifies (a sequencing constraint, not just a foreign key).

**Streaming is asymmetric between backup and restore, deliberately.**
Backup is single-pass and can write directly to stdout, a pipe, or object
storage — it never needs to look backward. Restore, per §5's "verified
before touching anything" requirement, cannot: verifying the trailing
manifest requires having seen the whole file, but no row may be applied
until that verification passes. Restore is therefore a **two-pass operation
over a local, seekable file**: pass 1 reads to the end, recomputes every
table's hash, and verifies the manifest signature and schema epoch, without
creating or touching the target database at all; pass 2 (only entered if
pass 1 passed) replays the same file into the target. This means `admin
restore` requires its input already landed as a regular file — it cannot
consume a live, non-seekable stream. Flagged as §12 Q1 for confirmation.

## 4. Confidentiality

Secret **values** are already ciphertext at rest, AES-256-GCM under a DEK
(`internal/encryption/encryption.go:37`, `EncryptionService`). Backup copies
those ciphertext bytes verbatim and never decrypts them — the backup file,
by construction, never contains plaintext secret material, the same way the
live database never does.

The DEK itself is generated randomly and only ever exists **wrapped** under
a KEK (`wrapKey`/`unwrapKey`, `internal/encryption/keymanager_lifecycle.go:
454,471`). The KEK comes from a pluggable `crypto.KeyProvider`
(`internal/crypto/keyprovider.go:21`): a passphrase (PBKDF2-HMAC-SHA256,
600,000 iterations, `internal/crypto/password_provider.go:34`, keyed by a
32-byte salt), a KMS provider (AWS/GCP/Azure, envelope-wrapping the KEK via
`KMSClient.Encrypt`/`Decrypt`, `internal/crypto/kms_provider.go:33`), or
several other provider shapes (file/env/exec/Shamir/TPM).

**Restoring onto a different host needs a portable copy of this wrapped
material — and no such export exists today.** The wrapped DEK and salt (or
KMS-wrapped-key blob) live only as files on the source host
(`config.EncryptionConfig.DEKPath`/`SaltPath`, `internal/config/config.go:
623`; `WrappedKeyPath`, `kms_provider.go:94`). The one existing "backup" of
this material, `internal/encryptionops/migrate_provider.go`'s
`MigrateProviderWithConfig` (lines 161–240), is a same-host, same-format
crash-safety copy taken immediately before an in-place re-wrap, verified by
a decrypt probe and restored on failure (`RestoreBackup`, line 285) — it
never bundles the salt and never crosses machines or passphrases. This
design adds the missing piece: the backup manifest's `encryption` section
carries the same on-disk bytes (wrapped DEK, salt if password-provider,
wrapped-KEK blob if KMS-provider) plus the provider type and key version,
relocated into the portable container rather than reinvented. No new wrap
format — this is new *plumbing*, not new cryptography.

At restore time, the operator supplies the same passphrase (or has
equivalent KMS access) as the source. `admin restore` derives the KEK,
attempts to unwrap the DEK from the manifest's bundled material, and runs a
decrypt probe (mirroring `migrate_provider.go`'s own pattern) — all in pass
1 (§3), before the target database is touched. A wrong passphrase or
missing KMS access fails cleanly here, not partway through a load.

**Same-host, in-place restore does not need the manifest's copy at all** —
the original `dek.key`/`salt` files are already present locally, and
ciphertext lines back up against them unchanged. The portable bundle exists
for the cross-host case: disaster recovery onto a fresh machine, and the
SQLite→Postgres move (§8), where the target has never had the source's
wrapped material.

## 5. Integrity: signed manifest

The manifest is a JSON object at the end of the file (§3), and its
signature must be checkable by an operator who supplied the right
passphrase/KMS access and nothing else — the same read-only, no-shared-state
posture design-b4 established for the audit-checkpoint HMAC. This design
mints a **new** KEK-derived signing key via the same HKDF-SHA256 shape
`deriveAuditCheckpointKey` already uses
(`internal/encryption/keymanager_lifecycle.go:148`) — over the KEK, not the
DEK, so it survives DEK rotation — but with its **own** domain-separation
string (e.g. `"keyorix-backup-manifest-kek-v1"`), never the literal
audit-checkpoint key. Reusing one derived key across two independent
signature protocols (audit checkpoints vs. backup manifests) is the kind of
cross-protocol key reuse worth avoiding on principle, not because a concrete
attack is known.

**Manifest contents:**

- `format_version`, `schema_epoch` (compared against `currentSchemaEpoch`,
  `internal/storage/factory.go:41`, using the exact refusal logic
  `checkSchemaEpoch` already implements — a newer-than-this-binary backup is
  refused with the same reasoning ADR-097/101 already established for a
  newer-than-this-binary *database*).
- Per table: `{name, row_count, sha256}` — the hash is over the exact NDJSON
  bytes written for that table, in the primary-key-ascending order backup
  read them; restore recomputes it over the bytes it reads back, in the same
  order, with no re-sorting on either side.
- `audit_chain: {head_id, head_hash, chained_events}` and
  `latest_checkpoint: {id, chained_events, head_id, head_hash, key_version,
  signature}` — the latter in the *same* JSON shape as
  `auditverify.ExternalAnchorBundle` (`internal/auditverify/
  anchor_bundle.go:20`), so a backup's own manifest can be handed directly
  to `admin verify-audit --anchor` as an external anchor with zero
  translation. Reuse, not a parallel schema.
- `encryption: {provider_type, key_version, wrapped_dek, salt?,
  wrapped_kek_blob?}` (§4).
- `generated_at`, `generator_version` (server build version).
- `manifest_signature`: HMAC-SHA256 over the canonical manifest bytes
  *excluding* this field, under the key above.

**Verification order at restore (all of pass 1, §3, before pass 2 exists):**

1. Magic bytes + format version.
2. `schema_epoch` vs. `currentSchemaEpoch` — refuse if the backup is newer.
3. Full re-walk: recompute every table's row count and hash from the bytes
   actually present, compare against the manifest's claims.
4. DEK-unwrap decrypt probe (§4) under the operator-supplied key material.
5. `manifest_signature` verification under the same KEK-derived key.

Steps 4 and 5 both depend on the operator's passphrase/KMS input but through
independent code paths (AES-GCM decrypt vs. HMAC compare) — a wrong key
fails both, giving defense in depth rather than one shared failure mode.
Only if every step above passes does pass 2 begin.

## 6. Consistency: `serverguard` exclusive lock, not a read snapshot

**Decision: `admin backup` and `admin restore` both hold
`internal/serverguard.AcquireExclusive` for their entire run**, via the same
`acquireDatabaseLock` helper (`server/admin/admin.go:128`) every other admin
command (`migrate`, `verify-audit`, `encryption *`, `recover-admin`) already
uses — backup locks the source database, restore locks the (empty) target.

A single read-snapshot transaction was the alternative considered and
rejected. Two reasons:

1. **A snapshot isolates the reader's view; it does not stop a live server
   from writing.** SQLite `BEGIN DEFERRED` or Postgres `REPEATABLE READ`
   guarantees *this transaction* sees a consistent point-in-time view, but a
   concurrently-running server can still write outside it. For a
   single-table read that is fine; for a multi-table streaming backup that
   reads `audit_checkpoints` and `audit_events` as *separate* statements
   (§3's streaming design, not one giant transaction), a concurrent
   checkpoint write between those two reads could pick a checkpoint that
   does not yet cover every event row the same run captured — an ordering
   hazard a snapshot alone does not close unless the entire backup runs
   inside one transaction, which trades this problem for long-running-
   transaction/lock-bloat costs on Postgres.
2. **`serverguard` already works identically on both backends** — SQLite via
   non-blocking `flock(2)` on a sidecar lock file, Postgres via non-blocking
   `pg_try_advisory_lock` — with no backend-specific branch needed in this
   design, and it is the established convention every other admin command
   already follows.

The cost — the server cannot be attached to the database during backup or
restore — is accepted by ADR-108 itself, which frames this whole decision
group as "operations that need the database to themselves." This is not a
compromise introduced here; it is what the parent decision already chose.

(`TryAcquireSchedulerLock`'s row-based TTL-lease mechanism,
`internal/storage/store/local_scheduler_lock_lease.go:70`, was also
considered — it is portable across backends too, but it backs
`RemoteStorage.WithSchedulerLock` for a different purpose (scheduler jobs
across HTTP spokes, self-healing on crash via TTL) and no `admin` command
uses it today. Introducing a second locking primitive for one command would
be inconsistent with every sibling command's convention for no real gain.)

## 7. Restore semantics

**Empty target only.** After `migrateDatabase` has brought the target to
`currentSchemaEpoch` (below), restore checks that a small set of anchor
tables (`users`, `secret_nodes`, `audit_events`, …) all have zero rows, and
refuses with a clear error otherwise. This is the guard against accidentally
pointing `admin restore` at a live production database.

**All-or-nothing, without one multi-table transaction spanning the whole
database.** Restore builds the fully-loaded database in a location that is
*not yet* the target, verifies it, and only then atomically makes it the
target:

- **SQLite:** load into a sibling temporary file, `fsync`, then atomically
  rename it over the target path — the existing `securefiles` atomic-
  replace idiom this repo already uses elsewhere for exactly this kind of
  swap.
- **Postgres:** load into a freshly created schema, then
  `ALTER SCHEMA ... RENAME TO ...` to swap it into place atomically. This is
  not a novel mechanism for this codebase — non-public-schema Postgres
  deployments are already a first-class supported shape
  (`internal/storage/migrate_postgres_nonpublic_schema_test.go`), so
  "build in a scratch schema, rename into place" fits an already-exercised
  deployment pattern rather than introducing a new one.

Either path needs enough free space to hold both the (empty) target shell
and the fully-loaded copy simultaneously during restore — flagged as §12
Q3.

**Refuse a backup from a newer schema.** Reuses `checkSchemaEpoch`'s exact
comparison (§5) — no new refusal logic to get subtly wrong.

**Automatic post-restore audit verification, before declaring success.**
After the atomic swap-in but before releasing the exclusive lock, restore
runs the same walk `auditverify.Verify` performs against the now-live
target, using the operator-supplied key material (§4) — which, being
KEK-derived the same way the checkpoint-signing key is, is already in hand
at this point in the command, no extra flag needed. `VerdictBroken` fails
the whole restore command (non-zero exit) but **does not delete the
swapped-in database** — a loud failure that leaves a forensic artifact in
place beats a silent one that leaves nothing (this repo's own standing
principle: don't trade loud failure for silent data loss).
`VerdictIndeterminate` (e.g., no checkpoint key reachable) is reported as a
warning, matching design-b4's own verdict semantics — it does not fail the
command.

## 8. Reuse: version-skipping upgrade and the SQLite → Postgres move

Both of ADR-108's two derived capabilities are the **same restore path**,
run with no new code, once two properties already designed above hold:

1. Restore always creates its target fresh and runs `migrateDatabase`
   against it *before* loading any row (§7) — so the target always has the
   complete current-schema table shape, all columns, all defaults, from the
   binary doing the restoring, regardless of which binary produced the
   backup.
2. Each row is stored as a JSON object keyed by column name (§3), not a
   positional/binary record — so a column the backup's schema didn't have
   yet simply takes its GORM-defined default on insert, and a column the
   backup had that current models no longer define is simply not read back.

**Version-skipping upgrade** is then: take a backup on the old binary (which
needs no schema knowledge beyond what it already has), restore it through a
current binary into a freshly-migrated-to-current-schema empty database.
*Same command, same code path as any other restore* — no per-version
column-mapping table, no special "upgrade mode" flag.

**The SQLite → Postgres move** is the same restore, pointed at a Postgres
target instead of a SQLite one — the format is backend-neutral by
construction (§3), so nothing about the container format or the load logic
changes; only the target DSN does. Confirmed as new ground: no
SQLite↔Postgres data-migration path exists anywhere in this repo today
(`internal/cli/migrate` implements only `migrate user-to-machine`, ADR-023,
an unrelated user→machine-identity conversion).

**The one real hazard this does not close**: a column that was *renamed* or
had an incompatible type change between the backup's schema version and the
restoring binary's is silently dropped (old name, no longer read) or fails
to parse (type change), rather than being migrated forward. This is not a
new gap this design introduces — it is the same class of hazard
`migrateDatabase`'s own "existing-DB path" already has (per-column
`ADD COLUMN` steps are hand-maintained today; issue #1642 found three
missing ones). Flagged as §12 Q4 rather than solved here.

## 9. Anti-rollback: opt-in via the same external-anchor mechanism as design-b4

A validly-signed *older* backup restored on purpose is a legitimate DR
action (§2); this design does not refuse it by default. But §7's automatic
post-restore verification already accepts an optional `--anchor` flag
(forwarded straight into the `auditverify.Verify` call, §7), and design-b4's
`crossCheckExternalAnchor` already does exactly the check this needs for
free: an externally-held anchor certifying *more* chained events than the
just-restored chain contains is reported as a truncation, regardless of
whether the restored data is internally self-consistent and validly signed
in isolation. Restoring an older backup, when the operator supplies a newer
external anchor, surfaces as exactly that condition.

This mirrors design-b4's own trust model rather than inventing a new one:
no anchor supplied means rollback cannot be ruled out, stated plainly (via
`Result.NotProven`), not silently assumed away. Whether an anchor mismatch
should be a hard refusal rather than a reported warning is §12 Q2.

## 10. CLI surface

```
keyorix-server admin backup  --output <path> [--force]
keyorix-server admin restore --input  <path> [--anchor <path>] [--force]
```

Both commands take the same `--config` every admin command already takes
(source DB for backup, target DB for restore) and hold
`serverguard.AcquireExclusive` via `acquireDatabaseLock` for their entire
run (§6) — `--force` behaves exactly as it does for every other admin
command (`admin.go:43`): still attempts the lock first, proceeds unprotected
with a loud warning only if acquisition itself fails.

Unlike `admin verify-audit`'s `--checkpoint-key-file` (a design-b4 choice
made because that tool is meant to run detached from the server's own
config), `admin backup`/`admin restore` run with the live server's
configuration already loaded, so KEK access for manifest signing/
verification and DEK wrapping/unwrapping comes from the same
`encryption.Service`/`KeyManager` every other admin command already
resolves from `--config` — no extra key-material flag needed.

`--output` follows the existing secure-output-file convention
(`internal/cli/secret/export.go`'s `createSecureOutputFile` →
`securefiles.SecureCreateFileHandle`, O_EXCL + O_NOFOLLOW, 0600) rather than
`admin audit export-checkpoint`'s plain O_EXCL — backup output can be large
and streamed (§3), so it is written incrementally through this handle
rather than buffered and written once like the checkpoint export.

## 11. Test and fuzz plan

1. **Property test: `restore(backup(state)) == state`.** Build a fixture
   database exercising secrets/versions, RBAC, machine identities, and a
   checkpointed audit chain (extending `differential_test.go`'s
   `diffFixture` pattern from design-b4's own test suite), take a backup,
   restore into a fresh empty target, and assert every table's content hash
   matches — reusing the *same* per-table hash the manifest already
   computes (§5) as the test oracle, rather than a second, parallel
   comparison mechanism.
2. **Exhaustive single-byte tamper of the manifest and a representative
   table section.** Directly extends the byte-flip approach built for
   `internal/auditverify/tamper_exhaustive_test.go` (PR #2097): on a small
   fixture, flip every byte offset of the manifest JSON and of one table's
   NDJSON section in turn, and assert restore's pass-1 verification never
   succeeds. Mutation-kill-validated the same way that PR was: temporarily
   disable the manifest-hash comparison and confirm the test goes red before
   trusting it.
3. **Truncation fuzz.** Truncate a valid backup at every section boundary,
   and at random byte offsets via a native `func Fuzz` target, and assert
   restore always either cleanly refuses with nothing loaded, or (for a
   non-truncating mutation that happens to still parse) fails the pass-1
   hash/signature check — never a partial load, never a panic. This directly
   answers the original TRACK OFFLINE-FUZZ ask (d): arbitrary/truncated/
   oversized backup input must never panic and never partially restore.
4. **Wrong-key test.** Restore with an incorrect passphrase/no KMS access;
   assert clean refusal in pass 1, zero rows in the target.
5. **Non-empty-target refusal test.** Attempt restore against a target with
   existing rows; assert refusal, zero rows changed.
6. **Post-restore verification test.** Corrupt the *source* database's audit
   chain before taking a backup of it; assert restore succeeds at loading
   rows but reports the overall command as failed once its automatic
   post-restore `verify-audit` returns `BROKEN` — and that the loaded
   (broken) database is left in place, not deleted.
7. **Rollback/anchor test (§9).** Take backup A, log further audit events
   and a new checkpoint, take backup B. Restore A while supplying an anchor
   derived from B's checkpoint; assert the post-restore anchor check
   surfaces the truncation.
8. **SQLite ↔ Postgres round trip**, `pg-gated` per this repo's
   `docs/security-closures.tsv` convention (needs `KEYORIX_TEST_PG_DSN`):
   back up a SQLite fixture, restore into Postgres, and the reverse
   direction, asserting equivalent content both ways.

## 12. Open questions for Andrei

1. **Restore requires a local, seekable file — never a live pipe (§3).**
   Backup can stream to stdout/a pipe/object storage; restore cannot,
   because verification must complete before any row is applied. Is
   requiring operators to land the file locally before restoring acceptable
   for v1, or does a future version need a buffer-to-local-scratch-file
   fallback for a non-seekable source?
2. **Anti-rollback (§9) is opt-in, not enforced by default** — restoring an
   older backup without supplying `--anchor` succeeds, since that is a
   legitimate DR action. Should restore instead *refuse* (not just warn)
   whenever an anchor *is* supplied and mismatches, or is "warn loudly"
   sufficient?
3. **All-or-nothing via atomic rename (§7) needs transient double disk
   space** — the empty target shell plus the fully-loaded copy exist
   simultaneously during restore. Acceptable for the expected deployment
   sizes, or does this need a documented minimum free-space requirement (or
   an alternate design) up front?
4. **Version-skipping upgrade (§8) does not handle a renamed or
   type-changed column** between the backup's schema version and the
   restoring binary's — same residual gap `migrateDatabase`'s own upgrade
   path already carries. Acceptable as a known, shared limitation, or does
   this design need an explicit per-version column-mapping table before
   shipping?
5. **A new KEK-derived signing key (§5)** — confirm no objection to minting
   a new HKDF domain-separation string/"slot" alongside the existing
   audit-checkpoint one, rather than reusing that key for manifest
   signatures too.
6. **Should the SQLite→Postgres move and version-skipping upgrade get
   dedicated wrapper subcommands/UX** (e.g. `admin migrate-to-postgres`)
   **or just be documented usage patterns of the same `backup`/`restore`
   pair** (this design's default assumption, §8)?
7. **Is a full, all-or-nothing export the only mode v1 needs**, or should
   selective/partial backup (by project, by table, by time range) be
   in scope from the start? Assumed "full only" throughout this document;
   flagging since it materially affects §3's format and §7's restore
   semantics if reversed later.

## Effort estimate

| Piece | Estimate |
|---|---|
| Container format + FK-safe ordering derivation + streaming writer/reader | 3–4 days |
| Manifest: signing key derivation, per-table hashing, schema-epoch check | 2 days |
| DEK/salt/wrapped-KEK portable export + restore-side unwrap probe (§4) | 2–3 days |
| `admin backup` + `admin restore` CLI commands, `serverguard` wiring, atomic swap-in (both backends) | 3–4 days |
| Post-restore automatic `verify-audit` integration + anchor forwarding (§9) | 1–2 days |
| Test plan (§11): property test, byte-tamper/truncation fuzz, PG round trip | 4–5 days |
| Docs (operator guide, DR runbook, SQLite→Postgres move walkthrough) | 1–2 days |

**Total: ~16–22 engineer-days**, plus review time given the
security-sensitive nature of a tool that handles the entire system's
confidential material and is the last line of defense in a disaster.
