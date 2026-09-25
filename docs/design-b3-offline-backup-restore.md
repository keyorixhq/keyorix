# Design: offline backup and restore (ADR-108 §B3)

**Status:** Design decided (2026-09-25) — see §12 for Andrei's resolutions of
every open question. Implementation blocked on PR #2099 merging; see §13.
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
  per-project, per-table, or time-range export (§12 decision 7).
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
consume a live, non-seekable stream (§12 decision 1: confirmed acceptable
for v1).

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
material.** The wrapped DEK and salt (or KMS-wrapped-key blob) live only as
files on the source host (`config.EncryptionConfig.DEKPath`/`SaltPath`,
`internal/config/config.go:623`; `WrappedKeyPath`, `kms_provider.go:94`).
The enumeration of exactly these files already exists —
`internal/keyfiles.Registry` (pre-existing, originally built for the
permission-fixing call sites: `keyorix system audit`/`fixfileperm`, server
boot validation, `KeyManager.ValidateKeyFiles`) walks `*config.
EncryptionConfig` and returns the KEK salt, wrapped DEK, and any
provider-specific wrapped-KEK blob or Shamir share files as one list — the
single source of truth this design should read from rather than
re-deriving its own. §13 records that PR #2099 (backup format v1) is the
first consumer to repurpose this registry for bundling into an archive
(SQLite-only, into a checksummed tar); this design's manifest `encryption`
section does the same enumeration for the backend-neutral v2 format: the
same on-disk bytes (wrapped DEK, salt if password-provider, wrapped-KEK
blob if KMS-provider), plus the provider type and key version, relocated
into the portable container rather than reinvented, and read via the same
`keyfiles.Registry` call v1 already uses rather than a second hand-written
list. No new wrap format, and — once #2099 lands — no new enumeration
either; this is plumbing, not new cryptography.

(For historical context: before #2099 existed, the only *backup* of this
material anywhere in the repo was `internal/encryptionops/migrate_provider.
go`'s `MigrateProviderWithConfig`, a same-host, same-format crash-safety
copy taken immediately before an in-place re-wrap — it never bundled the
salt and never crossed machines or passphrases, so it could not have served
this purpose even before v1 shipped.)

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
and the fully-loaded copy simultaneously during restore. **Decided (§12
decision 3): a preflight free-space check runs before pass 2 begins loading
anything** — comparing the archive's declared uncompressed size (manifest,
§5) against free space on the target's filesystem (and, for the Postgres
scratch-schema path, the tablespace's backing volume), refusing up front
with a clear message naming both numbers if there is not enough headroom,
rather than failing partway through a load.

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
missing ones).

**Decided (§12 decision 4): acceptable only if restore does not silently
tolerate it.** Pass 1 (§3) compares each table's set of manifest-declared
column names against the restoring binary's own current model schema for
that table; a column present in the backup but absent from the current
model **under a name the model doesn't recognize as a known-retired field**
is an unsupported schema delta, and restore refuses before pass 2 begins,
naming the table and column. This requires a companion documentation rule,
recorded here rather than left implicit: **schema migrations in this repo
must be additive-only going forward** — new columns and tables are fine
(the whole mechanism in §8 point 2 depends on that being safe), but
in-place column rename or type change is not permitted; a genuine rename is
modeled as add-new-column-plus-deprecate-old, never an `ALTER COLUMN`. This
rule needs to land in `docs/g80-remediation-notes.md` or equivalent
engineering-practice documentation alongside this design, not only here.

## 9. Anti-rollback: fails closed when an anchor is supplied and mismatches

A validly-signed *older* backup restored on purpose is a legitimate DR
action (§2), and with no `--anchor` supplied this design cannot rule out
rollback at all — the same honest limitation design-b4 states for a bare
verification run with no key (`Result.NotProven`), not silently assumed
away. **But once an anchor is supplied, decision 2 (§12) makes the check
load-bearing, not advisory.**

§7's automatic post-restore verification accepts an optional `--anchor`
flag, forwarded straight into the `auditverify.Verify` call, and design-b4's
`crossCheckExternalAnchor` already performs exactly the check this needs:
an externally-held anchor certifying *more* chained events than the
just-restored chain contains is reported as a truncation, regardless of
whether the restored data is internally self-consistent and validly signed
in isolation. Restoring an older backup while supplying a newer external
anchor surfaces as exactly that condition.

**Decided (§12 decision 2): fail closed.** When `--anchor` is supplied and
the post-restore check reports the anchor mismatch (truncation/rollback
evidence), `admin restore` refuses — the restore is left in the forensic
state §7 already establishes for a `VerdictBroken` outcome (data loaded,
command exits non-zero, nothing deleted), not silently accepted. The only
way past this refusal is an explicit `--allow-rollback` flag, which does
not suppress the check silently: it **writes an explicit audit event**
(`audit_events`, a new event type naming the operator, the supplied anchor,
and the certified-vs-restored chained-event counts) into the now-restored
database before the command reports success, so a rollback that was
knowingly overridden is itself part of the tamper-evident record going
forward — an operator can no longer make this override invisible even to
themselves.

## 10. CLI surface

```
keyorix-server admin backup  --output <path> [--force]
keyorix-server admin restore --input  <path> [--anchor <path>] [--allow-rollback] [--force]
```

`--allow-rollback` is only meaningful together with `--anchor` (§9): it does
not weaken any other check, and is rejected as a usage error if passed
without `--anchor`, since there is nothing to override otherwise.

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
7. **Rollback/anchor test, fail-closed (§9).** Take backup A, log further
   audit events and a new checkpoint, take backup B. Restore A while
   supplying an anchor derived from B's checkpoint; assert the whole restore
   command fails (non-zero exit) with the truncation named, and that no
   `--allow-rollback` audit event exists (since it wasn't passed). Repeat
   with `--allow-rollback` added: assert the restore now succeeds, AND that
   the restored database's own audit chain contains the new
   rollback-override event naming the operator and the anchor mismatch —
   asserting the event's *presence*, not just the command's exit code, per
   this repo's own "assert the effect, not the return value" discipline for
   a path that could otherwise silently swallow the override.
8. **Free-space preflight test (§7, decision 3).** Restore against a target
   filesystem with less free space than the manifest's declared uncompressed
   size; assert refusal before pass 2 begins, with both numbers named in the
   error, and zero bytes written to the target.
9. **Unsupported schema-delta refusal test (§8, decision 4).** Construct a
   backup whose manifest declares a column name the restoring binary's
   current model does not recognize; assert restore refuses in pass 1,
   naming the table and column, rather than silently dropping it.
10. **SQLite ↔ Postgres round trip**, `pg-gated` per this repo's
    `docs/security-closures.tsv` convention (needs `KEYORIX_TEST_PG_DSN`):
    back up a SQLite fixture, restore into Postgres, and the reverse
    direction, asserting equivalent content both ways.
11. **v1-archive restore compatibility (§13).** Once #2099 merges: restore a
    v1 (`gzip(tar(...))`) archive produced by that PR's `admin backup`
    unmodified, and assert it still succeeds end to end (format detection,
    delegation to v1's own loader, then this design's post-restore
    `verify-audit` running against the result) — a regression test proving
    v2's restore command never drops v1 support.

## 12. Decisions (Andrei, 2026-09-25)

Every question this design originally left open is resolved below. Each
decision's reasoning is also folded into the section it governs (§3, §7,
§8, §9, §10) so those sections read correctly standalone — this list is the
record of *what was decided and why*, not the only place the decision is
reflected.

1. **Restore requires a local, seekable file — never a live pipe (§3).**
   **Decided: yes, for v1.** Backup can stream to stdout/a pipe/object
   storage; restore cannot, because verification must complete before any
   row is applied. Operators land the file locally before restoring; no
   buffer-to-local-scratch-file fallback for a non-seekable source in v1.
2. **Anti-rollback (§9).** **Decided: fails closed.** A supplied `--anchor`
   that doesn't match the just-restored chain causes restore to refuse, not
   just warn. The only override is an explicit `--allow-rollback` flag,
   which writes an audit event recording that the override happened —
   restoring an older backup is legitimate DR, but doing so past a
   mismatched anchor is now itself part of the tamper-evident record, never
   silent.
3. **Transient double disk space during atomic-rename restore (§7).**
   **Decided: acceptable**, gated by a preflight free-space check that
   refuses up front with a clear message (declared vs. available space)
   rather than failing partway through a load.
4. **The renamed/retyped-column gap in version-skipping upgrade (§8).**
   **Decided: acceptable only if restore detects it and refuses**, rather
   than silently dropping or mis-parsing the column. Companion documentation
   rule: schema migrations in this repo are additive-only going forward — no
   in-place `ALTER COLUMN` rename or type change; a rename is modeled as
   add-new-column-plus-deprecate-old.
5. **A new KEK-derived manifest-signing key (§5).** **Decided: yes** — a new
   HKDF domain-separation info label, distinct from the existing
   audit-checkpoint key's, not a reuse of that key for a second signature
   protocol.
6. **Dedicated wrapper subcommands for the SQLite→Postgres move / version-
   skipping upgrade, vs. documented usage of `backup`/`restore` (§8).**
   **Decided: no wrapper subcommands in v1** — both are documented usage
   patterns of the same `admin backup`/`admin restore` pair.
7. **Selective/partial backup scope for v1 (§3, §7).** **Decided: full
   backup only for v1.** No per-project, per-table, or time-range export.

## 13. Relationship to PR #2099 — backup format v1 (2026-09-25 addendum)

PR #2099 (`feat(server/admin): add admin backup/admin restore`, ADR-108
§B3, open at the time of this addendum) ships ahead of this design as
**backup format v1**. It is SQLite-only by explicit scope (refuses on
Postgres, pointing operators at `docs/SELF_HOSTING.md` §5's manual
`pg_dump`/`psql` path instead): `admin backup --output` takes a consistent
snapshot via SQLite's own `VACUUM INTO` under the same `serverguard`
exclusive lock this design also uses (§6, `backup.go`), bundles it with
every encryption key-material file already enumerated by the existing
`internal/keyfiles.Registry` (KEK salt, wrapped DEK, wrapped-KEK blobs,
Shamir shares — precisely the "portable wrapped-DEK+salt" need §4
identifies, already solved by pre-existing code this design should reuse,
not duplicate) into one checksummed `gzip(tar(...))` archive: a
`MANIFEST.json` (`format_version: 1`, `backend: "sqlite"`, a `SHA256` and
tar entry name per bundled file) plus one tar entry per file.
`admin restore --input` checksum-verifies every entry before writing
anything, refuses a backend mismatch and a non-empty target (without
`--overwrite-existing`), then applies pending migrations exactly like
`admin migrate` — already covering the "version-skipping upgrade" case for
this SQLite-only, physical-snapshot shape.

This design (v2) does not replace v1; it is the SQLite↔Postgres-portable,
logical-export superset ADR-108 §B3 still needs — v1's own PR description
explicitly scopes the backend move and Postgres backup/restore out as
follow-up work. **`admin restore` must accept both formats, so an archive
taken by a pre-v2 binary is never stranded:**

- **Format detection is free, no version negotiation needed.** A v1 archive
  is valid gzip (magic bytes `1f 8b`) containing a `MANIFEST.json` entry; a
  v2 archive opens with the new `KYXBKP1` magic string (§3), which is not
  valid gzip. Restore inspects the first few bytes and dispatches before
  doing anything else.
- **v1 archives are handled by v1's own code, not reimplemented.** Once
  #2099 merges, this design's `admin restore` becomes the single CLI entry
  point; internally, a detected v1 archive is handed to (an exported form
  of) #2099's own archive-reading and restore logic unchanged — its
  checksum verification, its `internal/keyfiles.Registry`-driven key-file
  handling, and its post-load migration step all reused as-is, not
  rewritten against this design's own manifest/signature scheme, which v1
  archives were never built to carry. A v1 archive against a non-SQLite
  target still refuses exactly as it does today.
- **v2's new safety nets still apply to a v1 restore, layered on top, not
  duplicated into v1's code.** The free-space preflight (§12 decision 3) and
  the empty-target check run identically regardless of detected format,
  before either loader starts. Once a v1 archive is physically installed and
  migrated (v1's own mechanism), it is a live, fully-migrated SQLite
  database exactly like a v2 restore's output — so this design's automatic
  post-restore `verify-audit` (§7) and the fail-closed `--anchor`/
  `--allow-rollback` check (§9, §12 decision 2) run against it the same way,
  even though the v1 archive itself carries none of v2's signed-manifest/
  schema-epoch machinery (§5) to check on the way in.
- **`admin backup` only ever emits v2 archives once this design ships** —
  v1 compatibility is read-only, on the restore side, for archives already
  taken by pre-v2 binaries. There is no ongoing "which version should I
  write" choice for an operator to make.

**Sequencing: implementation starts only after #2099 merges.** Building v2
concurrently against a moving, unmerged v1 would mean two independently-
written restore paths landing and conflicting over the same `serverguard`
lock-acquisition and archive-handling code that #2099 is introducing right
now. Once #2099 is on `main`, v2's implementation extends and reuses that
code directly instead of re-deriving it.

## Effort estimate

| Piece | Estimate |
|---|---|
| Container format + FK-safe ordering derivation + streaming writer/reader | 3–4 days |
| Manifest: signing key derivation, per-table hashing, schema-epoch check, schema-delta refusal (§8 decision 4) | 2–3 days |
| DEK/salt/wrapped-KEK portable export (reusing `internal/keyfiles.Registry`, §13 — smaller than originally scoped since this enumeration already exists) + restore-side unwrap probe (§4) | 1–2 days |
| `admin backup` + `admin restore` CLI commands, `serverguard` wiring, atomic swap-in (both backends), free-space preflight (§7 decision 3) | 3–4 days |
| Post-restore automatic `verify-audit` integration, fail-closed anchor check + `--allow-rollback` audit event (§9 decision 2) | 2 days |
| v1-archive delegation path (§13): format detection + wiring to #2099's (exported) archive reader | 1–2 days |
| Test plan (§11): property test, byte-tamper/truncation fuzz, PG round trip, v1-compat regression | 4–5 days |
| Docs (operator guide, DR runbook, SQLite→Postgres move walkthrough, additive-only-migrations rule) | 1–2 days |

**Total: ~17–24 engineer-days**, plus review time given the
security-sensitive nature of a tool that handles the entire system's
confidential material and is the last line of defense in a disaster. Not
started until PR #2099 merges (§13).
