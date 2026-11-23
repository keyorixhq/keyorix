# Rotating encryption keys

Two independent rotations exist: the **DEK** (data encryption key — what actually
encrypts secret values) and the **KEK** (key-encryption key, derived from your master
passphrase — what wraps the DEK at rest).

Output captured on `deb388fb3`, 2026-11-22, native, on SQLite and on PostgreSQL (the PostgreSQL
differences are called out where they exist). Version numbers, fingerprints, row counts, hashes,
job ids and times differ on your install, and absolute paths and the database address are
replaced by placeholders. Lines that start with a timestamp such as `storage: opening existing
SQLite database at ...` are log lines on stderr and are mostly left out. The capture instance had
one secret and one MFA-enrolled admin, hence the row counts. Not captured (pending the e2e VM):
containers, Kubernetes, cloud KMS, TPM and Shamir providers.

For the preflight, the checks afterwards, rollback and what not to do, see
[key-rotation-runbook.md](key-rotation-runbook.md).

Both commands need exclusive access to the database — stop the server first (every replica, if you run several; see below). They read the
current master passphrase from `KEYORIX_MASTER_PASSWORD`, `KEYORIX_MASTER_PASSWORD_FILE`,
`--passphrase-file`, `--passphrase-fd` or `--passphrase-stdin`.

## Rotate the DEK (re-encrypts every secret)

Preview first — this makes no changes:

```bash
keyorix-server admin encryption rotate --config ./keyorix.yaml --dry-run
```

Expected:

```
🔍 Dry run: previewing what a DEK rotation would re-encrypt — no changes will be made to the database or the DEK...
2026/11/22 02:23:50 [sweep] secret_versions: 1 rows processed
✅ Dry run complete — no changes were made
📋 secret_versions: 1, api_tokens: 0, api_clients: 0, password_resets: 0, mfa_secrets: 1, dynamic_secret_configs: 0, dynamic_secret_leases: 0, notification_channels: 0 (legacy AAD upgraded: 0)
```

Then actually rotate:

```bash
keyorix-server admin encryption rotate --config ./keyorix.yaml --confirm
```

Expected:

```
⚠️  Rotating DEK and re-encrypting all DEK-encrypted rows. This holds a write lock on the database — stop write traffic before continuing.
🔄 Rotating DEK with full re-encryption sweep...
2026/11/22 02:23:52 [sweep] secret_versions: 1 rows processed
2026/11/22 02:23:52 [sweep] pre-commit verification: all 2 re-encrypted values decrypt under the new DEK
2026/11/22 02:23:53 ✅ Sweep committed: 1 secret_versions, 0 api_tokens, 0 api_clients, 0 password_resets, 1 mfa_secrets, 0 dynamic_secret_configs, 0 dynamic_secret_leases, 0 notification_channels re-encrypted (0 legacy AAD upgraded)
✅ DEK rotated and full re-encryption sweep complete. New version: v1795310632
✅ DEK rotated successfully
📋 New key version: v1795310632
📋 secret_versions: 1, api_tokens: 0, api_clients: 0, password_resets: 0, mfa_secrets: 1, dynamic_secret_configs: 0, dynamic_secret_leases: 0, notification_channels: 0 (legacy AAD upgraded: 0)
ran `keyorix-server admin encryption rotate` (full DEK re-encryption sweep)
```

(On PostgreSQL the line `DEK rotation: encrypted writes are now refused on every replica; waiting 10s for
replicas to observe it` comes right after the `🔄 Rotating DEK ...` line and the sweep starts 10 seconds
later; the rest is the same. The last summary line is the dry run's. Exit status 0. "all 2
re-encrypted values" counts the secret version and the MFA secret.)

A kill at any point during this is safe — the design guarantees exactly one of the old or
new DEK stays consistently active and every row stays decryptable under it, never a
half-rotated database.

## Several server replicas (PostgreSQL)

With more than one server on one PostgreSQL database (ADR-039; Helm
`server.replicas > 1`), each replica holds the DEK in memory and may have its
own copy of `dek.key`. The rotation only replaces `dek.key` on the host it runs
on. The database records which DEK it is encrypted under (the DEK epoch, a
fingerprint in `system_metadata`, not key material), and every replica checks it:

1. Upgrade every replica to a release with the DEK epoch check first (an older
   binary does not check it).
2. Stop **every** replica, not only the local one. `rotate` refuses while any
   server is attached to the database.
3. Run `rotate --dry-run`, then `rotate --confirm`, on one host. On PostgreSQL
   it first fences encrypted writes on every replica, waits about 10 seconds,
   then re-encrypts with the encrypted tables locked against writes (reads
   continue) and records the new epoch in the same transaction.
4. Copy the new `dek.key` (and `kek.salt` with the password provider) **and
   `keyset.manifest.json`** from that host to every other replica's key directory,
   or copy the whole key directory. The manifest records the new DEK; a replica that
   gets the key files without it refuses to start ("key material does not match the
   key-set manifest"). With the Helm chart's Secret mode,
   rotate in a workspace and publish the result as a new key Secret instead
   (`admin encryption key-secret unpack` / `export`; procedure and crash recovery in
   [multi-replica-keys.md, "Rotation in Secret mode"](../multi-replica-keys.md#rotation-in-secret-mode)).
   Keep the rotating host's key directory until every replica runs on the new key
   set: if the rotation was interrupted after its commit, its `dek.key.pending` is the
   only copy of the new DEK.
5. Start the replicas.

A replica whose `dek.key` is still the old one refuses to start:

```
refusing to start: this server's DEK is not the DEK the database is encrypted under:
the database's DEK epoch is "…", this server's DEK fingerprint is "…". …
```

Copy the current key files, `keyset.manifest.json` included (or the whole key
directory), to it and start it again. Nothing was written under the old DEK. A replica that was left running (`rotate --force`, or a lost presence
lock) refuses encrypted writes (`encryption refused: this server cannot confirm
that its DEK is the database's current DEK …`) within a few seconds of the
fence and keeps serving reads and revocations; restart it with the new key files.

If a rotation fails before its sweep commits, it lifts the fence itself; a
fence left by a killed rotation is lifted by the next server start that holds
the old DEK, or by re-running `rotate`. SQLite (single server) is unchanged.

## Rotate the KEK (change the master passphrase)

This re-wraps the DEK under a new passphrase; it does **not** touch any database row.
It still opens the database (read only, to finish an interrupted DEK rotation first, and to
take the exclusive presence lock, #3513), so the database must be reachable with the
configured `storage` settings: on PostgreSQL the server must be reachable; on SQLite a relative
`database.path` is taken relative to the config file. Give `encryption.dek_path` and
`salt_path` as absolute paths: relative ones are defined against the config file's
directory, and the command refuses to run from any other directory, naming the key (#4249). When the
database is not reachable, `rotate-kek` fails with
`cannot connect to the database to check for a running server`, although only key files change.
Bring the database up first; `--force` is not a fix for this (see the runbook).
`admin encryption migrate-provider` opens it the same way.

```bash
keyorix-server admin encryption rotate-kek --config ./keyorix.yaml --confirm --new-passphrase-file ./new_master_password
# or --new-passphrase-stdin / --new-passphrase-fd. A file is refused when it is group- or
# world-readable (any group or other bit, such as 0644: `... is group- or world-readable (mode
# 0644) -- refusing to read it; chmod 600 the file`) or owned by anyone but you or root; 0600 and
# 0400 both work. The same rule applies to --passphrase-file.
```

Expected:

```
Rotating KEK — re-wrapping DEK under new passphrase...
Verifying the audit chain under the current key and recording the key transition...
2026/11/22 02:24:02 audit key transition to key version "ack-d88056ed063e107f96587594d61787cd" completed: the verification state, high-water mark and retention anchor are signed under the new key
Audit verification state, high-water mark and retention anchor carried over to the new key (a fresh checkpoint is signed under it when the chain verified; a recorded break stays recorded).
KEK rotation complete.

  Evidence-signing key fingerprint:      esk-6b234bcedc082ff54192ca51a5aaf5ae
  Audit-checkpoint key fingerprint:      ack-d88056ed063e107f96587594d61787cd

Update the master passphrase in your deployment configuration to the new value before restarting the server.

Note: evidence packs signed before this rotation will report as 'superseded
key version' (not tampered) under `compliance verify`. Audit checkpoints signed
before it stay verifiable with the previous checkpoint key; export the new one
with `admin audit export-checkpoint-key`.
ran `keyorix-server admin encryption rotate-kek`
```

(The command also prints a `storage: opening existing SQLite database ...` log line before and after
this output. On PostgreSQL the output is the same apart from the fingerprints.)

The variable to update is `KEYORIX_MASTER_PASSWORD` or the file `KEYORIX_MASTER_PASSWORD_FILE`
points at (or your `key_provider`'s equivalent). The command's own output doesn't name it, so:
whatever you use to set the passphrase today, set it to the new value before the next start,
and update your offline copy of the passphrase.

Note: evidence packs and audit checkpoints signed **before** this rotation will report as
"superseded key version" (not tampered) under `compliance verify` afterward — expected,
not a problem.

## Verify nothing broke

```bash
KEYORIX_MASTER_PASSWORD_FILE=./new_master_password KEYORIX_CONFIG_PATH=./keyorix.yaml keyorix-server   # restart with the NEW passphrase after rotate-kek (the server has no --config flag)
keyorix secret get --id <id> --show-value
keyorix audit logs --limit 20
```

The secret's value should be unchanged, and `audit logs` should show an
`admin.encryption.rotate` (or `admin.encryption.rotate_kek`) event with the timestamp of your rotation.
After a DEK rotation followed by a KEK rotation on SQLite, `keyorix audit logs --limit 8` read:

```
ID     TIME (UTC)           ACTOR            KIND      EVENT                               DESCRIPTION
28     2026-11-22 01:24:38  admin            user      secret.read                         User admin read secret DEMO_SECRET
27     2026-11-22 01:24:34  system           system    license.evaluated                   License evaluated at startup: none — no license installed — running the community baseline
26     2026-11-22 01:24:34  system           system    data_retention.policy_configured    Data retention policy applied: anomaly_alerts=0d anomaly_alerts_unacked_ceiling=0d closed_access_reviews=0d break_glass=0d resolved_access_requests=0d
25     2026-11-22 01:24:30  admin_cli        admin_cli admin.backup_created                created backup archive <archive path> (80 table(s), 153 row(s), 2 key file(s))
24     2026-11-22 01:24:11  admin_cli        admin_cli admin.audit_checkpoint_key_exported exported the audit-checkpoint verification key (key version ack-d88056ed063e107f96587594d61787cd) to <key file path>
23     2026-11-22 01:24:02  admin_cli        admin_cli admin.encryption.rotate_kek         ran `keyorix-server admin encryption rotate-kek`
22     2026-11-22 01:24:02  system           system    system.audit_key_transition         audit key transition #1: checkpoint key version ack-dc89bca73b6ae9ab790676fb0cfeea3b replaced by ack-d88056ed063e107f96587594d61787cd; the verification state was carried over under both keys (record cac39e28b39b73ef12f2e5c12cf3302cce91cbd5bde311e90ef84c166ef920f6)
21     2026-11-22 01:23:53  admin_cli        admin_cli admin.encryption.rotate             ran `keyorix-server admin encryption rotate` (full DEK re-encryption sweep)
```

### The audit chain before and after

Run the offline verifier with the server stopped before the first rotation and after the last one
(`keyorix-server admin verify-audit --config ./keyorix.yaml`; add `--checkpoint-key-file <new key>`
after a `rotate-kek`, from `admin audit export-checkpoint-key`). Before, on a fresh install, then
after the DEK rotation (SQLite; the PostgreSQL output is identical apart from the ids):

```
Offline audit-chain verification
=================================
Verdict: VALID
  range:            id 1..18
  chained events:   18
  unchained legacy: 0

Checkpoint:
  present but UNAUTHENTICATED -- no --checkpoint-key-file was supplied, or it did not verify

Retention gap:
  none -- the chain reaches genesis

Anchor source: none

Owed break-glass audit records:
  none -- every break-glass activation's audit rows are in the chain

What this run does NOT prove:
  - a host admin holding both this database and its checkpoint signing key can fabricate a fully self-consistent, validly-checkpointed history; this verification proves only that a DB-only actor (without that key) could not have tampered undetectably
  - no checkpoint signing key was supplied: tail-truncation and genesis re-seed are not detected by a bare linkage re-walk alone (a shorter, self-consistent chain still verifies) — only the linkage of rows still present in the table was checked
  - that each SETTLED degraded break-glass activation's owed rows are in the chain: the server marks it settled in the same transaction as the append of its last owed row, and this run does not re-derive that from audit_events

Generated at 2026-11-22T01:23:44Z by auditverify/v1.
```

The DEK rotation appends events (`range: id 1..21` afterwards) and the verdict stays VALID. After the
`rotate-kek`, with the new key (SQLite, `--checkpoint-key-file <new key>`; PostgreSQL reads the same):

```
Offline audit-chain verification
=================================
Verdict: VALID
  range:            id 1..24
  chained events:   24
  unchained legacy: 0

Checkpoint:
  authenticated, key version "ack-d88056ed063e107f96587594d61787cd", certifies 21 chained events

Key transitions: 1 recorded, current epoch authenticated: true, old-key signatures checked: 0

Retention gap:
  none -- the chain reaches genesis

Anchor source: none

Owed break-glass audit records:
  none -- every break-glass activation's audit rows are in the chain

What this run does NOT prove:
  - a host admin holding both this database and its checkpoint signing key can fabricate a fully self-consistent, validly-checkpointed history; this verification proves only that a DB-only actor (without that key) could not have tampered undetectably
  - that each SETTLED degraded break-glass activation's owed rows are in the chain: the server marks it settled in the same transaction as the append of its last owed row, and this run does not re-derive that from audit_events
  - the old-key signature of 1 of 1 key transition record(s) was not checked: pass the earlier checkpoint key(s) with --previous-checkpoint-key-file to prove the pre-rotation state was not forged by a holder of the new key

Generated at 2026-11-22T01:24:12Z by auditverify/v1.
```

Online, with the server restarted on the new passphrase, `keyorix audit verify --full` (SQLite; the
PostgreSQL run printed the same lines with its own counts) reads:

```
Full audit verification running on the server (job <job id>)...
Audit chain: VALID
  chained events:   27
  unchained events: 0
  head id:          27
  head hash:        <64 hex characters>
  checkpoint:       checked against a signed in-DB checkpoint (on-box truncation detection)
```

and the same command on a fresh install, before any rotation, printed the same block with 18 chained
events. Without `--full` the command answers at once and adds the two lines `this check: rows 11..18 after
signed checkpoint #1 (complete: true)` and `full re-walk:     every row through id 18 re-hashed, completed
<time>`.

## Back up around a rotation

Take an `admin backup` **before** and **after** every rotation (SELF_HOSTING.md §5).
An archive carries its own wrapped DEK, so one taken before a DEK or KEK rotation
still restores: after `rotate-kek`, restore it with the passphrase that was current
when it was taken. Keep each old passphrase for as long as you keep the archives that
need it.

## When `admin backup` stops after an interrupted rotation

A `rotate-kek` that was interrupted before it changed any active key leaves
`keys/kek.salt.pending`. A server start that succeeds proves the active keys open without
it and leaves the file in place, and every later `admin backup` is refused while it
exists. The refusal exits with status **4** (every other backup failure exits 1) and prints
`keyorix-backup-refused reason=key-rotation-staging-file exit_code=4 files="keys/kek.salt.pending"`
on stderr, so a cron wrapper can match either. Each refusal is also an `admin.backup_refused`
audit event (`success=false`, naming the file) whenever the database can be opened without
changing anything: on SQLite that means with the server stopped, as a SQLite backup needs anyway,
and on any backend only when the database is already at this binary's schema epoch (a refused
backup never migrates the database). When it cannot be written, the refusal says so on stderr
(`note: this refusal was not recorded to the audit chain: ...`) and is otherwise the same.

The server's start log says it too:

```
[WARN] key set: keys/kek.salt.pending is a staging file left over from a key operation that was interrupted before it changed the active key set; the set is coherent without it and the file can be deleted. `admin backup` will refuse until keys/kek.salt.pending is gone: with the server stopped, run `keyorix-server admin encryption clear-stale-salt-pending`, which removes it only after proving the active key set opens without it
```

`keyorix-server admin diagnose` prints `[WARN] backups would be refused: staging file present
(keys/kek.salt.pending)` followed by the refusal's text, and `admin validate --posture` reports
`[backup/explicit] backups are refused: key-rotation staging file present (keys/kek.salt.pending)`
and exits 1. A `keys/dek.key.pending` is different: never delete it by hand (it can be the only
copy of the new DEK); start the server so boot recovery settles it. Boot never removes either
file itself, and neither does `admin backup`.

**Remove the stale salt with `admin encryption clear-stale-salt-pending`.** Stop the server
(the command holds the database lock and the key-directory lock `rotate-kek` holds, so it
refuses beside a server or a running `rotate-kek`), look at its decision, then run it:

```bash
keyorix-server admin encryption clear-stale-salt-pending --config ./keyorix.yaml --dry-run
keyorix-server admin encryption clear-stale-salt-pending --config ./keyorix.yaml
```

It removes `keys/kek.salt.pending` only when no DEK staging file is present, the key-set
manifest records no interrupted operation boot would still finish from it, and the DEK unwraps
under the active KEK with the current master passphrase (the proof a server start makes). In
every other case it refuses with `clear-stale-salt-pending refused, nothing was removed: <why>`
and exit status 1. A removal is an `admin.encryption.clear_stale_salt_pending` audit event; a
second run has nothing to do.

All of this was run on `BACKUP-STALE-SALT-NOV-1`'s branch, 2026-11-23, native, on a throwaway
SQLite install with a leftover `kek.salt.pending` (a copy of `kek.salt`, as a rotate-kek stopped
before any rename leaves it), after one successful server start. Beside the live server both
commands refused (the backup with exit 4 and the audit note, `clear-stale-salt-pending` with the
database-lock refusal). With the server stopped, the refused backup (stderr; exit status 4, no
archive written):

```
$ keyorix-server admin backup --output ./refused.tar.gz --config ./keyorix.yaml
This refusal was recorded to the audit chain (admin.backup_refused).
keyorix-backup-refused reason=key-rotation-staging-file exit_code=4 files="keys/kek.salt.pending"
Error: backup refused: a key rotation is running or was interrupted (found keys/kek.salt.pending). An archive taken now would include that staging file and `admin restore` would refuse it on any other host, so no archive was written and no key file was changed. If a rotation is running, wait for it to finish. Otherwise start the server once so boot recovery completes the rotation, then back up again. keys/kek.salt.pending is the KEK salt's staging file. After an interrupted rotate-kek the start may need it and the new passphrase, and if it is refused, follow the recovery it prints. A server start that succeeds and leaves keys/kek.salt.pending in place (its log says the file "can be deleted") has proved that the active key set opens without it: the rotation never changed the active keys, and every backup is refused until the file is gone. Remove it with `keyorix-server admin encryption clear-stale-salt-pending` (server stopped; `--dry-run` shows its decision first): it removes keys/kek.salt.pending only when no DEK staging file is present, no `admin encryption rotate-kek` is running and the active key set opens with the current passphrase without it, records that in the audit chain, and refuses otherwise; then back up again. Never delete a DEK's .pending file by hand: it can be the only copy of the new DEK. `admin validate --posture` reports this state until it is resolved
```

The command, with the wrong passphrase, then for real, then again:

```
$ keyorix-server admin encryption clear-stale-salt-pending --config ./keyorix.yaml --dry-run
Found keys/kek.salt.pending. Checking that the active key set opens with the current passphrase without it...
dry run: would remove keys/kek.salt.pending (no DEK staging file is present, and the active key set opens with the current passphrase without it); nothing was removed

$ KEYORIX_MASTER_PASSWORD=<a wrong one> keyorix-server admin encryption clear-stale-salt-pending --config ./keyorix.yaml
Found keys/kek.salt.pending. Checking that the active key set opens with the current passphrase without it...
Error: clear-stale-salt-pending refused, nothing was removed: the active key set does not open with the current passphrase without keys/kek.salt.pending (failed to initialize key manager: failed to unwrap DEK — wrong passphrase or corrupted key file: ...). The file may be the salt an interrupted rotate-kek needs, so it is left in place: if the server does not start either, follow "Interrupted rotate-kek or migrate-provider" in docs/operator/key-rotation-runbook.md

$ keyorix-server admin encryption clear-stale-salt-pending --config ./keyorix.yaml
Found keys/kek.salt.pending. Checking that the active key set opens with the current passphrase without it...
removed keys/kek.salt.pending. Run `keyorix-server admin backup` again.
ran `keyorix-server admin encryption clear-stale-salt-pending`: removed keys/kek.salt.pending, a KEK salt staging file left by an interrupted rotate-kek (no DEK staging file present, the active key set opened with the current passphrase without it)

$ keyorix-server admin encryption clear-stale-salt-pending --config ./keyorix.yaml
nothing to do: no KEK salt staging file is present, and `admin backup` is not refused for one
```

and the same `admin backup` succeeded:

```
Backup written to <archive path> (80 table(s), 24 row(s) total, 2 key file(s))
Store this archive OFF this host. Restore with:
  keyorix-server admin restore --input <archive path>
created backup archive <archive path> (80 table(s), 24 row(s), 2 key file(s))
```

The audit chain then held `admin.backup_refused` (success false),
`admin.encryption.clear_stale_salt_pending` and `admin.backup_created`, and `admin verify-audit`
reported `Verdict: VALID`. An archive taken before the refusal restores on the same host only
with `--allow-rollback`: the refusal's own audit event is newer than it, as after any audited
admin action.

The running server reports it too, for a monitor to poll: while a staging file is in its key
directory, `GET /api/v1/system/info` (for a caller with `system.write`) carries
`security.backup_refused` with `reason` `key-rotation-staging-file` (the same token as the
stderr line), the `files`, `staging_salt_only` (true when only the salt's staging file is
there) and a one-line `remedy` naming `clear-stale-salt-pending`. Each replica reports its own
key directory. The field is absent while backups are not refused, and goes away on the next
request once the file is gone. Alert on its presence. Reading it only checks whether the files
exist; it never moves or deletes one. Covered by
`TestJourney_BackupRefusedSignalWhileStagingSaltPresent` (real server, SQLite; it also drives
`clear-stale-salt-pending` beside the server, with `--dry-run`, for real and again).

## Rehearse it: `scripts/drills/key-rotation.sh`

The script runs this page's offline operations on a throwaway instance (SQLite or
PostgreSQL) with seeded data and checks, after each one, that every secret decrypts,
MFA login, a share and a machine token still work, and `admin verify-audit` is VALID:

1. `rotate --dry-run` changes nothing; `rotate --confirm` beside a live server is
   refused; a real DEK rotation works.
2. `rotate --confirm` killed with SIGKILL at six points spread over a clean rotation's
   wall time: `encryption validate` still passes, the server starts, data decrypts, and a
   later rotation completes. A SIGKILL cannot be aimed at a particular statement, so this
   shows the property at the sampled points, not at every instruction.
3. `rotate-kek`: the old passphrase is then refused at start (`wrong passphrase or
   corrupted key file`), the new one works, and an archive taken before the rotation
   restores with the old passphrase.
4. `migrate-provider` password to `file` and back to `password`: under `file` the server
   starts with no `KEYORIX_MASTER_PASSWORD`; the new passphrase on the way back comes from
   `KEYORIX_NEW_MASTER_PASSWORD`, never argv.

`scripts/drills/rotation-under-load.sh` repeats the DEK rotation with a load generator
(reads, writes, deletes) running. It shows that `rotate --confirm` beside the live server is
refused without disturbing the load, that every failed request falls between the server stop
and the server being healthy again, and that every write acknowledged around the rotation
reads back afterwards. There is no online rewrap: the window is the server being stopped.

Not covered (they need infrastructure the drill does not have): cloud KMS, TPM and Shamir
providers, and any container or Kubernetes variant (pending a run on the e2e VM).
Usage and environment are the same as the [upgrade drill](drill-upgrade.md); for PostgreSQL
also set `DRILL_PG_DSN_FILE2` to a second empty database (the restore leg).
