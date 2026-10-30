# Key rotation runbook: what to run, what to verify, how to go back, what not to do

[j6-key-rotation.md](j6-key-rotation.md) is the step-by-step with the expected output of each
command, including the several-replicas procedure. This runbook is the operator's wrapper
around it: pick the right rotation, the preflight, the checks afterwards, rollback, and the
mistakes that cost data. Every command below was checked against the cobra definitions of
`keyorix-server admin` and `keyorix` in this repository.

## 1. Which rotation

| You need to... | Run | What changes | What does not |
|---|---|---|---|
| Replace the key that encrypts the data (suspected DEK exposure, policy) | `admin encryption rotate` | A new DEK; every DEK-encrypted row is re-encrypted in **one** transaction (secret versions, API tokens and clients, password resets, MFA secrets, dynamic-secret configs and leases, notification channels). | The master passphrase. |
| Change the master passphrase (departure, exposure, policy) | `admin encryption rotate-kek` | The wrapped DEK, under a KEK derived from the new passphrase and a fresh salt. The evidence-signing and audit-checkpoint keys change with it. | No database row; the DEK value. The database must still be reachable: it is read to finish an interrupted DEK rotation first. |
| Move the KEK to another provider (password, file, env, exec, shamir, tpm, aws-kms, gcp-kms, azure-kms) | `admin encryption migrate-provider --to-type ... --confirm` | The DEK wrapping only; the previous wrapped DEK is kept as `<dek_path>.migrate-backup.*`. | Secret values. Like `rotate-kek`, it needs the database reachable. |
| Replace the lost-admin recovery key | `admin recovery-key rotate` | The recovery verifier; the old key stops working at once. See [j5-lost-admin.md](j5-lost-admin.md). | Not an encryption key. |

Rotating the DEK does not change the audit-checkpoint key (it is KEK-derived); rotating the KEK
does. That matters for the audit chain: section 5.

## 2. Preflight (all of it, every time)

1. **Back up, off the host.** `admin backup` is the only rollback for a DEK rotation.

   ```bash
   keyorix-server admin backup --output /backups/keyorix-pre-rotation-$(date +%F).tar.gz --config ./keyorix.yaml
   ```

   The archive holds the database and every key file (including its own wrapped DEK). On SQLite
   stop the server first; on PostgreSQL it works beside a live server, but fails and leaves no
   archive if a rotation is in progress. `--output` must not exist. The passphrase comes from
   `KEYORIX_MASTER_PASSWORD`, `--passphrase-file`, `--passphrase-fd` or `--passphrase-stdin`.
2. **Check the current state.** Both are read-only and take no lock:

   ```bash
   keyorix-server admin encryption status --config ./keyorix.yaml
   keyorix-server admin encryption validate --config ./keyorix.yaml
   ```

3. **Baseline the audit chain** so any change afterwards is yours to explain, and write a fresh
   external anchor (details in [audit-chain-break-runbook.md](audit-chain-break-runbook.md) §2, §7):

   ```bash
   keyorix-server admin verify-audit --config ./keyorix.yaml          # server stopped; expect VALID, exit 0
   keyorix-server admin audit export-checkpoint --output /media/anchor/checkpoint-$(date +%F).json --config ./keyorix.yaml
   ```

4. **Keep every server stopped** on the database from here to the end of section 3 (stop them
   before step 3 on SQLite; `verify-audit` on the configured database and `export-checkpoint`
   take the same exclusive lock). All rotation commands refuse to run beside a live server or
   another admin command. `--force` overrides that refusal: do not use it here. On
   PostgreSQL `encryption rotate` and `encryption auth-encryption rotate` refuse `--force`
   (`--force cannot override it for a DEK rotation on PostgreSQL`): `dek.lock` only sees replicas on this host, and a replica on
   another host that is still running can commit a row under the old DEK after the sweep.
   `rotate-kek` and `migrate-provider` open the database for this lock (#3513) even though
   only key files change, so they fail with `cannot connect to the database to check for a
   running server` while the database is unreachable: make sure it is up (and reachable with
   the configured credentials) before you start.
5. **Have both passphrases ready** (for `rotate-kek`): the current one and the new one, the new
   one in a file with mode `0600` owned by you or root (the flag refuses anything group- or
   world-readable). There is no flag that takes a passphrase as an argument, by design.
6. Run on the server host. With `storage.type: remote` the rotation commands refuse ("must run on
   the server host").
7. **Rotate with the same version as the servers, never an older admin binary or image.**
   Check `keyorix-server admin version` against the running servers' version. An admin binary
   that predates part of the rotation does that part wrong without knowing it: a v0.96.x
   `admin encryption rotate` against a database a v0.97 server has used re-encrypts every row
   but leaves the DEK epoch naming the old DEK, so replicas with the new key set refuse to start
   and replicas still holding the old key set start and write rows nobody can read later
   (recovery: section 6, "rotated with an older admin binary"). From v0.97 on the database records
   the newest rotation protocol of the servers that used it (`dek.rotation_protocol`), and an
   older admin binary that reads it refuses (`this binary's DEK rotation is older than the one
   this database's servers use`); v0.96.x binaries do not read it, so for them this rule is the
   only protection.

## 3. Run it

DEK, preview then do it ([j6](j6-key-rotation.md) shows the output):

```bash
keyorix-server admin encryption rotate --config ./keyorix.yaml --dry-run
keyorix-server admin encryption rotate --config ./keyorix.yaml --confirm
```

Before it commits, the rotation checks its own work inside the sweep transaction: it first
round-trips a sample of the newest secret versions through the new DEK, then reads back every
row it rewrote, in every swept table, and decrypts it with the new DEK. Any row that does not
decrypt stops the rotation before the commit, with the table and row id in the error
(`pre-commit verification of the DEK rotation failed: nothing was committed and the old DEK
stays active: secret_versions id=2 ...`). The log ends with `[sweep] pre-commit verification:
all N re-encrypted values decrypt under the new DEK` on success. The check reads every row a
second time, so plan for the sweep to take longer than the dry run.

KEK:

```bash
keyorix-server admin encryption rotate-kek --config ./keyorix.yaml --confirm \
  --passphrase-file ./old_master_password --new-passphrase-file ./new_master_password
```

The new passphrase must differ from the old one. When it finishes, set the new value everywhere
the server reads it (`KEYORIX_MASTER_PASSWORD`, the file `KEYORIX_MASTER_PASSWORD_FILE` points at,
or your provider's equivalent) **before** the next start, and update your offline copy.

With several replicas on one PostgreSQL database, follow [j6](j6-key-rotation.md) "Several
server replicas": stop all, rotate on one host, copy `dek.key` (and `kek.salt` for the password
provider) with `keyset.manifest.json` to the others, start. A replica holding an old `dek.key`,
or the new one without the new manifest, refuses to start.

## 4. Verify

```bash
KEYORIX_MASTER_PASSWORD_FILE=./new_master_password KEYORIX_CONFIG_PATH=./keyorix.yaml keyorix-server
keyorix-server admin encryption validate --config ./keyorix.yaml
keyorix secret get --id <id> --show-value        # the value is unchanged
keyorix audit logs --limit 20                    # admin.encryption.rotate / admin.encryption.rotate_kek
keyorix audit verify --full
```

`encryption validate` checks the key files and their permissions, not that the DEK opens the
data: with another install's `dek.key` in place it still prints `Encryption setup is valid`.
The check that the active key set decrypts every row is the dry run (server stopped; it
decrypts every row and writes nothing):

```bash
keyorix-server admin encryption rotate --dry-run --config ./keyorix.yaml
# good:  ✅ Dry run complete — no changes were made
# wrong: Error: dry-run rotation preview failed: ... failed to decrypt secret_version id=1: ...
```

Then take a second backup (`admin backup`, as in the preflight) with the post-rotation keys, and
keep the **old** passphrase for as long as you keep any archive taken before a `rotate-kek`: that
archive restores only with the passphrase that was current when it was taken.

## 5. After `rotate-kek`: the audit chain

`rotate-kek` and `migrate-provider` carry the audit verification state over to the new key
(`docs/design-audit-key-transition.md`):

- Before any key file is written, they verify the chain under the old key and record a key
  transition signed by both keys.
- After the commit, they re-sign the state, the high-water mark and the retention anchor
  under the new key, append a `system.audit_key_transition` event and write a fresh
  checkpoint.

The command prints each step. If the command is interrupted after the key files commit, the
server finishes the transition at its next start. A recorded break or discontinuity is
carried over, not cleared.

- Online, `keyorix audit verify` reads `VALID` straight after an honest rotation. Check it:

  ```bash
  keyorix audit verify --full
  ```

  `audit verification state discontinuity (key transition)` means the transition record is
  missing, forged or for another key epoch. A key change by an older binary after a recorded
  one also reads this way. Treat it like any discontinuity
  ([audit-chain-break-runbook.md](audit-chain-break-runbook.md) sections 1 and 2).
- Offline, export the **new** key and a **new** anchor, and keep the old key:

  ```bash
  keyorix-server admin audit export-checkpoint-key --output /secure/checkpoint-<date>.key --config ./keyorix.yaml
  keyorix-server admin audit export-checkpoint --output /media/anchor/checkpoint-<date>.json --config ./keyorix.yaml
  keyorix-server admin verify-audit --checkpoint-key-file /secure/checkpoint-<date>.key \
    --previous-checkpoint-key-file /secure/checkpoint-<old-date>.key --config ./keyorix.yaml
  ```

  With the new key alone, `verify-audit` reads `VALID` and lists the transition's old-key
  signature under "not proven". With the previous key it also proves that a holder of the
  new key alone did not forge the pre-rotation state.
- `compliance verify` still reports evidence packs signed before the rotation as "superseded
  key version", not tampered (the evidence-signing key is not carried over).

Rotate with the new binary only. Keep the old anchors, the old checkpoint keys and the note
of which key version signed them; do not overwrite them.

**Installs with purged audit history.** On an install that has had a retention purge, a key change
by an older binary leaves the retention anchor signed under the old key. The online walk then
needs genesis and reads broken, and a fresh checkpoint does **not** re-baseline it: the write
refuses the broken walk (RECOVERY-OPTIONS-1 F2). The current binary re-signs the anchor during the
transition, so this only follows a rotation done without it. To recover, rotate back to the previous
passphrase with the current binary, then rotate forward again with it.

A seal (an accepted audit loss, `admin audit accept-loss`) is carried over like the other signed
artifacts: the chain still reads `sealed` after the rotation, online and with the new key offline.
If the seal record cannot be trusted when the transition completes (replaced, garbled or forged
after the rotation was prepared, or an acceptance left unfinished), completion stops with
`the audit seal record cannot be trusted ... not completed` and signs nothing: no high-water
mark or checkpoint is re-signed against a seal list it cannot authenticate. The key change itself
stands. Treat the seal record as tampered with
([audit-chain-break-runbook.md](audit-chain-break-runbook.md) §7 and §8) and investigate. The
server retries the completion at every start and finishes it once the seals authenticate again.
Finish an unfinished acceptance (re-run `admin audit accept-loss`) **before** a key change: on top
of a key change its resume is refused, because the checkpoint it would replace is still signed
under the previous key (audit-chain-break-runbook.md §8, #3814).

## 6. Rollback

There is no command that reverses a DEK rotation. The two ways back are **roll forward**
(finish the rotation, or get the new key set to where it is needed) and **restore the
pre-rotation archive** (below). Roll forward whenever you can: a restore loses every write made
since the archive was taken.

### 6.1 A DEK rotation that failed midway

Every one of these leaves exactly one DEK under which every row decrypts. Rehearsed on SQLite
with the commands below (DEK-ROTATE-SAFETY-1); the PostgreSQL fence and epoch steps are covered
by the pg-gated tests named in `internal/encryption/INVARIANTS.d/`, not by a drill.

| What you see | State | What to do | What is lost |
|---|---|---|---|
| `pre-commit verification of the DEK rotation failed: nothing was committed and the old DEK stays active: <table> id=<n> ...`, or `re-encryption sweep failed — old DEK remains active: ... failed to decrypt <table> id=<n>` | Rolled back. `dek.key` is unchanged and `dek.key.pending` was removed; on PostgreSQL the epoch fence was lifted, so servers write again once started. | The named row does not decrypt under the **current** DEK either (a `canary ... does not decrypt under the current DEK` message says so): the damage predates the rotation. Find the row's last good copy: restore the latest archive that has it (the whole archive, below), or, if the row is an old version nobody needs, have it removed through the normal delete path. Then re-run `rotate --dry-run` (it must complete) and the rotation. If the row decrypts under the current DEK but not the new one (`... does not decrypt under the new DEK`), stop and report it: the rewrite itself was wrong. | Nothing the rotation did. The damaged row was already unreadable. |
| The command was killed, the host lost power, or the database connection dropped during the sweep (no `✅ DEK rotated` line) | The sweep transaction was rolled back. `dek.key` is the old DEK; a `dek.key.pending` may be left. | Run `encryption status`, then `rotate --dry-run` (must complete under the old DEK), then re-run the rotation: it discards the stale `dek.key.pending` first. Do not delete or copy `dek.key.pending` by hand. | Nothing. |
| `re-encryption sweep failed and may have committed — <dek_path>.pending was kept` or `failed to promote pending DEK to active after the re-encryption sweep committed` | The rows may already be under the new DEK, and `dek.key.pending` is its only copy. | Fix the cause the message names (disk full, read-only remount), then **on this host** run `encryption upgrade-aad` (it does not change the DEK; like every key-writing command it finishes an interrupted rotation first; `rotate --dry-run` does not) or start the server: either promotes `dek.key.pending` when the database's redo marker committed and discards it otherwise. Then `rotate --dry-run` must complete. Back up the key directory first; never delete `dek.key.pending`. | Nothing, if `dek.key.pending` survives. If it is lost after the commit, every swept row is lost with it: restore the archive. |
| PostgreSQL: `refusing to rotate: the database's DEK epoch is "..." but this host's DEK fingerprint is "..."` | Refused before anything was written. | This host's key files are not the database's current key set (another host rotated). Copy the current key files here, or run the rotation on the host that has them. | Nothing. |
| `this binary's DEK rotation is older than the one this database's servers use` | Refused before anything was written. | Run the rotation with the servers' version (preflight step 7). | Nothing. |

### 6.2 A DEK rotation that succeeded but was wrong

| What happened | How it shows | What to do | What is lost |
|---|---|---|---|
| The new key set did not reach every replica | That replica refuses to start (`the database's DEK epoch is ... this server's DEK fingerprint is ...` on PostgreSQL; a key-set manifest refusal without the new manifest). | Copy the current key files, `keyset.manifest.json` included, from the host that rotated and start it ([j6](j6-key-rotation.md)). | Nothing: no row was written under the old DEK. |
| The new `dek.key` was overwritten with the old one (config management, a stale volume snapshot) and no copy of the new one is left | `rotate --dry-run` fails with `failed to decrypt secret_version id=...` on every row; `encryption validate` still says valid. | Look for the new key set first: the rotating host's key directory, a post-rotation backup, `*.pre-restore-*` files. If it exists, put it back (roll forward). If not, restore the pre-rotation archive with `--allow-rollback` (below). | With a restore: every write since the archive (rehearsal: the one version written after the rotation was gone), and every revocation since comes back. |
| Rotated with an older admin binary (v0.96.x against a v0.97 database) | Replicas with the new key set refuse to start (`DEK epoch ... is not this server's DEK`); replicas with the old key set start but cannot read the swept rows. | Stop every server at once: an old-key replica writes rows nobody can read later. Distribute the new key set to every host. Then, with every server stopped, remove the stale epoch with the emergency SQL `DELETE FROM system_metadata WHERE key = 'dek.epoch';` and start **one** server with the new key set: it records the epoch again only after its DEK decrypts the newest secret version. If it refuses (`cannot decrypt its newest secret version`), an old-key replica wrote after the rotation: restore the pre-rotation archive. | Without a restore, nothing, provided no old-key replica wrote. With one, every write since the archive. |
| The rotation was fine but you want the old DEK back | Nothing is wrong. | Do not. Rotate again (roll forward) if the new DEK is suspect. Restoring the archive is the only way back to the old DEK. | With a restore: every write since the archive. |

### 6.3 Other rotations

| Where it went wrong | What to do |
|---|---|
| A KEK re-wrap (`rotate-kek`, `migrate-provider`) was killed or the host lost power | Nothing special: it leaves either the old or the new wrapped-DEK file, never a torn one. Run `encryption validate`, then re-run it if you still want it. |
| `rotate-kek` done, the server will not start (`wrong passphrase or corrupted key file`) | The configured passphrase is still the old one. Set the new one; nothing is lost. |
| `rotate-kek` done, and you want the old passphrase back | Rotate again with the sources swapped: `--passphrase-file ./new_master_password --new-passphrase-file ./old_master_password`. This re-wraps the same DEK under a fresh salt and again changes the checkpoint key (section 5). |
| `migrate-provider` was interrupted after the re-wrap | The previous wrapped DEK is on disk as `<dek_path>.migrate-backup.<nanoseconds>-<random>` (each run creates its own and never overwrites an earlier one); the DEK's plaintext value did not change. Keep it until you have verified. The server then names it in its start error; follow [Interrupted `rotate-kek` or `migrate-provider`](#interrupted-rotate-kek-or-migrate-provider). |
| `migrate-provider` failed verification and restored the previous DEK | The restore writes `<backup>.restoring` and renames it over `dek_path`, so `dek_path` is either the re-wrapped or the restored file, never a torn one. If the command was killed during the restore, a leftover `<backup>.restoring` is a complete copy of the backup; `migrate-provider cleanup` lists and removes it with the backups. |

### Interrupted rotate-kek or migrate-provider

Both leave `dek.key` wrapped under a KEK the configuration does not produce yet if they are
killed at one point, and every start then fails with `failed to unwrap DEK — wrong passphrase
or corrupted key file`. That error now names the leftover file it found and the line below
that applies. Stop the server and copy the key directory aside before you change anything.

| The error names | What happened | Recovery |
|---|---|---|
| `<salt_path>.pending exists: a rotate-kek was interrupted after it re-wrapped ...` | `rotate-kek` was killed after it renamed the new `dek.key` into place and before it renamed the salt. `dek.key` is under the new passphrase and the salt in `<salt_path>.pending`. | `mv <salt_path>.pending <salt_path>`, then start with the **new** passphrase. The start reconciles `keyset.manifest.json` with the renamed salt. |
| `<salt_path>.pending and <dek_path>.pending exist: a rotate-kek was interrupted before it replaced ...` | `rotate-kek` was killed before it touched `dek.key`, which is still under the previous passphrase. | Do not rename either file. Start with the **previous** passphrase (the next key writer or start resolves the leftovers) and re-run `rotate-kek`. |
| `<dek_path>.migrate-backup.<...> is the newest migrate-provider backup` | `migrate-provider` was killed after the re-wrap, or finished and `storage.encryption.key_provider` was not updated. `dek.key` is under the target provider; the backup is the same DEK under the previous one. | Set `storage.encryption.key_provider` to the provider you migrated to (the one `migrate-provider` printed) and start. To go back, run `keyorix-server admin encryption migrate-provider --to-type <previous provider> --confirm` from there. Keep the backup until the server starts; then `migrate-provider cleanup`. |

If the target provider cannot open `dek.key` (the KMS key is gone, the shares are lost), the
backup is the only copy under a KEK you still have. Restore it by rename, server stopped:
`cp -p <backup> <dek_path>.restoring && mv <dek_path>.restoring <dek_path>`. The key-set
manifest still records the re-wrapped DEK, so the next start refuses the file as not matching
it; once you have confirmed `<dek_path>` is that backup, move `keyset.manifest.json` aside so
the start adopts the current files (with a WARN and an `encryption.keyset_manifest_adopted`
audit event), as `migrate-provider`'s own rollback error says.

Restoring the archive (server stopped, same config and key paths, passphrase current when the
archive was taken):

```bash
keyorix-server admin restore --input /backups/keyorix-pre-rotation-<date>.tar.gz --overwrite-existing --config ./keyorix.yaml
```

`--overwrite-existing` moves each existing file aside to `<path>.pre-restore-<timestamp>` rather
than truncating it. The restore verifies the archive's signed manifest before writing, runs
`verify-audit` and fails on BROKEN. It refuses an archive that is behind the host's
`.audit-highwater-witness`; `--allow-rollback` overrides that, and records an
`admin.restore_rollback_override` audit event. Whether a pre-rotation archive trips that check
depends on whether the rotation advanced the witness; be ready for either. In the rehearsal
(SQLite, one rotation and one write after the archive) it did:

```text
$ keyorix-server admin restore --input ./backups/pre-rotation-2.tar.gz --overwrite-existing
Error: refusing to restore: this backup's audit trail (6 event(s)) is 1 event(s) BEHIND this host's own last known state (8 event(s)) ...
$ keyorix-server admin restore --input ./backups/pre-rotation-2.tar.gz --overwrite-existing --allow-rollback
verify-audit on the restored database: VALID
```

Afterwards every version from the archive decrypted under the restored key set and the version
written after the archive was gone. Run `rotate --dry-run` after a restore to confirm the
restored keys open every row, then start the servers with the restored key set on every host
(with several replicas, every host gets the restored key files, or it refuses to start). An
archive from before an accepted audit loss is refused as a rollback the same way, whatever its
event count.

## 7. What not to do

- **Do not use `--force`** to run a rotation beside a live server. The lock is what keeps a
  replica from writing under the key you are replacing (on PostgreSQL `encryption rotate`
  and `encryption auth-encryption rotate` refuse `--force` for that reason).
- **Do not rotate with an admin binary older than the servers** (preflight step 7), and do not
  start a server holding the old key set after a rotation to "see if it still works".
- **Do not delete `dek.key.pending`** after a failed or interrupted rotation: after a commit it is
  the only copy of the DEK the rows are under. The next key-writing admin command or server start
  on that host settles it.
- **Do not skip the backup**, and do not keep it only on the host that is being rotated.
- **Do not lose the old passphrase** while any archive taken before a `rotate-kek` is still one
  you may need.
- **Do not copy `dek.key` alone** to another replica: copy `keyset.manifest.json` with it (and
  `kek.salt` with the password provider), or confirm the replicas share the keys volume. Without
  the manifest the replica refuses to start; do not remove its manifest to get past that, which
  turns off the mixed-set check for that start.
- **Do not delete `*.migrate-backup.*` or `*.pre-restore-*` files** until the result is verified.
  `admin encryption migrate-provider cleanup --dry-run`, then `--confirm`, is the supported
  deletion. It takes the key-directory lock (`dek.lock`) exclusively, so it refuses while a
  server or a `migrate-provider`/rotation runs, `--force` or not: stop the server first.
- **Do not put a passphrase on a command line, in shell history or in a shared log.** Use a
  `0600` file, a descriptor, or stdin; the new passphrase on a `migrate-provider` back to the
  password provider comes from `KEYORIX_NEW_MASTER_PASSWORD` or the `--new-passphrase-*` flags.
- **Do not read an offline BROKEN right after `rotate-kek` as tampering** before comparing key
  versions (section 5), and do not treat a rotation as a fix for a broken chain: rotation neither
  repairs nor hides one ([audit-chain-break-runbook.md](audit-chain-break-runbook.md)).
- **Do not lose the key files.** `dek.key` and `kek.salt` are useless without the database and the
  database is unreadable without them; the preflight archive carries both.

## 8. Rehearse and gaps

`scripts/drills/key-rotation.sh` and `scripts/drills/rotation-under-load.sh` rehearse the offline
operations on a throwaway instance (see the end of [j6](j6-key-rotation.md)). The Kubernetes and
container variants, cloud KMS, TPM and Shamir providers are not covered by them: pending the e2e VM.
The recovery paths in section 6 were run with the real `keyorix-server admin` commands on a
scratch SQLite instance (DEK-ROTATE-SAFETY-1: a rotation refused over a damaged row, a rotation
killed with SIGKILL during the sweep, a lost new `dek.key` recovered by restoring the archive);
the PostgreSQL-only rows (epoch, `--force` refusal, older admin binary) are covered by pg-gated
tests, not by a drill.

Gaps in the product today:

- No online rotation: the window is the servers being stopped.
- No command to reverse a DEK rotation other than restoring an archive (by decision: roll
  forward, or restore).
- No command repairs a DEK epoch left stale by a rotation with an older admin binary; section 6.2
  uses emergency SQL for it.
- The pre-commit check proves every rewritten row decrypts under the new DEK, not that it
  decrypts to the same value; only its sample compares values.
- `verify-audit` checks the latest checkpoint and the key transition records, not every older
  checkpoint: older-epoch checkpoints other than the one each transition names are not
  re-verified (section 5).
- No command accepts a real audit loss (seal) yet: AUDIT-ACCEPT-LOSS-1.
