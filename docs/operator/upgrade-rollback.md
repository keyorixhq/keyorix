# Upgrade and rollback runbook

How to move an install to a newer release and how to go back, with the commands as
they were run. For what changes in each release read [UPGRADING.md](../UPGRADING.md);
for backup and restore in general, [SELF_HOSTING.md](../SELF_HOSTING.md) §5.

**What was run (2026-10-22, e2e VM, UPGRADE-ROLLBACK-1).** The published images
`ghcr.io/keyorixhq/keyorix-server` and `keyorix-web` **0.96.1 → 0.96.3**:

- the shipped `docker-compose.yml` of the v0.96.1 tag on PostgreSQL;
- the `keyorix-server` binaries taken out of those two images, on SQLite and on
  PostgreSQL 16, driven by the helpers of `scripts/drills/lib.sh` (the
  [upgrade drill](drill-upgrade.md) plus the steps below).

The seeded data was the same in every run: an admin with TOTP enrolled, two projects,
three secrets (one with three versions), a second user, a share, and a machine
identity with a token and a role. A DEK rotation (`admin encryption rotate --confirm`)
was done on 0.96.1 before the upgrade, so each run also had an audit history with a
verified chain. Every check below passed unless it says otherwise. v0.96.2 has a tag
but its images were never published: go from 0.96.1 to 0.96.3 directly.

## 1. Which binary can run on which database

| Release | Schema epoch | Floor it records | Runs on a database last migrated by |
|---|---|---|---|
| v0.96.0, v0.96.1, v0.96.3 | 2 | 2 | any v0.96.x |
| `main` / v0.97.0 | 5 | 3 | v0.96.x or newer; once it has started, **no** v0.96.x binary starts on that database again |

The schema epoch and the floor are stored in `system_metadata`. A server
refuses to start when the floor recorded there is above its own epoch. Between v0.96.1
and v0.96.3 nothing on disk changes: no migration, no key-envelope, ciphertext, audit or
TOTP format change. This was checked as follows:

- the schema dump and `system_metadata` are byte-identical before and after the
  upgrade and after a second start;
- `git diff v0.96.1 v0.96.3` touches no storage, encryption, audit or backup code.

So within v0.96.x you can swap the binary or image in either direction (§4A). Going
from v0.96.x to v0.97.0 is one-way for the binary: going back means restoring a
backup (§4B and [UPGRADING.md §6q](../UPGRADING.md)). The v0.96.x binary refuses with
`database declares a minimum compatible schema epoch of 3`.

`admin restore` refuses an archive whose schema epoch is newer than its own binary's
epoch. A v0.97 backup therefore cannot be restored with a v0.96.x binary.

## 2. Before the upgrade: the backup, concretely

Docker Compose on PostgreSQL. The backup runs beside the live backend:

```sh
docker compose exec backend ./keyorix-server admin backup --output /tmp/backup.tar.gz
(umask 077 && docker compose exec -T backend cat /tmp/backup.tar.gz > ./keyorix-backup-pre-upgrade.tar.gz)
docker compose exec backend rm /tmp/backup.tar.gz
```

Do not copy the archive out with `docker compose cp backend:/tmp/backup.tar.gz ...`.
In the shipped compose file `/tmp` is a tmpfs, which `docker cp` cannot read. It fails
with `Could not find the file /tmp/backup.tar.gz in container ...` (this was the
command in SELF_HOSTING.md until this change). That tmpfs is also capped at 64 MiB,
so for a larger archive raise its `size=` first.

SQLite (binary install). Stop the server first; a backup beside a live SQLite server is
refused:

```sh
systemctl stop keyorix-server          # or however you run it
keyorix-server admin backup --output keyorix-backup-pre-upgrade.tar.gz --config keyorix.yaml
```

Then, in both cases:

- [ ] The archive is non-empty and copied off the host. Record its `sha256sum`.
- [ ] The master password (`secrets/master_password`, or `KEYORIX_MASTER_PASSWORD`) is
  stored somewhere other than this host. The archive is useless without it.
- [ ] `admin verify-audit` says `Verdict: VALID` on the old release. On Compose:
  `docker compose stop backend`, then
  `docker compose run --rm --no-deps backend ./keyorix-server admin verify-audit`,
  then `docker compose start backend`.
- [ ] Note the encryption key paths in your config (`storage.encryption.dek_path`,
  `salt_path`). A restore only accepts an archive whose key paths are the
  same as the target config's (`restore refuses a mismatched key-file set (restore into
  the same config the backup was taken from)`). An archive from a binary install
  (`keys/kek.salt`) does not restore into the Compose stack (`/app/keys/kek.salt`)
  unchanged.

## 3. The upgrade

Docker Compose. Both images are pinned in `docker-compose.yml`; edit both tags, then
pull and recreate:

```sh
sed -i -E 's#(ghcr.io/keyorixhq/keyorix-(server|web)):0\.96\.1#\1:0.96.3#' docker-compose.yml
grep 'image: ghcr.io/keyorixhq' docker-compose.yml     # both lines must say 0.96.3
docker compose pull
docker compose up -d
docker compose ps                                      # backend and web: healthy
```

Binary install: stop the server, replace the binary, run `keyorix-server admin validate
--config keyorix.yaml`, then start the server.

Check after the upgrade:

- `docker compose logs backend` shows no `ERROR`, `panic` or `refus` line. On
  0.96.1 → 0.96.3 the only ADR-112 lines are the two `... is enforcing on its ADR-112
  secure-by-default value` INFO lines that 0.96.1 already logged. No grace-period line
  appeared, and MFA stayed enforced throughout. The 0.96.1 install had already recorded
  `adr112.require_mfa.enforced` and `adr112.file_permission_check.enforced` in
  `system_metadata`. The grace period in
  [UPGRADING.md](../UPGRADING.md#mfa-after-an-upgrade-the-grace-period-and-its-banner)
  concerns installs that come from before ADR-112 (v0.95.x).
- An admin logs in with password + TOTP. Known secrets read back with their values and
  version counts, shares are intact, and a machine token still reads.
- A new secret can be written and read.
- `admin verify-audit` (as in §2) says `VALID` and the chain has grown.
- A second start (`docker compose restart backend`) changes nothing in the schema. The
  migrations run on every start and are idempotent.

**Backing up with the new binary before its first start (installs coming from v0.95.x).**
Until the new server has started once, each notification channel's webhook URL still sits
in a plaintext legacy column; the server's first start is what encrypts it, and
`admin migrate` upgrades the schema without doing that. `admin backup` refuses in that
window (`start the server once to finish the upgrade migrations, then back up`) instead of
writing an archive that has lost the URLs, and leaves no archive behind. Start the
server once and wait until it is healthy (stop it again before a SQLite backup, as in §2),
then back up. Checked on v0.95.3 with
`scripts/release-qa/backup_inplace_upgrade_check.sh <work-dir> v0.95.3 [<pg-source-dsn> <pg-target-dsn>]`:
`admin migrate`, refused backup, first start, backup, restore into a fresh target; the
channel URL and per-table row counts match, on SQLite and on PostgreSQL.

## 4. Rollback

Pick the path by what you need to keep.

### 4A. Image or binary only (same schema epoch: within v0.96.x)

This keeps everything written on the new release. It is verified for 0.96.3 → 0.96.1.
After the downgrade, 0.96.1 read the secrets 0.96.3 had written and wrote new ones, and
`verify-audit` was VALID with both binaries. Upgrading again afterwards also worked.

```sh
sed -i -E 's#(ghcr.io/keyorixhq/keyorix-(server|web)):0\.96\.3#\1:0.96.1#' docker-compose.yml
docker compose pull
docker compose up -d
```

This path does not exist across a schema-floor change: v0.97 → v0.96.x is refused at
start (§1). Use 4B there.

With incremental audit verification on, rolling the binary back to a release older than
the audit verification state discontinuity (see the changelog) and upgrading again leaves
`keyorix audit verify` at `BROKEN` with `audit verification state discontinuity (before a
recorded break)`. The older binary re-signs the verification state without the fields
that place it against the audit chain. That alarm is sticky and has no accept command yet
([audit-chain-break-runbook.md](audit-chain-break-runbook.md)). If you need a clean
verification status, use 4B.

### 4B. Restore the pre-upgrade backup

Everything written after the backup is lost. That includes revocations: an account
suspended or a token revoked after the backup is active again. Review the audit trail
for what happened in between.

**Into fresh volumes (a replacement host, or after `docker compose down -v`).** Use the
old release's pins and follow SELF_HOSTING.md §5, "Restore" (`docker compose run ...
admin restore --input ...`, then `up -d`).

**In place, PostgreSQL (Docker Compose):**

```sh
# pins back to the old release first (as in 4A), then:
docker compose stop backend
docker compose exec -T postgres psql -U keyorix -d keyorix \
  -c 'DROP SCHEMA public CASCADE; CREATE SCHEMA public;'
sudo chown 1001 ./keyorix-backup-pre-upgrade.tar.gz && chmod 600 ./keyorix-backup-pre-upgrade.tar.gz
docker compose run --rm -v "$PWD/keyorix-backup-pre-upgrade.tar.gz:/tmp/backup.tar.gz:ro" \
  backend ./keyorix-server admin restore --input /tmp/backup.tar.gz \
  --overwrite-existing --allow-rollback
docker compose up -d
```

- **Empty the database first.** `--overwrite-existing` does not empty a PostgreSQL
  database (see "What not to do").
- **`--overwrite-existing`** is needed because the key files on the `keyorix_keys`
  volume already exist. The old ones are kept as `*.pre-restore-<timestamp>`.
- **`--allow-rollback`** is needed because this host's audit trail is ahead of the
  archive. Without it the restore refuses: `refusing to restore: this backup's audit
  trail (N event(s)) is M event(s) BEHIND this host's own last known state`.
- **Dropping the schema** works on the bundled `postgres` service, where `keyorix` owns
  the database. On a managed PostgreSQL where the role does not own `public`, drop and
  recreate the database instead.

The run ended with `verify-audit on the restored database: VALID`. After `up -d`, the
seeded data was there and the secret written after the upgrade was gone. On that
throwaway VM the archive was made readable with `chmod 644` rather than the owner-only
`chown 1001` + `chmod 600` shown above (the form SELF_HOSTING.md §5 recommends).

**In place, SQLite (binary install):** with the server stopped and the old binary,

```sh
keyorix-server admin restore --input keyorix-backup-pre-upgrade.tar.gz \
  --overwrite-existing --allow-rollback --config keyorix.yaml
```

The existing database file and key files are moved aside as `*.pre-restore-<timestamp>`.
Delete them once the rolled-back install is confirmed.

After any 4B restore, run `admin verify-audit` with the binary you rolled back to.

## 5. What not to do

- **Do not run `admin restore --overwrite-existing` over a PostgreSQL database that
  still holds data.** The restore replaces the key files first and then fails loading
  the rows (`duplicate key value violates unique constraint "permissions_pkey"`). The
  rows are left unchanged, so the database stays as it was, but the keys now come from
  the backup. If the DEK was rotated after that backup, the running install can no
  longer decrypt. Reproduced on 0.96.3: the MFA login then fails with
  `second-factor verification failed: A temporary error occurred ... (HTTP 503)`. To
  recover, move the newest `dek.key.pre-restore-*` and `kek.salt.pre-restore-*` back over
  `dek.key` and `kek.salt` (on Compose, in the `keyorix_keys` volume). Then empty the
  database and restore as in 4B.
- **Do not copy archives out of the backend container with `docker compose cp`** (§2).
- **Do not change the master password, or delete the `keyorix_keys` volume** (`docker
  compose down -v`), before the archive is off the host. The database alone cannot be
  decrypted.
- **Do not edit `schema_epoch` / `schema_min_compatible_epoch` by hand** to get an older
  binary to start. The floor is there because the older binary mishandles data the newer
  one wrote ([UPGRADING.md §6q](../UPGRADING.md)).
- **Do not use `--allow-rollback` as a routine flag.** It is for restoring an older
  backup on purpose, and it un-revokes everything revoked since that backup.
- **Do not skip 0.96.1 → 0.96.2.** There are no 0.96.2 images. Pin 0.96.3.

## 6. Measured times

These are wall-clock times on the e2e VM with the small seed above. They are dominated
by start-up and migration overhead, not by data volume: measure your own data with the
drill.

| Step | SQLite (binary) | PostgreSQL (binary) | Compose, PostgreSQL |
|---|---|---|---|
| DEK rotate `--confirm` (0.96.1) | 1.6 s | 1.5 s | 5.3 s (`run --rm`) |
| `admin backup` | 0.7 s (stopped) | 1.3 s (stopped) | 1.6 s (live, with copy-out) |
| Upgrade: first start of 0.96.3 to healthy | 1.1 s | 1.6 s | 18.9 s (`up -d`, recreate) |
| Second start of 0.96.3 | 1.1 s | 1.6 s | 7.0 s (`restart backend`) |
| 4A: 0.96.1 start on the upgraded data | 1.1 s | 1.6 s | 18.4 s (`up -d`) |
| 4B: restore into a fresh target (0.96.1) | 1.2 s | 18.4 s | — |
| 4B: in-place restore (0.96.1) | 1.3 s | 20.0 s (after emptying) | 23.7 s (empty + `run` restore) |
| Start after the in-place restore | 1.1 s | — | 7.0 s (`up -d`) |

Image pulls took 10–12 s per release. On PostgreSQL, a restore spends most of its time
migrating the empty schema (`admin init` + `migrate` of a fresh database took 19.5 s).
