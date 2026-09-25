# Air-gap backup / disaster-recovery runbook

For an operator running `keyorix-server` on a single machine with **no internet
access** (ADR-108 §B3): how to take a backup, verify it, move it off-host, and
restore it — either as a routine drill or a real disaster-recovery event.
Everything here uses only `keyorix-server admin <command>` (never a network
call, never a running listener — see `keyorix-server admin --help`) and the
audit hash chain (ADR-029). Nothing in this runbook requires — or should ever
require — reaching out to the internet.

## What a complete backup is

A complete backup is **two files' worth of content, bundled into one
archive**: the database, and every encryption key-material file (the KEK salt
and wrapped DEK — `internal/keyfiles.Registry`, the same enumeration `admin
audit` checks). Neither alone is useful: the database without the keys is
unreadable ciphertext; the keys without the database have nothing to unwrap.
`admin backup`/`admin restore` handle both together, in one archive, so you
never have to separately track which key files go with which database
snapshot.

Only local/sqlite storage is covered by `admin backup`/`admin restore` today.
For a Postgres-backed deployment, use `pg_dump`/`psql` directly — see
[SELF_HOSTING.md §5](SELF_HOSTING.md).

## Routine backup

```sh
keyorix-server admin backup --output /path/to/keyorix-backup-$(date +%F).tar.gz
```

This takes the same exclusive database lock every other `admin` command does
— it refuses to run alongside a live server or another `admin` command,
rather than risk a torn/inconsistent snapshot. The database snapshot itself
uses SQLite's `VACUUM INTO`, which is internally consistent regardless of
journal mode, then re-opens the snapshot with a **fresh** connection and runs
`PRAGMA integrity_check` before it's trusted — a corrupt snapshot is caught
at backup time, loudly, not discovered later when a restore fails on a host
that may no longer have the original database to re-back-up from.

**`--output` must not already exist** — each backup is a distinct,
timestamped artifact; the date-stamped filename above is not optional
decoration, it's how you avoid accidentally trying to overwrite one.

**Move the archive OFF this host.** A backup that never leaves the machine it
was taken on protects against nothing that machine itself could lose (disk
failure, ransomware, a bad `rm`). Copy it to removable media, a second host,
or an object-lock bucket before you consider the backup done.

## Exporting an audit-chain anchor (do this too, not instead)

A backup archive's checksums (SHA-256 per file) prove the archive was not
**corrupted** in transit — a bad copy, a truncated transfer, bit rot. They do
**not** prove it wasn't **tampered with**: anyone who can edit the archive can
recompute a SHA-256 to match their edit. Tamper evidence comes from the
ADR-029 audit hash chain instead, and — for the strongest guarantee this
system offers — from a checkpoint anchor held somewhere the backup's own
"holder" doesn't control:

```sh
keyorix-server admin audit export-checkpoint --output /path/to/checkpoint-$(date +%F).json
```

This packages the most recently **signed** checkpoint (written periodically by
the audit-checkpoint scheduler — see `audit_checkpoints.schedule` in your
config, default 24h) into a small JSON file. Copy that file to write-once or
otherwise-external media (a burned CD/DVD, a WORM-mode USB stick, an
object-lock bucket) — **held OUTSIDE this host**, ideally not alongside the
backup archive itself. An anchor genuinely held externally is the one check
that constrains even a host admin who holds both the database and its
checkpoint signing key (see `docs/design-b4-offline-audit-verify.md` §2). If
no checkpoint has been written yet, this command fails rather than fabricate
one — wait for the scheduler's next cycle (its interval is logged at server
startup), or lower `audit_checkpoints.schedule` if you need one sooner.

## Restoring (drill, or the real thing)

Restore into a **fresh, empty data directory**, with the **same config**
(same key-material paths) the backup was taken from:

```sh
keyorix-server admin restore --input /path/to/keyorix-backup-2026-09-25.tar.gz
```

What this does, in order:

1. Every file in the archive is checksum-verified against the manifest
   before anything is written to disk.
2. The archive's key-file set must match this config's encryption settings
   **exactly** — a partial or mismatched key-file restore (e.g. a backup
   taken mid key-rotation) is refused outright rather than silently leaving
   the database undecryptable later.
3. Each file (database and key files alike) is written **atomically** — a
   temp file, fsynced, then renamed/linked into place — so a crash or
   failure partway through never leaves a target file truncated or
   half-written. Refuses to overwrite an existing, non-empty database or key
   file unless `--overwrite-existing` is given; with that flag, the existing
   file is moved aside to `<path>.pre-restore-<timestamp>` rather than
   truncated, so an unrecoverable mistake still has a way back.
4. Pending migrations are applied (idempotent) — so a backup taken on an
   older binary and restored onto a newer one ends up ready to start, not
   merely restored to its old schema.
5. **`admin verify-audit` runs automatically** against the restored database
   and its verdict is printed. Restore **fails (non-zero exit)** if the audit
   chain reports BROKEN. A bare re-walk (no external anchor) can still miss
   tail-truncation or a genesis re-seed — see the next section for the
   stronger check.

Confirm the restore further:

```sh
keyorix-server admin diagnose
```

### Cross-checking against the externally-held anchor

If you exported a checkpoint anchor before things went wrong, verify the
restored database against it directly:

```sh
keyorix-server admin verify-audit --json --anchor /path/to/checkpoint-2026-09-20.json
```

Check `.verdict == "VALID"` and `.external_anchor.supplied == true` /
`.external_anchor.authenticated == true` in the JSON output. `authenticated`
additionally requires `--checkpoint-key-file` (the KEK-derived checkpoint
signing key, extracted out of band — never the KEK or passphrase itself); a
supplied-but-unauthenticated anchor still cross-checks the chain's head/
chained-event count against the external copy, just without cryptographic
proof it came from this exact key. Read the full report's "What this run
does NOT prove" section (or `--help`) — a compliance claim from this tool
should always be read alongside what it explicitly did not check, not just
the top-line verdict.

## Automated end-to-end drill

`scripts/airgap-e2e.sh` runs this entire flow for real, in a container with
`--network none` (proving none of it needs internet access): boots a real
server, bootstraps an admin user, creates a real project + secret over the
HTTP API, waits out an audit-checkpoint cycle, exports the checkpoint anchor,
stops the server, backs up, restores into a **fresh** data directory,
verify-audits the restored database against the externally-held anchor,
boots a server against the restored data and confirms the secret **value**
round-tripped correctly — then a negative leg: corrupts a byte inside the
archive and confirms restore refuses it (non-zero exit) instead of silently
accepting damaged input.

```sh
./scripts/airgap-e2e.sh
```

Requires Docker or Podman, and `jq` on the host running the script (not
inside the container — the container never needs it). Skips cleanly (exit 0)
if neither Docker nor Podman is available; this is a manual drill, not a
build dependency. Not run in CI — CI already covers the archive-parsing/
atomic-write layer directly (`server/admin/backup_restore_*_test.go`, plus
`FuzzReadBackupArchive`); this script is for validating the real container
image and the real HTTP-driven flow, which takes real wall-clock time
(tens of seconds, to wait out a checkpoint interval) and a real container
engine CI shouldn't need for every push.

**Known blocker (as of 2026-09-25):** `docker build -f server/Dockerfile .`
currently fails on a clean checkout — `server/admin/init.go` imports
`github.com/keyorixhq/keyorix/configs`, but `.dockerignore` excludes
`configs/` from the build context, so the Go build inside the image fails
with `no required module provides package .../configs`. This is a
pre-existing regression from the PR that added `admin init`
(`server/admin/init.go`, not owned by this track), not something introduced
here — filed as a handoff in the BACKUP track report
(`~/proj/prompts/reports/BACKUP.md`) rather than fixed in this PR, since
`.dockerignore`/`init.go` are outside this track's owned paths. Until it's
fixed, either drop `configs/` from `.dockerignore`, or pre-build the image
yourself with a workaround and point the script at it via
`KEYORIX_AIRGAP_E2E_IMAGE=<your-tag> ./scripts/airgap-e2e.sh` (skips the
build step entirely).

## What this runbook does NOT cover

- **Postgres-backed deployments** — back up/restore with `pg_dump`/`psql`
  directly (SELF_HOSTING.md §5); `admin backup`/`admin restore` refuse
  non-sqlite storage outright.
- **Cross-backend migration** (SQLite → Postgres) or **version-skipping
  upgrades** beyond what `admin restore`'s own automatic migration step
  handles — these are documented usage patterns, not wrapped commands, per
  the v2 backup design (PR #2100, `docs/design-b3-backup-v2.md` once merged).
- **A portable, backend-neutral archive format.** Today's archive is a
  SQLite file snapshot plus key files (`admin backup`'s own format,
  version 1) — not yet the streaming, backend-neutral format
  the v2 design (PR #2100) describes. v2 restore is designed to accept
  v1 archives until 1.0.
