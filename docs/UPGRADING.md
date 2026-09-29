# Upgrading Keyorix

**Verification status of this guide:** commands below are marked either
UNVERIFIED or VERIFIED. UNVERIFIED means it has not yet been run end to end
against a clean environment as part of this release's QA pass; treat it as
documented-but-unproven until it's flipped to VERIFIED.

## 1. Always back up first

Before any upgrade, take a full backup — database *and* encryption keys, both
required (the database without the keys is unreadable ciphertext; the keys
without the database are useless). See section 4 below for the current
backup command and format, and `docs/SELF_HOSTING.md` §5 for the
Docker-Compose/Postgres procedure.

```sh
keyorix-server admin backup --output backup-$(date +%F).tar.gz
```

**UNVERIFIED**

## 2. Upgrading from v0.95.x → v0.95.2

This is the normal, in-place upgrade path: same major/minor line, schema
migrations run automatically and are additive.

```sh
# Docker Compose
docker compose pull
docker compose up -d

# Single binary
# stop the old process, replace the binary, restart
```

Schema migrations run on boot. If a rolling multi-replica upgrade hits
`database schema epoch N is newer than this binary's schema epoch M`, that's
expected mid-rollout (see `docs/SELF_HOSTING.md` §9 troubleshooting table) —
not applicable to the bundled Helm chart, which is pinned to 1 replica.

**UNVERIFIED**

## 3. Upgrading from v0.94.x or v0.93.x (version skip)

**What's actually been proven, and what hasn't:** an end-to-end harness
downloads the actual **v0.95.0** release binary, takes a backup with it,
carries that data onto v0.95.2 running against a real PostgreSQL 16
instance, and confirms secrets decrypt identically, the audit chain still
verifies, and authz answers are unchanged. That is a real, binary-level
proof — but it covers exactly one hop: **v0.95.0 → v0.95.2, on Postgres.**
It does **not** cover v0.94.x or v0.93.x as a starting point, and it does
not cover a SQLite-backed install skipping versions. If you're upgrading
from v0.94 or earlier, or on SQLite, there is currently no equivalent proof
— treat the single-hop path below as the only currently-substantiated
route, and open each intermediate release's own upgrade notes if in doubt.

**The mechanical shape that's been proven**: an old release's `admin
backup` writes the v1 (physical, SQLite-only) archive format. v1 can only
restore into SQLite, so getting an old SQLite-era install onto v0.95.2 on
Postgres is a 3-hop procedure, not a direct restore:

1. Restore the old binary's v1 archive into an **intermediate SQLite**
   database, using v0.95.2's `admin restore` (v1 reading is kept
   indefinitely, see section 4).
2. Take a fresh v2 backup of that intermediate SQLite database.
3. Restore that v2 archive into the real Postgres target.

```sh
keyorix-server admin restore --input old-v1-backup.tar.gz --output-db ./intermediate.sqlite
keyorix-server admin backup --db ./intermediate.sqlite --output intermediate-v2.tar.gz
keyorix-server admin restore --input intermediate-v2.tar.gz --target-dsn "$POSTGRES_DSN"
```

**UNVERIFIED** (the commands above mirror the proven harness's shape; not
independently re-run against this exact release build yet)

If you're going from v0.94/v0.93 straight to v0.95.2, the same 3-hop shape
should still apply mechanically (v1 read support doesn't change), but that
specific starting point has not been run by anyone as of this writing.
**Recommendation:** upgrade to v0.95.1 first (a version with its own direct
RC verification), confirm the install is healthy, then upgrade again to
v0.95.2. Two proven single-version hops beat one unproven multi-version
skip.

## 4. Backup format: v1 vs v2

- **v0.95.2 writes only the v2 format.** `admin backup` produces the new
  backend-neutral, NDJSON/logical archive — there is no v1-output mode.
- **v1 archives still restore.** `admin restore` auto-detects the archive's
  declared format version and dispatches to the right reader; v1-reading
  support is kept "until 1.0" per the design doc's own decision
  (`design-b3-backup-v2.md` §3.6 decision 3). You do not need to convert an
  old v1 archive before restoring it — `admin restore --input old.tar.gz`
  works directly on v0.95.2.
- **v2 supports PostgreSQL.** `admin backup`/`admin restore` now work
  against both SQLite and PostgreSQL targets, not SQLite-only as before.
- **The manifest signing key depends on the KEK, not on anything global.**
  The manifest is HMAC-signed with a key derived (via HKDF) from that
  specific archive's own KEK at the time the backup was taken. Restore
  unwraps the KEK from the **archive's own staged key files**, never the
  live target's — so an archive's manifest stays verifiable on its own
  terms regardless of what happens to the target's keys afterward.
- **What happens after a KEK rotation (`keyorix encryption rotate`):** a
  rotation re-wraps the DEK under a new KEK on the *live* install. It does
  **not** retroactively touch any existing backup archive — an archive taken
  before the rotation carries its own pre-rotation KEK-derived keys inside
  it and restores/verifies exactly as it did before. Rotate, then take a
  fresh backup afterward if you want your most recent backup to reflect the
  new KEK; you do not need to re-take or migrate old backups because of a
  rotation. **UNVERIFIED**: not yet exercised against a real rotation +
  restore cycle — confirm with a real `encryption rotate` → `admin backup`
  → `admin restore` cycle before relying on it operationally.
- **Tamper detection:** v1's archive-level checksums only catch corruption
  (a bad copy, a truncated transfer, bit rot) — anyone with write access to
  the archive can recompute them to match tampered content. v2's HMAC-signed
  manifest additionally requires the KEK-derived key to forge, so it closes
  that specific gap. v2 restore also fails closed on a **stale** backup by
  default: restoring an archive older than the target's own recorded audit
  high-water mark is refused unless you pass `--allow-rollback` explicitly.

## 5. Helm-specific steps

- **Bootstrap token secret.** The chart generates and wires
  `KEYORIX_BOOTSTRAP_TOKEN` automatically (idempotent across `helm
  upgrade`) — the server requires this token to authorize `POST
  /system/init`. `NOTES.txt` prints the retrieval command for a manual
  `keyorix system init` if you need it.
- **Password-length gate.** The chart refuses to render if
  `auth.adminPassword` is under 16 characters. **Check your values file's
  `adminPassword` length before upgrading the chart** — a value that
  rendered before this release may now fail the chart render outright.
- **First-boot bootstrap retryability.** A password rejected at bootstrap
  (e.g. containing the admin username) no longer leaves the database
  half-seeded. The whole bootstrap runs in one transaction, so a rejected
  attempt writes nothing and retrying with a corrected password just works.

**UNVERIFIED**: real `helm install`/`helm upgrade` against a kind cluster
with the release images.

## 6. Air-gapped image rename

The published air-gapped image is renamed from `keyorix-server-lean` to
`keyorix-server-airgap`. If you pull this image by tag in a CI pipeline, a
compose override, or a Helm values override, update the repository name
before your next pull — `keyorix-server-lean` does not receive new tags
going forward.

```sh
# old
ghcr.io/keyorixhq/keyorix-server-lean:v0.95.1

# new
ghcr.io/keyorixhq/keyorix-server-airgap:v0.95.2
```

**UNVERIFIED**: image pull not yet independently re-run against the actual
v0.95.2 release artifact; the rename and the underlying build were
validated end-to-end against a real air-gapped image build (the SQLite
`airgap-e2e.sh` drill and the documented Postgres manual-backup procedure).

## 7. Rollback

If an upgrade goes wrong:

1. Stop the new version.
2. Restore the backup you took in step 1, using a binary matching the
   version that backup came from (an `admin restore` binary can read
   older-format archives, but restoring into a *newer* schema than the
   backup's own binary understands is not the supported direction — restore
   with the matching or a newer binary, then let migrations run forward
   again, not backward).
3. `admin verify-audit` after restore, on whichever binary you rolled back
   to, to confirm the audit chain is intact.
4. If the new version's database has already advanced the recorded schema
   epoch (ADR-097), a straight downgrade of the *binary* while keeping the
   already-migrated database is refused at startup by design (`database
   schema epoch N is newer than this binary's schema epoch M`) — this is
   why step 2 restores data from before the failed upgrade rather than
   attempting to run the new binary's data on the old binary.

**UNVERIFIED**: no rollback drill has been run yet against this release.

## 8. See also

- `docs/SELF_HOSTING.md` §4 (master password / KEK), §5 (backup and
  restore), §6 (upgrades), §9 (troubleshooting).
- `docs/AIRGAP_RUNBOOK.md` for the air-gapped-specific backup/restore
  procedure.
- `CHANGELOG.md` and the GitHub release notes for the full list of changes
  in this release.
- `design-b3-backup-v2.md` for the full backup-v2 design (§3 format, §5
  manifest signing, §6.3 rollback protection, §7 streaming).
