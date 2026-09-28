# Upgrading Keyorix

**Verification status of this guide (2026-09-28, Session Q, item Q3): every
command below is marked either UNVERIFIED or VERIFIED. Nothing has been run
against a clean environment yet — that's Q4 (release QA), which is gated on a
set of PRs that were all still open at the time this guide was written (see
`~/proj/prompts/reports/SESSION-Q.md`). Do not treat an UNVERIFIED command as
proven; re-run this whole guide once Q4 actually executes, and update the
markers in place.**

## 1. Always back up first

Before any upgrade, take a full backup — database *and* encryption keys, both
required (the database without the keys is unreadable ciphertext; the keys
without the database are useless). See section 4 below for the current
backup command and format, and `docs/SELF_HOSTING.md` §5 for the
Docker-Compose/Postgres procedure.

**UNVERIFIED**: the exact backup command to run depends on which format your
current binary writes — see section 4.

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

**UNVERIFIED**: not yet run end to end against a real v0.95.1 install in this
session. Q4 step 2 ("Upgrade: install v0.95.1 … upgrade to the candidate,
verify data, run `admin verify-audit`") is where this gets proven.

## 3. Upgrading from v0.94.x or v0.93.x (version skip)

**What's actually been proven, and what hasn't:** PR #2293 (Session H, item
H6, still open as of this writing) built a real end-to-end harness that
downloads the actual **v0.95.0** release binary, takes a backup with it,
carries that data onto HEAD running against a real PostgreSQL 16 instance,
and confirms secrets decrypt identically, the audit chain still verifies, and
authz answers are unchanged. That is a real, binary-level proof — but it
covers exactly one hop: **v0.95.0 → HEAD, on Postgres.** It does **not**
cover v0.94.x or v0.93.x as a starting point, and it does not cover a
SQLite-backed install skipping versions. If you're upgrading from v0.94 or
earlier, or on SQLite, there is currently no equivalent proof — treat the
single-hop path below as the only currently-substantiated route, and open
each intermediate release's own upgrade notes if in doubt.

**The mechanical shape H6 proved**, once you're are on a version whose
`admin backup` still writes the v1 (physical, SQLite-only) archive format
(see section 4): v1 can only restore into SQLite, so getting an old
SQLite-era install onto HEAD/Postgres is a 3-hop procedure, not a direct
restore:

1. Restore the old binary's v1 archive into an **intermediate SQLite**
   database, using HEAD's `admin restore` (v1 reading is kept indefinitely,
   see section 4).
2. Take a fresh v2 backup of that intermediate SQLite database.
3. Restore that v2 archive into the real Postgres target.

```sh
# UNVERIFIED (mirrors scripts/release-qa/scenario_version_skip_postgres.sh,
# not independently re-run by this session):
keyorix-server admin restore --input old-v1-backup.tar.gz --output-db ./intermediate.sqlite
keyorix-server admin backup --db ./intermediate.sqlite --output intermediate-v2.tar.gz
keyorix-server admin restore --input intermediate-v2.tar.gz --target-dsn "$POSTGRES_DSN"
```

If you're going from v0.94/v0.93 straight to a version whose `admin backup`
already writes v2 (post-#2270), the same 3-hop shape should still apply
mechanically (v1 read support doesn't change), but that specific starting
point has not been run by anyone as of this writing. **Recommendation:**
upgrade to v0.95.1 first (a version this repo has direct RC verification
for — see `~/proj/prompts/release-notes-v0.95.1.md`), confirm the install is
healthy, then upgrade again to v0.95.2. Two proven single-version hops beat
one unproven multi-version skip.

## 4. Backup format: v1 vs v2

- **What your binary currently writes** depends on whether PR #2270 has
  merged. Before it merges, `admin backup` still writes the v1 (physical,
  SQLite-only) format described in `docs/SELF_HOSTING.md` §5. Once #2270
  merges, `admin backup` writes **only** the new v2 (backend-neutral,
  NDJSON/logical) format — there is no v1-output mode anymore.
- **v1 archives still restore.** `admin restore` auto-detects the archive's
  declared format version and dispatches to the right reader; v1-reading
  support is kept "until 1.0" per the design doc's own decision (design-b3-
  backup-v2.md §3.6 decision 3). You do not need to convert an old v1 archive
  before restoring it — `admin restore --input old.tar.gz` on HEAD works
  directly.
- **v2 adds Postgres support.** Before #2280 merges, `admin backup`/`admin
  restore` only work against SQLite; Postgres backup/restore is v2-only.
- **The manifest signing key depends on the KEK, not on anything global.**
  Per PR #2263 (H2, still open): the manifest is HMAC-signed with a key
  derived (via HKDF) from that specific archive's own KEK at the time the
  backup was taken. Per PR #2270 (H3, still open), restore unwraps the KEK
  from the **archive's own staged key files**, never the live target's — so
  an archive's manifest stays verifiable on its own terms regardless of what
  happens to the target's keys afterward.
- **What happens after a KEK rotation (`keyorix encryption rotate`):** a
  rotation re-wraps the DEK under a new KEK on the *live* install. It does
  **not** retroactively touch any existing backup archive — an archive taken
  before the rotation carries its own pre-rotation KEK-derived keys inside
  it and restores/verifies exactly as it did before. Rotate, then take a
  fresh backup afterward if you want your most recent backup to reflect the
  new KEK; you do not need to re-take or migrate old backups because of a
  rotation. **UNVERIFIED**: this is read directly from the PR descriptions
  and the design doc, not independently exercised against a real rotation +
  restore in this session — confirm with a real `encryption rotate` →
  `admin backup` → `admin restore` cycle in Q4 before relying on it
  operationally.
- **Tamper detection:** v1's archive-level checksums only catch corruption
  (a bad copy, a truncated transfer, bit rot) — anyone with write access to
  the archive can recompute them to match tampered content. v2's HMAC-signed
  manifest additionally requires the KEK-derived key to forge, so it closes
  that specific gap. v2 restore also fails closed on a **stale** backup by
  default (PR #2233, still open): restoring an archive older than the
  target's own recorded audit high-water mark is refused unless you pass
  `--allow-rollback` explicitly.

## 5. Helm-specific steps

- **New bootstrap token secret (PENDING #2271, not yet merged).** Once
  merged, the chart generates and wires `KEYORIX_BOOTSTRAP_TOKEN`
  automatically (idempotent across `helm upgrade`) — before this PR, the
  chart set the master/DB/admin passwords but never this token, which the
  server also requires to authorize `POST /system/init`; following the
  README's quick-start literally left the pod `Ready` with no admin user
  ever created, a silent failure. After #2271 merges, `NOTES.txt` prints the
  retrieval command for a manual `keyorix system init` if you need it.
- **New password-length gate (PENDING #2271).** The chart will refuse to
  render if `auth.adminPassword` is under 16 characters. Today (before this
  PR) that's silent — the server itself still enforces its own password
  policy at bootstrap time, so a too-short password fails there instead,
  but (see #2295 below) a rejected password used to be able to brick the
  install. **Check your values file's `adminPassword` length before
  upgrading the chart, once #2271 ships.**
- **First-boot bootstrap retryability (PENDING #2295).** Before this PR, a
  password rejected at bootstrap (e.g. containing the admin username) could
  leave the database half-seeded, and every later attempt — even a
  compliant password — failed with an unrelated 500 until a full wipe. Once
  #2295 merges, the whole bootstrap runs in one transaction and a rejected
  attempt writes nothing, so retrying with a corrected password just works.
- **UNVERIFIED**: real `helm install`/`helm upgrade` against a kind cluster
  with the candidate images, per Q4 step 1.

## 6. Air-gapped image rename

The published air-gapped image is renamed from `keyorix-server-lean` to
`keyorix-server-airgap` (ADR-109 step 6 / B2-B3). If you pull this image by
tag in a CI pipeline, a compose override, or a Helm values override, update
the repository name before your next pull — `keyorix-server-lean` is not
expected to keep receiving new tags going forward.

```sh
# old
ghcr.io/keyorixhq/keyorix-server-lean:v0.95.1

# new
ghcr.io/keyorixhq/keyorix-server-airgap:v0.95.2
```

**UNVERIFIED**: image pull not independently re-run by this session; the
rename itself is confirmed merged on `main` (`ddadf47c`) and was validated
end-to-end against a real air-gapped image build in PR #2231 (still open —
that PR is the validation pass for this whole air-gapped track, including
the SQLite `airgap-e2e.sh` drill and the documented Postgres manual-backup
procedure).

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

**UNVERIFIED**: no rollback drill has been run in this session. Recommend
one as part of Q4's release QA before this section is treated as proven.

## 8. See also

- `docs/SELF_HOSTING.md` §4 (master password / KEK), §5 (backup and
  restore), §6 (upgrades), §9 (troubleshooting).
- `docs/AIRGAP_RUNBOOK.md` for the air-gapped-specific backup/restore
  procedure (Postgres path there is currently a manual `pg_dump`/`psql`
  procedure, not `admin backup`/`admin restore`, which explicitly refuse
  non-SQLite storage as of this writing).
- `~/proj/prompts/release-notes-v0.95.2.md` for the full list of changes in
  this release, with merge status per item.
- `design-b3-backup-v2.md` for the full backup-v2 design (§3 format, §5
  manifest signing, §6.3 rollback protection, §7 streaming).
