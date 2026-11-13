# i6-gen — old-release backup fixture generator

This directory holds the generator that produces the **old-version restore
fixtures** task I6 consumes: a v2 logical backup archive written by a *real*
older released binary (built from its git tag, using that tag's own
`admin backup` code path — `runAdminBackup`), plus an `expected.json` sidecar
recording, in the OLD code's own view, what was put in the store (plaintexts,
roles, grants, counts). That sidecar is the "old" side of the differential
oracle; the current-main restore test is the "new" side.

`zz_i6gen_test.go.txt` is **reference source, intentionally not compiled in
main** — it uses unexported helpers from the tag's `server/admin` package
(`writeBackupRestoreTestConfig`, `chdirTest`, `loadConfig`, `runAdminBackup`,
`captureStdout`, `resetBackupRestoreFlags`, the `backupOutput` flag var) and
only compiles *at that tag*. It is stored as `.txt` so it neither builds nor is
linted here. The produced archive is what gets committed as a fixture; the
generator itself never runs in CI.

## How the committed fixtures were produced

For a target tag `<TAG>` (the fixtures in-tree today are for `v0.96.3`):

```sh
# 1. Check out the released tag into a throwaway worktree.
git worktree add --detach .scratch/wt-<TAG> <TAG>

# 2. Drop the generator into that tag's server/admin package so it can reach
#    the unexported backup/restore test helpers.
cp scripts/i6-gen/zz_i6gen_test.go.txt .scratch/wt-<TAG>/server/admin/zz_i6gen_test.go

# 3. Run it. It writes <out>/backup.tar.gz + expected.json (+ dek.key/kek.salt,
#    which the archive also carries internally, so they are not committed).
#    Default out dir is .scratch/snapshots/<TAG>; override with I6_OUT_DIR.
go test -C .scratch/wt-<TAG> ./server/admin/ -run TestI6Generate -count=1 -v

# 4. Copy the small (<2 MB) archive + sidecar into the fixture tree. Both the
#    admin restore test and the backupfmt fuzzer read these.
cp .scratch/snapshots/<TAG>/backup.tar.gz  server/admin/testdata/i6-oldversions/<TAG>/backup.tar.gz
cp .scratch/snapshots/<TAG>/expected.json  server/admin/testdata/i6-oldversions/<TAG>/expected.json
cp .scratch/snapshots/<TAG>/backup.tar.gz  internal/backupfmt/testdata/i6/<TAG>-backup.tar.gz

# 5. git add -f the *.tar.gz (the repo .gitignore excludes *.gz; the existing
#    v0.95.x fixtures are force-added the same way).
```

The archives are deterministic small fixtures (~8 KiB), well under the 2 MB
fixture budget, so they are committed rather than regenerated at test time.

## What the fixture deliberately does NOT contain

- A **non-empty audit chain**: a valid, linked chain is not producible at the
  raw-storage seeding layer this generator uses (it needs full core/auth
  context). The `audit_events` table is empty — an empty chain verifies VALID.
  Non-empty-chain old→new restore is already covered by the real-binary
  fixtures `server/admin/testdata/v0.95.3-backup.tar.gz` (TestAdminRestore_V0953Archive)
  and `v0.95.0-backup.tar.gz` (TestBackupRestore_PropertyRoundTrip_V1ArchiveOnHEAD).
- **Pending key-rotation state** and **passphrase-change history**: no
  straightforward raw-storage API exists for them at this tag; the structural
  tables are present but empty.

See `expected.json`'s `notes` field for the per-fixture record of this.

## Adding another tag

Repeat the steps for another buildable tag in the N-2…N window (e.g. v0.96.1,
v0.95.3), create `server/admin/testdata/i6-oldversions/<TAG>/`, and add the tag
to `i6Tags` in `server/admin/i6_restore_oldversion_test.go`. No test-body change
is needed. Only tags whose archive stays under 2 MB are committed; larger ones
would be generated into `.scratch/` at test setup instead (none seen so far).
