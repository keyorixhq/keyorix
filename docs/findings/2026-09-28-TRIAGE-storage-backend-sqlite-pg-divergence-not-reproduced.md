# TRIAGE: SQLite/PostgreSQL backend divergence (FuzzStorageBackendDifferential) — does not reproduce at HEAD

**Status:** closed, no fix needed — could not reproduce; root-caused to hardening that landed
after the original finding. This is a triage record, not a FINDING, because there is nothing
currently wrong to demonstrate.

**Original finding:** `keyorix-notes/claude/2026-09-20-FINDING-storage-backend-sqlite-pg-divergence.md`
(2026-09-20T21:37Z, rig A `vcd-keyorix-fuzz`, commit unknown/untracked — the rig ran off a moving
`origin/main` checkout, not a pinned SHA).

## What the original finding said

`op=1 operand=48` (`CreateUser("beta")` in the current op-index scheme) diverged: SQLite accepted
the create, PostgreSQL rejected it. The finding's own text says this did **not** reproduce
deterministically across three subsequent 60-minute slices that loaded the same input as part of
a growing seed corpus — it called this "state- or ordering-dependent, not a pure function of the
input bytes."

## What was checked at HEAD (this session, 2026-09-28)

1. **Direct replay** of the archived failing input
   (`~/proj/fuzz-archive/2026-09-20-night/FuzzStorageBackendDifferential-a0eadd0d861a2490`,
   raw bytes `A010A0(0000000000000000000`) against a real PostgreSQL 16 (local docker container,
   `KEYORIX_TEST_PG_DSN` set) and SQLite, via `go test -run FuzzStorageBackendDifferential/a0eadd0d861a2490 -v`:

   ```
   --- PASS: FuzzStorageBackendDifferential (0.91s)
       --- PASS: FuzzStorageBackendDifferential/a0eadd0d861a2490 (0.07s)
   PASS
   ok  	github.com/keyorixhq/keyorix/internal/storage/store	0.929s
   ```

2. **60-second fuzz burst** (`-parallel=2`, per FUZZ-MECH machine-use rules) against the same
   PostgreSQL instance, seeded with the full corpus (including the archived input):

   ```
   fuzz: elapsed: 1m0s, execs: 5523 (92/sec), new interesting: 17 (total: 19)
   PASS
   ok  	github.com/keyorixhq/keyorix/internal/storage/store	62.029s
   ```

   No divergence in 5,523 executions.

3. **Full 200-file seed corpus replay** (see the companion PR that adds this corpus,
   `E1`) against the same PostgreSQL instance: 202/202 pass (200 archived seeds + the two
   `f.Add` cases), 0 failures.

4. **The schema-provenance hardening already in the harness itself is the load-bearing change**:
   `backend_differential_fuzz_test.go`'s own doc comment (added 2026-09-25, see
   `TestBackendDifferentialHarnessSchema_MatchesProduction` in
   `backend_differential_schema_guard_test.go`) explains that earlier versions of this harness
   brought each backend up via a bare `db.AutoMigrate()`, which skipped every one of production's
   partial unique indexes (`uniq_users_username_folded_active`,
   `uniq_secret_nodes_project_env_name_active`, etc.). Both backends are now migrated through the
   real production entry point (`storagefactory.NewStorageFactory().CreateStorage`), and a pinned
   guard test (`TestBackendDifferentialHarnessSchema_MatchesProduction`, passing) stops this from
   silently drifting back.

   Two commits already on `main` independently close gaps in exactly this area, either of which
   is a plausible root cause for the specific `CreateUser` divergence:
   - `2fdeb675` / `2566e1b2` — `ensureSecretNodeNameIndex`'s sibling helpers (including the
     username/email folded-active indexes) were only guaranteed present from a **second**
     `migrateDatabase` run onward; a genuinely first boot could leave a unique index absent on
     one backend and present on the other, exactly the shape of an error-class disagreement on
     a duplicate-name create.
   - `b0d975e4` / `4e11b72a` (folded-name normalization wiring) and `dc8a21f9` (#1642
     constructor-enforced NFC/case normalization) — both landed after 2026-09-20 and directly
     touch how `CreateUser`'s uniqueness inputs (`UsernameFolded`/`EmailFolded`) are computed and
     enforced.

## Conclusion

Not reproducible at HEAD by direct replay, by a fresh 60-second/5,523-exec burst, or by a
202-case full-corpus replay. The most likely explanation is that one or more of the schema/
normalization hardening commits above already closed this class of divergence as a side effect,
consistent with the original finding's own observation that the failure was intermittent and did
not survive across even a single subsequent fuzzing session. There is no narrowly-scoped oracle
exception here because there is nothing currently failing to except — weakening the oracle
without a reproducing case would be exactly the kind of unearned exception this codebase's
engineering practices warn against.

**No code change is made by this triage.** If this class of divergence recurs, the harness
already records the real driver error on both sides (`lastSQLiteErr`/`lastPGErr`) precisely so a
future recurrence does not require this same archaeology.

## Action taken instead

The in-repo seed corpus for `FuzzStorageBackendDifferential` was empty except for two hand-written
`f.Add` cases. This session added a 200-file deduped seed corpus drawn from the 2,297 unique
corpus files recovered from the decommissioned vCD rig archives
(`~/proj/fuzz-archive/2026-09-21-vcd-decommission/vcd-keyorix-fuzz.{gocache-fuzz,night-gocache.gocache-fuzz}.tgz`
+ `vcd-keyorix-fuzz.testdata-fuzz.tgz`, `~/proj/fuzz-archive/2026-09-21-vcd-decommission/claude/2026-09-21-vcd-rigs-decommission-record.md`
is the archive's own manifest), selected by stratified sampling over corpus-entry length to
preserve both short and long/deep operation sequences, always including the archived finding
input itself. All 200 replay clean at HEAD against real PostgreSQL.
