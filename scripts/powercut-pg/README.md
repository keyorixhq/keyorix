# scripts/powercut-pg — real disk-level power-cut test for the PostgreSQL backend

The PostgreSQL twin of `scripts/powercut` (which does the same for SQLite). It
crash-tests the Postgres storage backend's commit **durability** across a real
`dm-flakey` power cut: no acknowledged commit may be lost, no structural tear may
be observable after recovery.

Like `scripts/powercut`, it builds its **own** throwaway stack and never touches
a real block device or the host's real Postgres cluster:

- its own sparse file → loop device → `dm-flakey` → ext4 mount, and
- its own `initdb`'d PostgreSQL 17 cluster on that mount, on a scratch Unix
  socket / non-default port, run as the `postgres` system user (the server
  refuses to run as root).

## Running

```
sudo scripts/powercut-pg/run-dmflakey-pg.sh --cut-mode wal --durability strict
sudo scripts/powercut-pg/soak.sh --minutes 20          # rotate all shapes for 20 min
```

Needs root, `dm-flakey` (`modprobe dm-flakey`), `dmsetup`/`losetup`/`mkfs.ext4`/
`e2fsck`, and PostgreSQL 17 server binaries (`/usr/lib/postgresql/17/bin` or on
PATH). `run-dmflakey-pg.sh` builds the Go tool itself if `--bin` is omitted.

## Oracle

Events are **Keyorix audit events** committed through the **production storage
factory** (`storage.type: postgres`), exactly mirroring the SQLite tool's shape.
After the cut and recovery:

1. every commit **acknowledged before the cut** is present (no lost commit);
2. the audit **hash chain verifies** (`VerifyAuditChain`) — the Postgres analog
   of the SQLite tool's `PRAGMA integrity_check` + hash-chain pair;
3. `pg_amcheck --heapallindexed` is clean (heap + btree structural tearing,
   across every table — a torn page cannot be committed given `full_page_writes`);
4. `postgres` performed a **clean WAL replay** on restart (checked in the server
   log, not just "it started" — the Postgres-specific part the in-process SQLite
   tool has no equivalent of);
5. `e2fsck -fn` on the ext4 is clean.

**Positive control** (wal/checkpoint): judged against *all* acks the run must
FAIL, because commits acknowledged *after* the cut were dropped — proving the cut
took effect and the PASS is not vacuous.

### Durability: strict vs standard — read this before trusting a green run

On Postgres the **default** audit durability is `standard` (ADR-112 Amendment 3):
the audit commit issues `SET LOCAL synchronous_commit = off`, so a returned
`LogAuditEvent` does **not** promise the WAL record was fsync'd. Treating an
acknowledgement as a durability promise under `standard` is **unsound** — an
acknowledged-then-lost commit there is by design, not a defect.

The tool therefore defaults to `--durability strict` (an acknowledgement means
the WAL record was fsync'd before `COMMIT` returned — the sound oracle, mirroring
SQLite's `synchronous=FULL`). `--durability standard` is run as a **negative
control / red-proof**: it reliably loses acknowledged-before-cut commits on the
cut, which is what proves the oracle can actually go red.

Empirically (91.7 min / 478 cuts, 2026-11-17, PostgreSQL 17 on this host):

| shape                | runs | before-cut commits lost |
|----------------------|------|-------------------------|
| wal / strict         | 124  | **0** |
| checkpoint / strict  | 123  | **0** |
| clean / strict       | 118  | **0** (sanity control) |
| wal / standard (ctl) | 113  | 4406 (≈39/run — by design) |

All 478 restarts recovered via clean WAL replay. Zero strict-mode findings.

## CI wiring (the flagged unknown, resolved 2026-11-17)

Does any CI job actually run the `server/faultops` mock-interface fuzzers against
a real Postgres DSN?

- **Yes, seed corpus only, full-profile only.** `.github/workflows/ci.yml`, job
  `test-suite`, sets `KEYORIX_TEST_PG_DSN` **job-wide** and starts a Postgres 16
  container per running leg; its `faultops-1..faultops-5` legs run
  `go test ./server/faultops`. So the faultops fuzzers' **seed corpus** runs
  against real Postgres — but only on the FULL profile (`merge_group`, push to
  `main`, or a PR labeled `ci:full`; a normal `pull_request` runs faultops on
  SQLite only, per CI-LIGHT-1), and only as `go test` (seed corpus), never as
  `go test -fuzz` (active mutation).
- `pg-race-tests.yml` and ci.yml's `closures-pg` job also set the DSN but run
  `internal/core` / `internal/storage` / the closures check, **not** faultops.
- Verified locally 2026-11-17: with `KEYORIX_TEST_PG_DSN` set, the faultops
  worlds genuinely build on Postgres (`PROFILE world.postgres open+migrate+indexes
  ~600 ms` per world, a fresh schema created/dropped each time) and both the
  smoke tests and `FuzzStorageFaultOperations` (seed corpus + a 90 s live fuzz)
  **pass** against real Postgres — the opt-in capability is **not broken**, just
  slow (~3 execs/s on PG vs far faster on SQLite, because each world
  create/drops a schema and bootstraps), which is why no CI job active-fuzzes it.

## What this does NOT model

Same caveats as `scripts/powercut`: a disk whose volatile write cache lies about
flushes, torn sector writes below the bio layer, or any filesystem other than
ext4. `dm-flakey` honours flushes issued before the switch and drops whole bios
after it. A PASS means "no acknowledged commit lost on ext4 over dm-flakey in this
run", not a proof for all power-loss behaviour.
