# scripts/fuzzing/soak: long-running resource-growth soak (SOAK-1)

`run-soak.sh` runs the [`server/soak`](../../../server/soak/README.md) harness: a seeded mixed workload against the real router, sampled for goroutines, descriptors, DB connections, heap, temp files and bookkeeping-table rows, judged by three oracles. It is not a `targets.d` entry because it is not a `Fuzz*` function (`targets.d` lines are `<pkg>|<FuzzName>|<fuzztime>`); it is a timed `go test` with its own flags.

## Commands

```
# smoke: about a minute, SQLite (this is also what the red-proof uses)
scripts/fuzzing/soak/run-soak.sh smoke

# long, SQLite: 30 minutes, 4 workers
scripts/fuzzing/soak/run-soak.sh long 30m 4

# long, PostgreSQL (a throwaway schema is created and dropped by the harness)
KEYORIX_TEST_PG_DSN='postgres://user:pass@host:5432/db?sslmode=disable' scripts/fuzzing/soak/run-soak.sh long 30m 4

# the red-proof: control plus five planted leaks, each must fail the right oracle
server/soak/testdata/redproof/run.sh
```

Run from the repository root. Output goes to `.scratch/soak/<UTC>-<mode>-<backend>/` (override with `SOAK_OUT`): `series.tsv` (every sample), `verdicts.txt`, `run.log`, and `heap/baseline.pb.gz` + `heap/final.pb.gz`. The script exits non-zero when a hard oracle fails, a mix kind never did its job, or the run did not finish.

## Running it on pve01

1. Respect the PVE-BENCH-LOCK convention before starting; the soak is CPU and disk heavy and its timings are the thing being watched.
2. In a fresh clone of origin/main on pve01 (not a shared checkout), start it detached, for example `systemd-run --collect --unit soak-1 --working-directory <clone> scripts/fuzzing/soak/run-soak.sh long 30m 4`, once with SQLite and once with `KEYORIX_TEST_PG_DSN` set to a disposable database.
3. Do the same at 2h once (`long 2h 4`): the smoke cannot show whether the bounded caches plateau; the 30 minute run can, and 2 hours separates "slow leak" from noise.
4. Copy `series.tsv`, `verdicts.txt` and the heap profiles off the host before cleaning up (raw-data rule: keep the cell-level files, not only a table).

## What to look at

1. **`verdicts.txt`, the `hard` lines first.** A `FAIL ... baseline goroutines ... grew: +N <function>` names the leaking function; `FAIL ... stacks <function>` prints the whole stack of a goroutine that did not exist at baseline; `db_in_use` is a connection not returned; `temp_files` lists the names; `fds` is a descriptor leak. Any hard FAIL on an unplanted run is a **finding**: reproduce with the same seed (`KEYORIX_SOAK_SEED`), then file it.
2. **`heap_inuse` and `heap_objects` in `series.tsv`, last half of the run.** Bounded caches fill early; a series still rising linearly in the last half is the lead. Attribute it with `go tool pprof -sample_index=inuse_space -base heap/baseline.pb.gz heap/final.pb.gz`. The smoke's first-half rise (about 8.8 to 12.2 MB, attributed to `secretMetadataCache` and the token cache) is expected to flatten once the cache cap (10,000 entries per map) is reached, around 20,000 requests: confirm that it does.
3. **`rows_*` columns.** `audit_events` and `secret_access_logs` rise by design. `sessions`, `rate_limits`, `login_attempts`, `notifications` and `password_histories` should be flat or bounded; a steady rise there is a bookkeeping leak (rows nothing purges).
4. **The WARN lines** of oracle (a) are leads, not verdicts (report-only). The calibration in `server/soak/testdata/calibration.tsv` comes from a 10,000-request smoke; recalibrate from two or three long runs before trusting a long-run WARN, and commit the new numbers with the run directories' names.
5. **Not covered, so do not conclude from silence**: gRPC, SSO, SCIM, MFA/WebAuthn, machine identities, dynamic-secret leases, bulk endpoints, backup/restore, the scheduler (full list and the coverage table in the harness README).
