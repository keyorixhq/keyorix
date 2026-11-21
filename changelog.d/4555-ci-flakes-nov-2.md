### Testing
- **Three CI flakes fixed (PILOT-FLAKES-NOV-2).** The stale-salt boot-log test in
  `server/admin` reads its log capture only under a lock (a background logger of
  another test raced the bare buffer under `-race`, #4501), and the Postgres live
  backup fixture now closes the storage it builds so its trigger-integrity check
  no longer outlives the test. `internal/egressguard` pins that stray files in the
  root-level scratch dirs it skips (`tmp/`, `.scratch/`, `.redproof-*` exports) do
  not affect its scan, while same-named dirs below the root are still scanned.
- **Soak heap oracle has a 2 MiB noise floor (#4389).** On the default 1.5k-op run
  the heap verdict now also needs a 2 MiB fitted rise over the second half, so
  sample noise no longer extrapolates into a false leak. Stated coverage loss: a
  per-op heap leak below about 2.8 KiB/op is not caught on that run (it needs a
  manual `KEYORIX_SOAK_OPS` of about 6700 or more); `TestSoakHeapOracle_FloorBoundary`
  pins the floor from both sides.
