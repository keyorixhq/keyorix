- **INV-HTTP-soak-bounded-resource-growth** Under a sustained, seeded stream of mixed
  operations (secret create/read/update/rotate/delete, login/logout token churn, audit
  reads, project/environment churn) against the real in-process stack (NewRouter + auth
  middleware + handlers + core + crypto + storage), the server's resource use does not
  grow without bound: the goroutine count, the open-file-descriptor count, the
  heap-in-use after GC, and the on-disk database+WAL size per logical record each stay
  flat — their least-squares slope over the second half of the run stays under a
  calibrated per-10k-operations ceiling unless the trend is genuinely monotonic. This is
  the leak class a per-input fuzzer cannot see (it rebuilds or resets state every
  iteration). Why: a long-lived daemon that leaks a goroutine, an fd, a heap allocation,
  or an un-pruned row per request stays green on every unit test and every per-input
  fuzzer, then exhausts a limit in production days later (precedent: a per-fixture
  `time.AfterFunc` coalescer re-armed against a closed DB pinned a whole core graph).
  Guard: `soak_bounded_growth_test.go` (`TestSoakBoundedGrowth`, SQLite always +
  PostgreSQL when `KEYORIX_TEST_PG_DSN` is set; thresholds calibrated in its doc comment
  and in `/mnt/data/wave4/out/i5-REPORT.md` section 4). Not covered: background
  schedulers/rotation loops (this harness wires NewRouter+core, not server/main's
  `startSchedulers`, so their growth is out of scope and is exercised by the kill-9/edge
  soak drills instead); a remote client's connection-pool fds (requests run over a local
  httptest.Server + keep-alive client); and growth slower than the calibrated per-10k-ops
  ceiling.
