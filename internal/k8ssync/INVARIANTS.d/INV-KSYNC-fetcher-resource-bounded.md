- **INV-KSYNC-fetcher-resource-bounded** The Keyorix fetcher dials only its configured
  loopback/allow-listed server — never a redirect- or response-chosen host (air-gap) — and
  no bounded-page hostile response shape drives its per-call network/allocation cost past a
  calibrated absolute ceiling, nor leaks goroutines/fds across calls. Why: `getJSON` caps
  each response body at `maxResponseBodyBytes` and `refuseRedirect` blocks redirects
  (`keyorix_fetcher.go`). Guard: `FuzzK8sSyncFetcherResource`
  (`internal/k8ssync`) wraps the shared `internal/fuzzutil/resguard` meters (NetMeter
  air-gap + `dials`/`net_bytes_in`, sampled `alloc_bytes`) around `FetchWithExpiry`, budget
  committed at `testdata/resguard-k8ssync-fetcher.json`.
  UNGUARDED-CORNER (HARDENING, see OP1 report §6): `resolveID` paginates
  `for page := 1; ; page++` with NO client-side page/request ceiling — a server
  advertising a large `total_pages` makes one resolution read an unbounded CUMULATIVE
  response volume (each page body is capped, their number is not), bounded only by the
  caller's context deadline. `TestResguardK8sSyncPaginationRedGreen` reproduces it (a
  3000-page walk trips `net_bytes_in`); keep-alive keeps the dial count at 1, so volume,
  not dial count, is the signal. A production fix would cap pages client-side.
