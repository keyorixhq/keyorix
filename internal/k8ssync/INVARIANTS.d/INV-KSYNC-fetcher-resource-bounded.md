- **INV-KSYNC-fetcher-resource-bounded** The Keyorix fetcher dials only its configured
  loopback/allow-listed server — never a redirect- or response-chosen host (air-gap) — and
  no bounded-page hostile response shape drives its per-call network/allocation cost past a
  calibrated absolute ceiling, nor leaks goroutines/fds across calls. Why: `getJSON` caps
  each response body at `maxResponseBodyBytes` and `refuseRedirect` blocks redirects
  (`keyorix_fetcher.go`). Guard: `FuzzK8sSyncFetcherResource`
  (`internal/k8ssync`) wraps the shared `internal/fuzzutil/resguard` meters (NetMeter
  air-gap + `dials`/`net_bytes_in`, sampled `alloc_bytes`) around `FetchWithExpiry`, budget
  committed at `testdata/resguard-k8ssync-fetcher.json`.
  The `resolveID` page walk is capped client-side at `maxSecretListPages` (1000): a server
  advertising a larger `total_pages` makes the resolution fail with a plain error (never
  `ErrUpstreamGone`) after that many requests, instead of reading an unbounded cumulative
  response volume (each page body is capped, their number was not). Guard:
  `TestFetcher_SecretListPageCountIsBounded` (`internal/k8ssync`).
  REMAINING CORNER (HARDENING, see OP1 report §6): the cap bounds the request count, not
  the volume — 1000 full pages still exceed the per-call byte budget
  (`TestResguardK8sSyncPaginationRedGreen` shows a 3000-page walk tripping `net_bytes_in`;
  keep-alive keeps the dial count at 1, so volume, not dial count, is the signal). Lowering
  the cap or adding a cumulative-byte ceiling would close it.
