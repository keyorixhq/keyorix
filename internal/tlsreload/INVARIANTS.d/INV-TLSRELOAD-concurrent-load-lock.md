- **INV-TLSRELOAD-concurrent-load-lock** Under concurrent `GetCertificate` callers
  the same fail-closed invariant holds: no caller ever receives a torn, mismatched or
  empty cert/key pair. The `mu` mutex in `Reloader` serialises the reload check and
  the pointer swap; without it a concurrent reader could observe a partially-updated
  `r.cert`.
  Guard: `internal/tlsreload` `FuzzReloaderConcurrentLoad` (concurrent N=4 goroutines,
  oracles A/B/C/D/E; -race; `reloader_concurrent_fuzz_test.go`).
  **Not covered**: same exceptions as INV-TLSRELOAD-fail-closed; additionally does not
  verify the exact sequential differential (which pair is "currently expected" at each
  moment), only that the served pair is always from a coherent pool entry.
