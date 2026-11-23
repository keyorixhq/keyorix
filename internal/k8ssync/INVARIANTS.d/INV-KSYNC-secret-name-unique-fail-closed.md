- **INV-KSYNC-secret-name-unique-fail-closed** A secret name that the server lists more
  than once for the requested project and environment is refused with a plain error, never
  resolved first-wins and never `ErrUpstreamGone`: which of two same-named entries is the
  intended one is unknowable to the agent, so picking one could materialise the wrong
  value, and reading the ambiguity as "gone" would wipe the synced copy. A name matched
  exactly once still resolves. The walk that looks for a second match is bounded by
  `maxSecretListPages` (see INV-KSYNC-fetcher-resource-bounded). Why: `resolveID`
  (`keyorix_fetcher.go`); KFZ-2026-171 / fuzz-corpus#176. Guard:
  `TestFetcher_DuplicateSecretNameFailsClosed`, with
  `TestFetcher_SingleSecretMatchStillResolves` as the liveness control
  (`internal/k8ssync`).
