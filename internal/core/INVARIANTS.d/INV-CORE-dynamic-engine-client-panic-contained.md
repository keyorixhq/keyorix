- **INV-CORE-dynamic-engine-client-panic-contained** A panic inside a third-party client
  library called by a dynamic-secret engine (`Issue`, `Revoke`, `Renew`) or a rotation
  executor (`Rotate`, `GenerateUpstream`) never unwinds into `internal/core`. Both are
  built only through `dynamic.New` and `rotation.NewManager`, which wrap them
  (`dynamic.Contain`, `rotation.containExecutor`); the wrapper converts the panic into
  `*dynamic.EngineClientPanicError` (`errors.Is(err, dynamic.ErrEngineClientPanic)`) that
  carries the backend, the operation and no panic text (the text can hold target data or an
  admin DSN). The panic text and stack go to the server log only, through
  `ports.RedactSensitive` and one quoted line. Core treats it as any other engine failure:
  a panicking `Issue` leaves no lease row, a panicking `Revoke` leaves the lease
  `revoke_failed` (never `revoked`, no `RevokedAt`; the sweeper retries it), a panicking
  `Renew` leaves the lease and its expiry as they were, and the HTTP/gRPC answer is the
  existing engine-failure one (502-class), not a 500. Core code must therefore not call a
  concrete engine or executor type directly, only what the two constructors return. Why:
  no `recover()` existed between a client library and core code holding a lease row or an
  audit step.
  Guard: `internal/dynamic/hostile_engine_panic_test.go`
  `TestHostileTargetNeverPanicsIntoCaller` and `internal/rotation/hostile_executor_driver_test.go`
  `TestHostileTargetNeverPanicsIntoRotationCaller` (every DSN-based engine and executor
  against a loopback target answering malformed frames; red on the pre-fix tree for the MySQL
  client), `contain_test.go` in both packages (typed error, no panic text, generating
  executors stay generating), `TestNewReturnsContainedEngines`, and
  `internal/core/dynamic_secrets_engine_panic_test.go` (lease semantics above).
  **Not covered**: a panic on a goroutine the client library starts itself cannot be
  recovered by a wrapper; the cloud engines and executors (AWS, GCP, Azure, Kubernetes) are
  exercised through stubs only, not against a hostile server; a panic in `Issue` after the
  target created the account loses the generated account name, so that account is not
  cleaned up by core (same as any `Issue` error today); a client that allocates without
  bound on a hostile length prefix is a memory problem, not a panic, and is not contained
  here.
