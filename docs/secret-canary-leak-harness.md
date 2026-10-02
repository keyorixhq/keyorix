# Secret canary-leak harness (server/faultops)

ADR-112 ("Secrets and audit") requires: *"Secret values never appear in logs,
error messages, URLs or metrics. Enforced by a test oracle over all
operations, not by review alone."* This document covers the fault-injection
half of that oracle, added in `server/faultops/canary_leak_fault_fuzz_test.go`.

A mature, independent canary-leak oracle already exists at
`server/http/canary_secret_leakage_fuzz_test.go` (`FuzzCanarySecretLeakage`,
#1952) — it scans every HTTP/gRPC response, the stdlib log, the full SQLite
schema (generic column introspection) and the raw on-disk file for a wide
set of canaries (secret values, PATs, sessions, MFA secrets, dynamic-secret
credentials), over a fuzzed sequence of hostile request *shapes*. What it
does **not** do is inject faults into the underlying `storage.Storage`
calls — so it never exercises the error-handling branch of a secret
operation, only the request-shape-driven branches. Error paths are where a
leak is most likely to hide: a wrapped storage error that echoes back the
value it was trying to persist.

`server/faultops` already has the fault-injection side
(`FuzzStorageFaultOperations`, `faultstorage.FaultyStorage`) and a catalog of
every operation driven through the real REST/gRPC transports
(`opCatalog`), but its only existing canary check (oracle (e) in
`fuzz_storage_fault_operations_test.go`) is two hardcoded literals
(`"fuzz-value"`, `"fuzz-value-updated"`) checked against one channel
(`opResult.Detail`, the HTTP/gRPC response). This harness generalizes that:
more literals, more channels, under fault injection, swept across every
secret-touching operation.

## What it covers

Two passes in `canary_leak_fault_fuzz_test.go`, one shared scanner:

1. **`TestFreshCanarySecretLifecycleUnderFault`** — mints its own unique,
   high-entropy canary (`crypto/rand`, never a static fixture) and drives
   create → update → delete directly against the real HTTP transport,
   faulting the underlying `CreateSecret`/`UpdateSecret`/`DeleteSecret`
   storage call (no fault, injected error, injected panic) at each step.
2. **`TestCanaryLeakAcrossSecretOperations`** — the broad sweep: every
   `opCatalog` entry whose key names a secret-shaped resource (REST
   `/secrets/...`, gRPC `SecretService`/`ShareService.ShareSecret`,
   secret templates, dynamic secrets) — read-only reuse of `opCatalog`,
   no edits to `opcatalog_test.go`, following the same convention as the
   existing `FuzzAuditCompleteness`. Each op runs unfaulted, then faulted at
   the first and last distinct `storage.Storage` method its own unfaulted
   dry run actually calls (discovered via `FaultyStorage.Calls()`, not a
   hand-maintained per-op table), both as an error and as a panic. Needles
   are `knownSecretValueLiterals` — every literal `opcatalog_test.go` itself
   assigns to a secret's value, grep-verified, not guessed.
3. **`FuzzCanaryLeakUnderFault`** — the same op set and scanner as a
   standalone `Fuzz` entrypoint, for continuous fuzzing coverage. Not wired
   into `FuzzStorageFaultOperations`'s `checkOracles` — that file
   (`opScopedBestEffortTables`/`knownOpenTolerances`) is a declared conflict
   hotspot; a standalone entrypoint gets equivalent coverage with zero edits
   to it.

Every captured channel is scanned after every run:

- the HTTP/gRPC response body/status the operation itself returned,
- the stdlib `log` package output emitted during the call (the sole logger
  in this codebase),
- every `AuditEvent` row written since the call started (`Description` and
  `Diff` columns),
- the `/metrics` endpoint.

Each needle is checked in raw form plus hex, base64 (standard and URL)
encodings — no legitimate channel in this codebase encodes a secret value,
so a match on the encoded form alone is already sufficient evidence.

## Red-proof

Before trusting a clean sweep, this harness's own detection was validated
against two independent planted leaks (not committed — done and reverted
during development, see the session report for the exact diffs and PASS/FAIL
transcripts):

- a `log.Printf` of the request's secret value in the create handler — caught
  as a `server log output` violation, all three fault variants;
- the create-secret audit event's description string carrying the secret
  value — caught as an `audit_events row` violation.

Both reproduced red without the real code change and green once reverted,
following this repo's "a sweep clean-verdict needs positive-control
validation" rule.

## What it cannot cover

- **Client-side logs.** Nothing here inspects a CLI's own stdout/stderr, a
  browser console, or any log line emitted outside this server process.
- **Non-literal leak shapes.** The broad sweep's needle set is the catalog's
  own known literals plus one fresh canary per lifecycle step — a leak that
  only manifests for a value shape neither of those two passes ever
  constructs (e.g. a secret value containing characters this harness's
  fixtures never use) is not exercised.
- **Exhaustive fault placement.** The broad sweep only faults the *first*
  and *last* distinct storage method call observed on an unfaulted dry run,
  not every method at every call ordinal — a bounded, documented sample
  (see the file's own doc comment), not exhaustive coverage of every
  possible fault point `FuzzStorageFaultOperations`'s full fuzzing space
  could eventually reach.
- **Everything `FuzzCanarySecretLeakage` (server/http) already disclaims** —
  see that file's own doc comment (raw-file/DB exemptions tied to the
  tracked, unfixed `NotificationChannel.URL` audit-diff finding, etc.).
