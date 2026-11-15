- **INV-HTTP-openapi-error-typed-and-leakfree** Across EVERY operation the OpenAPI document
  enumerates (307 ops / 246 paths), every error response (HTTP status >= 400) with a JSON body
  carries the documented uniform error envelope — a non-empty string `error` type-label and an
  integer `code` (the shape `httpx.SendError` writes and `components.responses.Error`
  documents) — and no error body (any status) leaks a Go stack frame / panic text, an internal
  filesystem path or the repo module path, raw SQL/driver text (`SQLSTATE`, `pq:`,
  `no such table`, `UNIQUE constraint`, …), or seeded secret material. Why: this is the
  fuzz/census-level, whole-surface counterpart of INV-HTTP-error-responses-uniform and
  INV-HTTP-core-error-answered-through-shared-classifier (which guard the per-`sendError`-call
  and per-handler views); a handler that error-maps a core failure to a blanket 500 with
  `err.Error()` would leak storage/driver text to a client, and a handler that answers a
  bespoke non-enveloped body would break the thin generated clients that parse the typed
  `error` label. Guard: `TestOSFErrorMapperCensus` (deterministic — drives not-found /
  malformed-id / empty-and-garbage-body probes against every enumerated op under admin and a
  zero-grant user; asserts 0 leaks and 0 missing `error`/`code`) and oracle 6
  (`osOracleTypedError`) in `FuzzOpenAPIStateful`, which gates the same two properties on every
  fuzzer-reached error response. Red-proofed: a planted `SendError` that appended
  `SQLSTATE … /mnt/data/…go:42` was caught as 427 leaks, and a planted `SendError` that dropped
  the `error`/`code` keys was caught as 427 missing-shape (both reverted, never committed).
  Not covered: that `message` is the exact documented sentence (only that it is not a leak);
  `code != status` (recorded as a candidate, not gated — a handler may carry an app code);
  empty/non-JSON error bodies (recorded as a candidate — net/http's own pre-handler 400/431 are
  out of scope); undeclared non-2xx STATUSES (recorded as a HARDENING candidate; oracle 1 gates
  undeclared 5xx, oracle 2 undeclared 2xx); leakage in an encoded/transformed form a literal
  substring scan cannot see.
