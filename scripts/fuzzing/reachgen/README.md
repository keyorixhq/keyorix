# reachgen — reachability-first fuzz-harness lead generator

Complements [`autofuzzgen`](../autofuzzgen/README.md). Where autofuzzgen starts
from a CodeQL taint query over Keyorix's *own* sinks, reachgen starts from the
**dependency boundary**: it answers "which exported functions of third-party
modules does Keyorix code actually call, with arguments that can carry
attacker- or operator-influenced data?" and ranks the UNCOVERED ones so the
highest-traffic, unfuzzed entry points surface first.

It is **offline** (`GOPROXY=off`-safe; uses only the module cache) and
**read-only**. It never finds bugs itself — it is a lead generator, and every
emitted skeleton is reviewed and red-proofed by hand before any harness is
trusted, exactly like autofuzzgen.

## Run

```
go build -o /tmp/reachgen ./scripts/fuzzing/reachgen/cmd/reachgen
/tmp/reachgen -patterns ./... -top 40 -md ranked.md -out /tmp/drafts
```

- `-md` writes the ranked markdown table (the Phase-0 "what Keyorix really
  calls in its dependencies" deliverable).
- `-out` writes one draft harness `.txt` per fuzzable, uncovered lead.
- `-include-covered` keeps entries an existing Fuzz target already appears to
  cover (off by default).

## How it ranks

1. `go/packages` loads every Keyorix package with full type info.
   A test-support package (its non-test files import `testing` or testify,
   e.g. `internal/core/storage/storagetest`) is skipped and named on stderr;
   a test helper that imports neither is still scanned.
2. For each `CallExpr` whose callee is an **exported** func/method of a
   **third-party** package (dotted first path segment, not under the Keyorix
   module), reachgen records a call site.
3. A lightweight **intra-procedural** taint pass labels each site's argument
   provenance: `request-body` (a `string`/`[]byte`/`io.Reader`/`*http.Request`
   param reaches the arg), `uploaded-file` (`multipart.*`), `config`
   (a `Config`/`Options`-typed value, `os.Getenv`, or an `internal/config`
   value), `backend-response` (a value returned by a DB/driver/cloud call on
   `backendPrefixes`), else `static`.
4. Entries are filtered to those with ≥1 **untrusted** site, de-ranked if an
   existing `*_test.go` Fuzz target appears to cover them, and sorted by
   untrusted-site count then total call count.

## What this does NOT do (read before trusting a row)

See the package doc comment in `reachgen.go`. In short: the taint is
intra-procedural (1-level + a local fixpoint) so it **under**-counts
cross-function reachability; `backend`/`config` detection is prefix/shape
based, so an unlisted driver is missed; a call site is **not** proof of
deployment reachability (CLAUDE.md: "a Go call graph is not a deployment
path") — the ranked list is where a reachability trace *starts*, not a
substitute for one; and coverage is a loose token-match hint, re-checked by
hand.

## Tests

`reachgen_test.go` drives a local, offline fixture module under `testdata/`
(`example.com/app` calling the stand-in deps `example.com/lib` and a fake
`github.com/jackc/pgx/v5`, all via `replace`). It asserts third-party-only
recording, each provenance label, assignment taint propagation, method-call
resolution, the static-call filter, and `MarkCovered`.
