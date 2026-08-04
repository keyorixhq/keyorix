# ADR-074: Contract-test harness for `server/http/handlers/openapi.yaml`

## Status

Proposed. Phase 0 (investigation) complete. This ADR is Phase 1. Phase 2
(implementation) proceeds against this record after review.

## Context

`server/http/handlers/openapi.yaml` declares 167 operations. Measured
directly by parsing the spec's YAML AST (not by eyeballing it — a hand-count
across a 3,400-line file is exactly the kind of thing that's wrong by one and
never rechecked):

- **10** operations have a 2xx response with a JSON-Schema-bearing `content`
  block.
- **12** operations have a `204 No Content` success response — nothing to
  validate a body against by definition, not a gap.
- **145** operations have a non-204 success response described in prose only
  (a `description:` string, no `content:` block at all).

10 + 12 + 145 = 167. Every operation is accounted for in exactly one bucket.

The consequence of the 145 is measured, not inferred: generating a client
from this spec today produces `(*http.Response, error)` in Go and
`Promise<void>` in TypeScript for those operations — a generated `getSecret`
caller gets a response object it has to parse by hand, the same as if no spec
existed for that endpoint at all.

**Why a wrong schema is worse than an absent one.** An absent schema fails
generation loudly and immediately — `Promise<void>` is impossible to use by
accident, the type system stops you at the call site. A wrong schema
succeeds at generation and produces a typed client that silently misparses
or drops fields at runtime, discovered only when a caller notices missing
data days or releases later. Hand-writing 145 schemas by reading handler code
would produce exactly that risk at scale, with no independent check that any
of them are actually right, and no protection against the next refactor
silently drifting the handler out from under an already-written schema. This
ADR is about building the check first, so the schema-writing work that
follows lands verified rather than trusted.

## Decision 1: the spec stays hand-written and becomes machine-verified

The alternative — generate `openapi.yaml` from Go types — was considered and
rejected for this codebase, not in the abstract. The case for it is real:
generated output cannot drift from the code, by construction, which is
exactly the failure mode this ADR is otherwise defending against by other
means (a test harness that must be kept correct, rather than a build step
that cannot be wrong). That's a legitimate architecture and this ADR does not
claim contract-testing is strictly better than generation in general.

It's rejected here because generating from Go types would discard three
things this spec already has that a struct-tag-derived schema does not
reconstruct:

- **Prose on all 167 operations.** PR #1152 ("add operation descriptions to
  all 133 undocumented endpoints") was itself a deliberate investment in
  spec quality independent of schemas — descriptions like exportAuditLogsCSV's
  ("Distinct from the JSON `/audit/export` SIEM feed — this is a single
  one-shot download capped at 10,000 rows") encode operational knowledge no
  Go struct tag carries.
- **The shared `Error` response component**, `$ref`'d 415 times across the
  spec (verified by count, not estimated). A generated spec would either
  inline 415 copies of the same shape or require its own deliberate
  component-extraction pass — solving a problem hand-authoring already
  solved.
- **Prose quality generally.** Field descriptions like
  `absolute_expires_at`'s "Hard ceiling past which refresh is refused" are
  editorial judgment calls about what a spec consumer needs to know, not
  derivable from a type alone.

So: keep the hand-written spec, and close the actual gap — that nothing
today confirms a handler's response matches what its operation declares —
with a harness instead of a rewrite.

## Decision 2: library — `getkin/kin-openapi`

Evaluated against the real spec file, not in the abstract (Phase 0 detail
below). Two candidates were live options; a third path — hand-rolled
JSON-Schema assertion — was the fallback if neither handled this spec
cleanly. Neither fallback was needed.

| | `kin-openapi` v0.146.0 | `pb33f/libopenapi-validator` v0.14.0 |
|---|---|---|
| Parses/validates this spec | Clean, 0 errors, 126 paths | Clean, 0 errors |
| Request→operation matching | `routers/gorillamux`, first-class | Built into `ValidateHttpResponse` |
| Response validation | `openapi3filter.ValidateResponse` | `Validator.ValidateHttpResponse` |
| Transitive modules | ~19 (testify, go-spew already shared) | ~35 (jsonpath, xml2json, ordered-map unused here) |
| Broken-response error message | One readable line: ``Error at "/data/user_id": value must be an integer`` + schema/value dump | Generic top-line ("does not meet the schema requirements"); exact field/reason only in a `SchemaValidationErrors` sub-list the caller must print itself |

`kin-openapi` wins on footprint and on error-message ergonomics without extra
harness code to extract a usable message — directly relevant to the Phase 3
requirement that a validator whose failure output is unreadable is one people
disable.

**Named limit, same treatment as ADR-073's tree-shaking approximation:**
`kin-openapi` supports OpenAPI **3.0.x only**. This spec declares `openapi:
3.0.3` (verified), so this is not a live constraint today. But 3.1's JSON
Schema alignment (3.0's `nullable: true` / restricted `type` keyword give way
to real JSON Schema in 3.1) is attractive precisely for the 145-schema
authoring work ahead, and would remove some of 3.0's schema-expressiveness
friction. **Reopening trigger:** if this spec moves to OpenAPI 3.1, revisit —
that migration requires switching this harness to `libopenapi` (which
`pb33f/libopenapi-validator` is built on and which does support 3.1),
since `kin-openapi` cannot load a 3.1 document at all. `kin-openapi` is the
defensible choice for the spec as it exists today, not a permanent one
regardless of spec version.

## The honest enforced baseline is ~7, not 10

Three of the ten schema'd operations validate close to nothing:

- `exportAuditLogsCSV` and `exportAccessReviewCampaignCSV` declare
  `text/csv` bodies as `{type: string, format: binary}` — a schema
  satisfied by any non-empty byte stream. Wiring the harness to these two
  checks "a response body exists with the right content-type," not "the
  response matches its contract."
- `prometheusMetrics` (`GET /metrics`) is `promhttp.Handler()` — third-party
  code, not a handler this repo owns, and no client is or will be generated
  against Prometheus exposition format. It is **out of scope**, and recorded
  as such explicitly in the pending/registry structure (Decision 3) with its
  reason, rather than silently absent from both the enforced and pending
  counts — an operation that's simply missing from every list is
  indistinguishable from one nobody thought about yet, which is the same
  false-control shape this ADR exists to prevent.

That leaves **7 operations with actual JSON-Schema signal enforced on day
one**: `authGetSetupToken`, `authLogin`, `authRefresh`, `healthCheck`,
`listSecretACLs`, `systemInit`, and `exportSecretAccessLog`'s JSON side (see
below). Phase 2 wires the harness to all 10 schema'd operations — the CSV
pair still gets real value from content-type and non-empty-body checks, and
`prometheusMetrics` is explicitly registered out-of-scope rather than
omitted — but the ADR states the number that reflects actual verification
strength, not the number that looks best.

## `exportSecretAccessLog`'s dual content-type is a deliberate case, not an incidental one

`GET /api/v1/secrets/{id}/access-log/export` is the only operation today that
declares **two** 2xx content types — `application/json` and `text/csv` —
selected by an `export` query parameter, not by status code. It is called
out here because it is exactly the kind of case a harness naturally handles
by accident today (only one content-type exists, so "check the JSON schema"
and "check the response's actual schema" happen to be the same thing) and
breaks the moment a second dual-content operation appears, with no
compile-time or spec-level signal that the harness's assumption was ever
narrower than the spec.

Phase 2 must select the schema to validate against by the **response's
actual `Content-Type` header**, matched against the operation's declared
content types for that status code — never by assuming `application/json`
and falling through. This is stated as a requirement here specifically so it
is designed in from the first operation that needs it, not patched in later
when a second dual-content operation makes the shortcut visibly wrong.

## Fail-closed semantics

A handler response that does not validate against its operation's declared
schema **fails the test.** This is not a warning or a log line — a
generated-client caller trusts the schema; a harness that only warns is
indistinguishable from no harness once nobody is reading its output.

An operation whose schema is absent must be **explicitly registered as
pending**, with a reason, not silently skipped. The alternative — the
harness only checks the 10 (or 7) it currently knows how to check and says
nothing about the other 157 — reports green across 145+ unverified
operations. That is the same false-control shape as `SCA scan` reporting
success with no NVD database (PROCESS.md, "Required checks must fail
closed"): a check that appears to cover the surface it doesn't.

**Invariant: every operation in the spec lands in exactly one of three
buckets — enforced, pending-with-reason, or out-of-scope-with-reason.** The
harness proves this partition; it is not allowed to assume it holds. A
partition that's merely assumed is exactly how 145 operations went
unverified in the first place — nobody excluded them on purpose, the spec
just grew and nothing checked that every new operation landed somewhere
accounted for.

The pending registry:

- Lists every operation not yet enforced, by `operationId`, with a reason
  (`"schema not yet written"` for the 145; `"promhttp.Handler, third-party,
  no generated client"` for `prometheusMetrics`; the two near-zero-signal
  CSV operations are enforced, not pending, but their entry should say what
  "enforced" means for them — presence/content-type, not a real body
  schema).
- Shrinks as schemas land. Adding an operation to the pending list requires
  a reason — the registry is a record of known gaps, not a dumping ground.
  It is expected to reach zero.
- Is itself asserted accurate in **both** directions:
  - An operation listed as pending that **does** have a schema in the spec
    must fail the build. Without this check the registry is exactly the kind
    of second place to update that this ADR's own reasoning (three
    paragraphs up) argues against — it would drift from the spec the same
    way the spec drifted from the handlers.
  - An operation present in the spec with no 2xx schema and **no registry
    entry at all** — neither enforced, nor pending, nor out-of-scope — must
    also fail the build. This is the opposite direction from the first
    check, and it is the one that keeps the registry honest as the spec
    grows: without it, a new endpoint merged without a schema doesn't even
    need someone to remember to register it as pending — it just silently
    joins the unverified pile, and 145 grows without bound with the harness
    still reporting green.

## Coverage assertion: "enforced" must mean "exercised"

The harness is opt-in per test — a test calls it, or it doesn't run. That
means an operation can be correctly listed as enforced (it has a schema, the
registry says so) while every test that could exercise it never actually
calls the harness — the operation is unverified in practice while appearing
verified on the list. The registry's partition (previous section) checks
that the *spec and registry* agree with each other; it says nothing about
whether the *tests* actually invoke the check at all.

Phase 2 must assert that every enforced operation is exercised through the
harness at least once across the test run, and fail the build if not. This
is the same false-control shape as `SCA scan` reporting success with no NVD
database (PROCESS.md, "Required checks must fail closed") — a check that
exists, is wired up, and is listed as covering something, but whose actual
data source (here, a real test invocation) is silently absent. An "enforced"
list nobody confirmed ever ran is a claim, not a fact.

## Non-goal

This ADR does not decide anything about SDK/client generation. It makes the
spec trustworthy to generate from; whether or when to actually generate
Go/TypeScript clients from it is a separate decision, with its own ADR, once
this one's enforced baseline is large enough to make that worth doing.

## Phase 0 findings that inform Phase 2 design

- Handler tests call handler functions directly
  (`h.SomeHandler(w, req)`) rather than routing through the real chi
  `router.go`. Path params for routes that need them are already injected via
  `chi.NewRouteContext` in ~20 files that need it. This means requests
  already look like real routed requests in the tests sampled, which is what
  operation-matching depends on — but it is a property of how each test
  happens to construct its request, not something the compiler enforces, so
  Phase 2's harness must fail loudly (not skip) when a request's path
  doesn't resolve to any operation.
- `kin-openapi/routers/gorillamux` correctly resolves `*http.Request` to
  `operationId` + path params, including disambiguating nested templates
  (`/secrets/{id}` vs `/secrets/{id}/acl` vs `/secrets/{id}/access-log/export`)
  — verified against this router, not assumed from the library's docs.
- `server/http/handlers` already runs under `go test -race` in CI today,
  sharded across 4 matrix legs (`handlers-1..4`). It is not excluded. A
  connection-pool leak investigation referenced under the number ADR-069 was
  opened, investigated, and closed (BACKLOG.md) with its underlying fix
  merged (PR #1296). This harness will run in CI automatically as part of
  the existing `handlers-*` legs, with no new CI wiring required.
- `docs/` numbers contiguously from ADR-065 through ADR-073 (verified
  directly against `origin/main`) — this ADR is 074.
