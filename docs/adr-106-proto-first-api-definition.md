# ADR-106: The proto becomes the single source of truth; HTTP and OpenAPI are generated

## Status

**Accepted in direction (owner decision, 2026-09-09).** The API will be defined once, in
`server/proto/keyorix.proto`, with the HTTP/JSON surface and the OpenAPI document generated from it
rather than hand-written alongside it.

**Proposed, not ratified:** the migration sequencing, the risk mitigations, and the decision to keep
the gRPC port unexposed. No handler is authorized for migration by this document.

**Supersedes ADR-074 Decision 1** ("the spec stays hand-written and becomes machine-verified") —
see §3, which argues that ADR-074 rejected a *different* alternative than the one accepted here.
**ADR-074 Decisions 2 onward stand unchanged** and become load-bearing for this migration: its
contract-test harness is the equivalence check that makes a staged migration safe (§5).

**Supersedes `docs/adr-105-grpc-scope-and-parity.md` phases 1-4.** Under this decision gRPC/HTTP
parity stops being a project: it is a build output.

## Context

### Three hand-written descriptions of one API

| artefact | size | maintained |
|---|---|---|
| HTTP handlers | 151 files | by hand |
| `server/proto/keyorix.proto` | 13 services, 86 RPCs | by hand |
| `server/http/handlers/openapi.yaml` | 126 paths, 167 operations | by hand |

Each is a separate statement of what the API is, and nothing forces them to agree. ADR-105 records
what that costs on the proto side: two control gaps found by accident, years apart
(`server/grpc/services/secret_service.go:166`, and the missing `classification`/`description`
fields).

### The spec is mostly prose, and ADR-074 measured it

From ADR-074's own Context, derived by parsing the spec's YAML AST rather than by inspection:

- **10** of 167 operations have a 2xx response carrying a JSON Schema
- **12** are `204 No Content` — nothing to validate, not a gap
- **145** describe success in prose only, with no `content:` block at all

And ADR-074's own assessment of how much of that is actually enforced: *"The honest enforced
baseline is ~6, not 10."*

So roughly **6 of 167 operations have a machine-enforced response contract.** ADR-074 states the
consequence directly: generating a client from this spec today yields `(*http.Response, error)` in
Go and `Promise<void>` in TypeScript for the 145 — *"the same as if no spec existed for that
endpoint at all."*

This is the finding that drives this ADR. The audit and support value a specification is supposed
to provide is, today, largely absent — not because the spec is neglected, but because hand-writing
145 correct schemas is a job nobody should attempt. ADR-074 says so itself: *"a wrong schema is
worse than an absent one"*, because it *"succeeds at generation and produces a typed client that
silently misparses or drops fields at runtime."*

### The market evidence

Surveying ten secrets-management products (see
`claude/2026-09-09-grpc-parity-market-evidence.md`): nine expose REST only. The two products
anywhere in the survey that maintain gRPC/HTTP parity — Google Cloud Secret Manager and HashiCorp
Boundary — both achieve it by generating one transport from the other via `google.api.http`
annotations. Google makes it a rule with teeth (AIP-127: *"APIs must provide HTTP definitions for
each RPC that they define"*). Nobody maintains parity by hand.

Boundary is the closer model: its protos carry `google.api.http`, `buf.gen.yaml` runs
`grpc-gateway` and an OpenAPI generator, and its gRPC server listens on an **in-memory `bufconn`
listener** — customers only ever speak HTTP/JSON.

## Decision

1. **`server/proto/keyorix.proto` becomes the single source of truth.** Every operation carries a
   `google.api.http` annotation defining its HTTP binding.
2. **The HTTP surface is generated** via `grpc-gateway`, replacing hand-written handlers. Handlers
   become generated stubs that call `internal/core`, which remains the enforcement layer and is
   unaffected by this ADR.
3. **`openapi.yaml` is generated** via `protoc-gen-openapiv2`, and stops being hand-edited.
4. **The gRPC port stays unexposed by default** (`server.grpc.enabled: false`, unchanged). Adopting
   proto-first is about having one definition, not about shipping a second public transport. If a
   customer ever needs gRPC, it becomes a config flag rather than a project.
5. **gRPC/HTTP parity is therefore not a work item.** It is a property of the build. ADR-105's
   phases 1-4 are withdrawn; its Phase 0 documentation stands and remains accurate for as long as
   the migration is incomplete.

The toolchain is already present: `buf.yaml` (v2, STANDARD lint, `breaking: FILE`) and
`buf.gen.yaml` exist, and the `Makefile` has `proto` / `proto-deps` / `proto-lint` targets. This
adds `grpc-gateway` and `openapiv2` plugins to `buf.gen.yaml` — the same three-plugin shape
Boundary uses.

## 3. Why ADR-074's rejection does not carry over

ADR-074 rejected generation, explicitly and with reasons. Those reasons were aimed at **generating
OpenAPI from Go struct tags**, which is a different proposal. Its three objections, tested against
proto-first:

| ADR-074's objection to struct-tag generation | does it apply to proto-first? |
|---|---|
| "Prose on all 167 operations" would be discarded (PR #1152's deliberate investment) | **No.** `protoc-gen-openapiv2` emits leading proto comments as `description`. The prose is *migrated*, not lost — it moves from YAML into proto comments, and stays adjacent to the definition it describes. |
| The shared `Error` component, `$ref`'d 415 times, would be inlined 415 times or need its own extraction pass | **No — proto is better here.** A shared `Error` message generates as one definition referenced everywhere, by construction. Hand-authoring solved this once; proto solves it permanently. |
| Field-level editorial prose ("Hard ceiling past which refresh is refused") is not derivable from a type | **No.** Same mechanism — proto field comments carry through. Still editorial judgment, still hand-written, just written in one place instead of two. |

ADR-074 also said, fairly: *"generated output cannot drift from the code, by construction, which is
exactly the failure mode this ADR is otherwise defending against by other means… That's a
legitimate architecture and this ADR does not claim contract-testing is strictly better than
generation in general."*

This ADR takes that option. ADR-074's contribution is not overturned so much as completed: it
identified the gap (145 unspecified operations), correctly refused the dangerous fix
(hand-write 145 schemas), and built a harness to verify what little could be verified. Proto-first
closes the gap at its source — the schema becomes the type the handler already uses, so it cannot
be wrong.

## 5. Migration: strangler, with ADR-074's harness as the safety net

**No big-bang rewrite.** The existing infrastructure happens to be exactly what a staged migration
needs:

- **`contracttest.AssertOpenAPIResponse` is the equivalence check.** For each migrated endpoint, the
  generated handler must produce a response that still validates against the spec. That is a real,
  automated proof of behavioural equivalence, endpoint by endpoint.
- **`pendingRegistry` (145 entries) is the worklist and the progress meter.** It already shrinks
  monotonically, and `CheckPartition` already fails the build when an entry gains a schema. The
  migration therefore reports its own progress through machinery that exists today.
- **New endpoints go proto-first from day one.** This stops the problem growing while the backlog
  drains, and it is the only part that should start immediately.

Suggested order: one capability area per batch, smallest and least security-sensitive first, each
batch removing its `pendingRegistry` entries. Secrets read/write last, not first — it is the
highest-risk path and should migrate onto a toolchain that has already proven itself elsewhere in
the codebase.

## 6. Risks that must be pinned by test BEFORE any endpoint migrates

These are the places where a generated surface can silently differ from a hand-written one. Each
needs a red-then-green test on the *current* implementation first, so the migration has something
to preserve.

1. **Anti-enumeration status codes (`adr-096`, "403 for both").** grpc-gateway's default error
   mapping is `codes.PermissionDenied` → 403 and `codes.NotFound` → 404. If the current design
   deliberately returns 403 for a resource that does not exist, the default mapping **regresses a
   security property**. Requires a custom `runtime.WithErrorHandler`, and a test asserting the
   403/403 pair before anything moves.
2. **i18n error messages across five locales.** Error bodies are produced by the gateway's error
   handler after migration. The locale negotiation and message catalogue must survive it.
3. **Three credential types on one `Authorization: Bearer` header** (session tokens, PATs, machine
   tokens). Auth is middleware and should be unaffected, but the middleware chain around a gateway
   mux is not the chain around the current router.
4. **Path and response fidelity for the web UI.** Keyorix-web consumes these endpoints. Every path,
   query parameter, status code and body shape must be reproduced exactly; `google.api.http` can
   express them, but each one must be transcribed deliberately rather than regularised into an
   AIP-style shape. A tidier URL is a broken UI.
5. **CI wall clock.** Currently 13.5 minutes with a ~10.5-minute ceiling tier
   (`claude/2026-09-09-ci-wallclock-reduction-plan.md`). Code generation adds a build step and a
   generated-code-freshness check; size them against that ceiling rather than discovering the cost
   afterwards.
6. **`buf breaking: FILE` is already configured** and will now be guarding a customer-facing HTTP
   contract, not just an off-by-default proto. That is a benefit, but it means proto edits acquire
   consequences they did not previously have.

## Consequences

- One definition, three generated artefacts: gRPC service, HTTP handlers, OpenAPI document. A typed
  client becomes generatable for **167** operations rather than ~6.
- `openapi.yaml` stops being hand-editable. The prose currently in it must be migrated into proto
  comments as each area moves, or it is lost — this is a real, non-trivial cost, and PR #1152's
  investment is exactly what is at stake.
- `buf lint`'s deferred exceptions (`PACKAGE_VERSION_SUFFIX`, `PACKAGE_DIRECTORY_MATCH`) come due:
  a customer-facing generated API should live at `keyorix/v1/`, and moving it changes import paths.
  Decide this before the first migrated batch, not during.
- ADR-105's ledger-and-gate design (§5 there) becomes unnecessary *for gRPC*, since generation
  guarantees what the ledger would have checked. The same reasoning does not extend to anything
  still hand-written during the transition.
- Until the migration completes, the codebase carries both styles. ADR-105's Phase 0 documentation
  is what tells operators the truth in the meantime.

## Related

- `docs/adr-074-openapi-contract-test-harness.md` — Decision 1 superseded; harness retained
- `docs/adr-105-grpc-scope-and-parity.md` — phases 1-4 withdrawn
- `docs/adr-096-anti-enumeration-403-for-both.md` — risk 1
- `claude/2026-09-09-grpc-parity-market-evidence.md` — the survey behind §"The market evidence"
