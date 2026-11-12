# BK-4 investigation — does the audit-coverage claim hold?

## Observation (from prev session)
In the harness, only role / machine-identity ops produced audit_events rows.
Project create/delete and secret create/update/delete produced NONE.

## Root cause (traced in code, re-verified this session)
Audit attribution for project and secret mutations is **request-context-gated**:

- Project/environment: `CreateProject`/`UpdateProject`/`DeleteProject` write their
  `project.*` audit row only when `mutationAuditActorFromContext(ctx)` returns
  `audited=true` (internal/core/catalog.go; mutation_audit_tx.go:125-138). The flag
  is true only if the context was tagged with `WithMutationAuditActor`.
- Secret: secret mutations write their `secret.*` audit row only when
  `mutationAuditRowFor(ctx,…)` returns `ok=true` (secret_mutation_audit.go:58-97),
  which requires the context to carry a `SecretMutationAudit` set via
  `WithSecretMutationAudit`.

The contract is explicit and codified as invariants:
`internal/core/INVARIANTS.d/INV-CORE-secret-mutation-audit-same-tx.md` and
`INV-CORE-security-mutation-audit-same-tx.md`. Audit attribution (actor id,
username, IP, user-agent, client-origin) is request-scoped data that only the
transport layer holds, so core writes NO row rather than a bogus/zero-actor row
when it is absent.

- Role/machine-identity ops differ because they take an **explicit `actorID`
  parameter**, so they always have an actor and always audit — which is exactly why
  they are the only ops that produced audit rows in the fuzzer.

## Live callers that DO tag the context in production (reachability trace, re-verified)
Confirmed by grep over non-test code this session:
- Project: `server/http/handlers/catalog.go:263,399,441,488,514`,
  `server/grpc/services/project_service.go:209,239,263` (all call
  `WithMutationAuditActor`).
- Secret: `server/http/handlers/secrets_crud.go:143`,
  `server/grpc/services/secret_service.go:101` (both call `WithSecretMutationAudit`).
- (Alert-escalation policies follow the same pattern — additional confirmation the
  idiom is the standard transport contract, not a one-off.)

## Verdict: CLAIM HOLDS — classification HARNESS ARTIFACT, not a product defect
Project and secret mutations ARE audited in production via the transport-tagged
context path, with live REST and gRPC callers confirmed for both, and the behaviour
is pinned by two committed INVARIANTS.d files. The fuzzer's silence is a harness
artifact: it drives core directly with an untagged `context.Background()`, so it
exercises the by-design "untagged caller → no core audit row" branch.

Consequence for oracle 3: the audit hash-chain round-trip is exercised ONLY by
role / machine-identity audit events in the committed harness. Tagging the harness
context with `WithMutationAuditActor` + `WithSecretMutationAudit` would add
project/secret rows to the round-trip — an optional harness HARDENING, not a
correctness fix. Oracle 3 already runs against a real chain.
