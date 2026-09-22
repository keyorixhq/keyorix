# ADR-draft (unnumbered, proposed, deferred): Request idempotency for create operations

**Status:** Proposed, deferred. Not assigned an ADR number — this is a discussion
outline for a future decision, not an accepted architectural decision. See
`docs/findings/2026-09-23-FINDING-create-ops-ambiguous-commit-mixed-state.md`
for the finding that motivated it.

## Context

Fault-injection fuzzing (`FuzzStorageFaultOperations`) found that every
multi-step `Create*` operation in `internal/core` has an ambiguous-response
gap on its first storage call: if the underlying write commits but the
acknowledgment is lost (network blip, timeout, dropped response), the caller
is told "error" with no ID to reconcile against. A `storage.WithTransaction`
wrap (the companion finding/fix) closes the *mixed-state* half of this — the
row is now always either fully absent or fully committed, never half-applied
— but does not close the *ambiguous-response* half: the client still can't
tell "my create failed" apart from "my create succeeded but I never heard
back."

## Known affected call sites (as of this sweep)

`CreateProject`, `CreateProjectWithEnvs`, `CreateSecret`, `CreateUser` — all
in `internal/core`. This sweep covered `(c *KeyorixCore) Create*` methods
specifically; not an exhaustive repo-wide claim.

## Options considered

1. **Client-supplied idempotency key.** A header or request field; server
   dedupes on `(actor, key)` within a TTL window. Standard REST/gRPC pattern.
   Needs a new table plus a TTL cleanup job. Strongest guarantee, most work.
2. **Server-side reconciliation sweep.** Detect orphaned rows after the fact
   (e.g. a `SecretNode` with zero `SecretVersion` rows, a `User` created
   with no roles more than N seconds ago) and either complete or flag them.
   Cheaper to build than option 1, but heuristic and reactive rather than
   preventive — it notices the gap, it doesn't stop the client from being
   confused in the moment.
3. **Do nothing beyond the transaction fix.** Per the impact analysis in the
   companion finding, a lost-ack row today is inert and operator-cleanable,
   not corrupting. Document the tradeoff and accept it until a real caller
   needs better guarantees.

## Decision

Deferred. This is a product/API-design call — which operations need it, what
the client contract looks like, whether the cost of option 1 is justified
before any client actually needs it — not something to default into as a
side effect of a fuzzer-driven bug fix.

## Reopening triggers

Reopen this decision at the latest when either happens:

- **The first client that does automated retries** against these endpoints
  without its own dedup logic — a Terraform provider, a Kubernetes
  operator/controller reconcile loop, a CI/CD integration script. Automated
  retry-on-error is exactly the pattern that turns "rare lost ack" into
  "routine, repeated, silently-orphaned rows" — the difference between a
  once-a-year operational curiosity and a steady background leak.
- **Any customer-visible report** of a duplicate-looking or missing-piece
  resource that traces back to this class (an orphaned project/secret/user a
  support ticket surfaces).

Whichever comes first should re-trigger this decision, not just a fix at the
one call site that happened to surface it.
