# ADR-053: Automated rotation planning

## Status

Accepted.

## Context

Keyorix knows which secrets are *due* for rotation (rotation policies +
`GetRotationStatus` classify covered secrets as overdue / due-soon / ok), how *risky*
each secret is (`ComputeSecretRiskScore`, a composite of expiry / rotation-age / usage /
exposure), and how secrets *depend* on each other (the dependency graph, ADR-052). What
it did not have is the thing that ties those together: a **plan** an operator can act on
— *which* secrets to rotate, in *what order*, and *why*.

The M3 roadmap item is "Automated rotation planning — AI proposes rotation sequence."
With the dependency graph shipped (ADR-052), the prerequisite is met and the core of the
plan can be produced deterministically.

## Decision

Add `GenerateRotationPlan(projectID)` that composes the three existing signals into an
ordered, batched, explainable **rotation plan**, exposed at
`GET /api/v1/projects/{id}/rotation-plan` (scoped `secrets.read`).

- **Candidates.** The plan covers exactly the policy-covered secrets that are **overdue
  or due-soon** (healthy secrets are omitted). A secret covered by several policies
  appears once, keeping its most-urgent classification.
- **Waves.** The candidates are partitioned into dependency-respecting **waves** by a
  level-by-level Kahn topological sort over the dependency subgraph *induced by the
  candidates* (`rotationWaves`): wave 0 holds candidates with no in-plan dependency, and
  a candidate appears one wave after the last candidate it depends on. Secrets within a
  wave have no rotation dependency on each other, so they are **safe to rotate in
  parallel**. (Edges to non-candidate secrets impose no ordering — you don't rotate a
  healthy dependency just because a dependent is due.)
- **Priority.** Within each wave, secrets are ordered by an **urgency** score
  (`rotationUrgency`): overdue always outranks due-soon; within a class, more time past
  due (capped) and higher composite risk raise the score. Deterministic, with secret id
  breaking ties.
- **Rationale.** Each planned rotation carries human-readable `reasons` ("30 days
  overdue", "high risk (score 78)", "rotate after db-password") and the `after_secret_ids`
  it must follow — so the plan is auditable and overridable, not a black box.

### Why deterministic, not an LLM

The "planning" is a deterministic, explainable algorithm, not an opaque model. That is
the right choice for a **security operation** in Keyorix's **on-prem / air-gapped**
deployments (ENS/ENISA posture): the order is reproducible, justifiable to an auditor,
and carries no external dependency or data-egress in the rotation decision path. The
structured plan is deliberately shaped so an **optional LLM advisor** could later narrate
it, batch it across maintenance windows, or weight it by business context — sitting *on
top of* the structured output, never in the security-critical path. That advisor is a
deferred follow-up, not part of this ADR.

## Alternatives considered

- **LLM-generated plan in the rotation path.** Rejected — incompatible with the air-gap
  / determinism / auditability requirements; an advisor on top of the deterministic plan
  captures the upside without the risk.
- **A flat ordered list (reuse `GetProjectRotationOrder`).** Insufficient — it orders the
  *whole* dependency graph regardless of what's due, and can't express which secrets are
  safe to rotate together or why each is urgent. The plan is candidate-scoped and
  wave-batched.
- **Auto-execute the plan.** Out of scope here — execution is the existing auto-rotation
  executor's job (ADR-046/047). This ADR is planning; wiring the plan into the executor
  (rotate wave-by-wave) is a deferred follow-up.

## Deferred follow-ups

- An **LLM advisor** that narrates / window-batches / risk-weights the plan.
- Wiring the plan into the **auto-rotation executor** (ADR-046) so a project rotates
  wave-by-wave, dependency-first, automatically.
- A deployment-wide plan (all projects) and an environment-scoped variant.
- gRPC + CLI surfaces and a web/ plan view (API-only first vertical).
