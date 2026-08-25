# ADR-052: Secret dependency tracking

## Status

Accepted.

## Context

Keyorix can rotate secrets — manually, on a schedule, and (ADR-046/047) automatically,
including against upstream backends. But it has no notion that one secret *depends on*
another: a database password whose value is embedded in an application token; a root CA
that signs an intermediate that signs a leaf certificate; an API key referenced by a
derived service credential. Without that knowledge two questions an operator must answer
before rotating anything go unanswered:

- **Impact / blast radius** — "if I rotate this secret, what else breaks or must be
  refreshed?"
- **Rotation order** — "in what sequence should I rotate a set of related secrets so I
  don't invalidate a dependent before its dependency is in place?"

The M3 roadmap lists *"Automated rotation planning — AI proposes rotation sequence"*
with the note **"Requires secret dependency tracking first."** This ADR builds that
prerequisite — and, since a topological sort of the dependency graph *is* a correct
rotation sequence, it delivers the planning value deterministically, leaving any
AI/heuristic layer as later polish rather than a dependency.

## Decision

Model an explicit, operator-declared **directed dependency graph** over secrets and
answer the two questions from it.

- **Edge model.** `SecretDependency` is one directed edge — `DependentSecretID` depends
  on `DependsOnSecretID` — within a single project **and environment** (the project id
  is denormalised onto the row for cheap project-scoped queries). The pair is unique.
- **Invariant: the graph is a DAG, confined to one environment.** At add time the core
  rejects a self-edge, a duplicate, an endpoint that isn't a real secret, an edge whose
  endpoints are in different projects **or environments**, and — crucially — any edge
  that would introduce a **cycle** (checked by testing whether the prospective
  dependency can already reach the dependent over existing edges). Keeping the graph
  acyclic is what makes a rotation order always exist.
- **Authorization is environment-granular.** A grant is scoped to {project,
  environment}, and the HTTP layer authorizes the caller on the *path* secret's
  environment. Confining every edge to a single environment is what makes that
  authorization also cover the dependency secret — a cross-environment edge would let a
  caller scoped to one environment reference (and then read the name of) a secret in
  another. `DELETE` additionally requires the edge to *reference* the path secret, so
  the same environment-scoped grant governs the removal. (This closed a cross-
  environment IDOR caught in pre-merge security review.)
- **Queries (pure, unit-tested graph functions over the project's edges):**
  - *Impact* — `GetSecretImpact` returns the transitive **dependents** of a secret in
    breadth-first order with hop-distance: the blast radius of rotating it.
  - *Rotation order* — `GetProjectRotationOrder` returns a topological order (Kahn's
    algorithm, deterministic ascending-id tie-break) in which every secret precedes any
    secret that depends on it — i.e. rotate foundational secrets first, then refresh
    their dependents.
- **API (HTTP, project-scoped via the secret in the path).** Under `/secrets/{id}`:
  `GET/POST /dependencies`, `DELETE /dependencies/{depId}`, `GET /impact`; plus
  `GET /projects/{id}/rotation-order`. Reads require scoped `secrets.read`, mutations
  scoped `secrets.write` — the same RBAC as the secrets themselves; `DELETE` additionally
  checks the edge *references* the path secret so the environment-scoped grant actually
  guards it.
- **Audit.** Adding/removing an edge writes `secret.dependency_added` /
  `secret.dependency_removed`, attributed to the actor and the dependent secret.
- **Metadata only.** The graph is built from declared relationships and secret
  *names*; no secret value is ever read.

## Alternatives considered

- **Infer dependencies automatically** (e.g. scan values for one secret embedded in
  another). Rejected — it would require reading plaintext values (against the
  metadata-only principle) and is unreliable; the operator's explicit declaration is the
  trust boundary, mirroring how classification and rotation policies are operator-set.
- **Allow cycles and best-effort order.** Rejected — a cycle has no valid rotation order
  and almost always indicates a modelling error; failing closed at add keeps every later
  query total and meaningful.
- **Jump straight to "AI proposes a rotation sequence."** Deferred — the deterministic
  topological order is correct and explainable; an AI layer can later optimise across
  maintenance windows, risk, or batching, on top of this graph.
- **A global cross-project graph.** Rejected for now — dependencies are naturally
  project-scoped, and per-project keeps authorization and the queries simple.

## Deferred follow-ups

- The "AI proposes rotation sequence" layer (windows / batching / risk weighting) on top
  of the topological order.
- Wiring the rotation order into the automated-rotation executor (ADR-046) so a planned
  rotation runs dependency-first automatically.
- gRPC + CLI surfaces and a web/ graph visualisation (the API is the first
  vertical).
- If a cycle is ever written despite the add-time guard (e.g. a future write path that
  bypasses `CreateSecretDependencyExclusive`), `GetProjectRotationOrder` fails closed
  permanently for that project with no code path to remove the offending edge — for a
  secrets manager, rotation that has quietly stopped is a compliance problem worth a
  detection/repair path even though it isn't a crash or a hang.
- Cascade behaviour on secret soft-delete/restore (currently an edge to a deleted secret
  simply stops resolving a name; a future pass could prune or flag it).
