# ADR-037: Per-project MFA policy

**Status:** Accepted
**Date:** 2026-06-12

## Context

ADR-034 added a deployment-wide MFA mandate (`security.require_mfa`): when on, any
interactive session without a second factor is confined to the enrolment endpoints
until the user enrols. That is all-or-nothing — it cannot express "the
**production** project requires MFA, but the sandbox doesn't." Teams running a
single Keyorix install across projects of differing sensitivity need step-up
assurance scoped to the sensitive projects, without forcing MFA on everyone.

## Decision

Add a **per-project MFA requirement** (`Project.RequireMFA`). When set, an
interactive session **without a second factor** is denied access to that project's
scoped resources, even when the deployment-wide policy is off.

- **Model:** `Project.RequireMFA bool` (additive column, default false). Toggled
  via `PUT /api/v1/projects/{id}` with `{"require_mfa": true|false}` (gated by the
  same `secrets.write`-on-project authorization as other project edits); a nil
  field leaves it unchanged. The toggle is audited
  (`project.mfa_requirement_enabled|disabled`).
- **Enforcement** lives at the HTTP authorization layer, where the request's
  interactivity is known. `ProjectMFABlocked` denies (403 `ProjectMFARequired`)
  iff the caller is an **interactive session** (`SessionAuth`) **without** a second
  factor **and** the resolved scope's project requires MFA. It is applied:
  - in `RequireScopedPermission` (covers all secret read/write/version/list and
    other project-scoped middleware routes), and
  - in the handful of endpoints that authorize in-handler rather than via that
    middleware — dynamic-secrets issue/list/revoke (ADR-035) and rotation-policy
    create — so the policy is uniform across every project-scoped path.
- **Exemptions mirror the deployment-wide policy:** non-interactive credentials
  (PAT / machine token / OIDC) are **exempt** — they cannot carry a second factor
  and blocking them would break automation. A session whose user already has TOTP
  or a passkey passes (their session is inherently second-factor-backed). The
  project lookup is skipped entirely unless the caller is interactive-without-MFA,
  so MFA-backed and automated callers pay no cost.

## Why the HTTP layer, not core `Authorize`

`AuthorizePrincipal` cannot distinguish an interactive session from a PAT — both
resolve to actor type "user" — and it has no `SessionAuth` signal. The
interactivity marker lives only on the request's `UserContext`. So the policy is
enforced where that context exists (the authorization middleware and in-handler
authorizers), consistent with where `EnforceMFAEnrollment` already runs.

## Relationship to the deployment-wide policy

The two compose: `security.require_mfa` is a floor applied to every endpoint via
`EnforceMFAEnrollment`; the per-project flag is an additional gate on a specific
project's resources. When the global policy is on, an un-enrolled user never
reaches a scoped route anyway; when it is off, the per-project flag still protects
the projects that opt in. A passkey (ADR-036) satisfies either requirement.

## Verification

Core tests: `UpdateProject` toggles `RequireMFA` (and a nil leaves it unchanged),
`ProjectRequiresMFA` reflects it, the toggle audits exactly once (no re-audit on a
no-op), and a missing project errors. Middleware tests over a real store:
interactive-without-MFA is blocked on an MFA-required project but not on an open
one; an MFA-backed session passes; PAT and machine identities are exempt; global
scope (projectID 0) is never subject to a project policy. `make build` + full
suite + `go vet` green.

## Deferred

Per-environment MFA granularity; requiring a *fresh* re-authentication / step-up
within an active session (today "has a second factor" suffices, since every
MFA-enabled login is second-factor-verified); a project-level minimum factor
strength (e.g. require a phishing-resistant passkey, not just TOTP); surfacing the
flag in the CLI/gRPC project commands.
