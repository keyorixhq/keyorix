# Outcome mapping: allowed | denied | other

The single table every layer's raw result is mapped through before the oracles
compare anything. Decided in Phase 1 from the code and ADR-096; each rule cites
where it comes from. Phase 2 implements exactly this table (one function per
layer) and nothing else.

## Preconditions the mapping relies on

1. **Every target exists.** The harness only addresses seeded fixtures
   (project A/B, their groups, machine identities, invitations, access
   requests, memberships). It never sends a nonexistent id. That is what lets
   a "not found"-shaped answer count as a denial: under ADR-096 every
   accepted convention collapses "denied" and "nonexistent" into one shape,
   and with existence fixed, that shape can only mean "denied".
2. **Positive control per (operation, iteration).** The canonical global
   admin runs the same operation with the same arguments on a fresh store.
   If the admin does not get `allowed`, the operation's arguments or route
   are wrong for this fixture. The iteration is recorded as
   `uncalibrated` and excluded from both oracles; it is never counted as a
   denial or as a disagreement. This keeps a 404 from a wrong path, or a 400
   from a bad body, from being read as authorization.
3. **Fresh store per iteration.** Rate-limit or lockout state cannot leak
   between iterations. A `429`/`ResourceExhausted` is still mapped to `other`
   and counted, as a harness-health signal.

## Table

| Layer | allowed | denied | other |
|---|---|---|---|
| core called directly | `err == nil` | `errors.Is(err, core.ErrPermissionDenied)` (covers every `newPermissionSentinel` var and `markPermissionDenied`/`permissionDeniedf`); **or** one of the untyped refusals `errors_permission.go` lists as not matching it: `ErrBreakGlassListForbidden`, `ErrAccessOutsideSchedule`, `ErrConnectRefNotPermitted`, `errAdminAuthorityRequired` (unexported, matched via an exported test hook or by identity in an in-package test helper, decided in Phase 2), SCIM `ErrorNotAuthorized` | anything else (validation, conflict, storage). See "Untyped refusals" below. |
| REST | `2xx` | `401`, `403`; `404` on an existing target (ADR-096 Convention B sites, plus Convention A's real 404 that only a globally-permitted caller can get, which the positive control rules out for a denied principal); `502` whose body is the `ErrConnectUnknownConnector` text on a **known** connector (ADR-096 "Connect" convention) | every other status: `400`, `409`, `422`, `429`, `5xx`, `502` with any other body |
| gRPC | `OK` | `Unauthenticated`, `PermissionDenied`; `NotFound` on an existing target (ADR-096 Convention B: gRPC `GetSecret`/dynamic-secret RPCs); `FailedPrecondition` carrying the `ErrConnectUnknownConnector` text on a known connector | every other code: `InvalidArgument`, `AlreadyExists`, `FailedPrecondition` (other text), `ResourceExhausted`, `Internal`, `Unavailable`, `Unimplemented` |

`401` vs `403` and `Unauthenticated` vs `PermissionDenied` are both `denied`.
The fixed principal set includes "no token / no session" and expired
credentials, so which of the two appears is not an authorization decision for
these oracles.

## Untyped refusals (core leg)

A core refusal built from plain `fmt.Errorf`/`errors.New` text with no
sentinel cannot be classified as `denied` without matching on message text.
Message text is translated, so that is forbidden here (and in the repo).
Such a refusal maps to `other`. When the transport says `denied` for the same
input, the pair is reported in its own bucket, **mapping gap (untyped core
refusal)**, not as a disagreement. That is the honest reading: core did
refuse, but nothing typed says so, which is itself the known class
`TestEveryErrorPermissionDeniedRefusalIsTyped` only partially covers.

## When the core leg is not an authorization layer

`MATRIX.md`'s `core refusal` column is `none` for core entries that perform no
authorization refusal on any path. The transport (router middleware or gRPC
service code) is the only gate there, and the core method usually takes the
actor id only for the audit row (`RevokeInvitation`, `CreateGroup`, ...).
Calling such a method directly "as" a principal succeeds by construction. For
those operations:

- Oracle 1 compares **REST vs gRPC only**; the core leg is recorded but
  excluded from the agreement check (intended difference, class
  `transport-enforced`).
- Oracle 2 compares each **transport** with the reference model.

## Intended differences (recorded, never reported as disagreements)

| Id | Difference | Why |
|---|---|---|
| ID-1 | Actor id 0 is a core-only principal | Core treats actor 0 as the trusted system/internal caller (the existing parity fuzzer grants roles as actor 0). No session or token can be issued for it, so REST and gRPC can never present it. Core leg only; no transport comparison. |
| ID-2 | `transport-enforced` operations (core refusal = none) | See above. |
| ID-3 | Operation present in REST but not gRPC | ADR-105 (accepted 2026-09-09): gRPC is a partial data-plane surface by decision. Missing-in-gRPC is a matrix gap result, not a disagreement. |

## Disagreement classes in the report

Each finding is reported as operation, principal, layers and outcomes, never
with a secret or a raw request body:

- **real bypass**: one layer `allowed`, another `denied` (Oracle 1), or a
  layer `allowed` where the model says deny (Oracle 2).
- **over-denial**: a layer `denied` where the model says allow. Reported,
  lower priority; may be an intended stricter gate. Then classified
  intended (documented here) or a bug.
- **mapping gap**: core `other` vs transport `denied` (untyped refusal), or
  any pair where the only difference is `other`.
- **uncalibrated**: the positive control failed; counted per operation so a
  silently broken operation is visible, never treated as clean.

## Spec notes (Phase 2: what the model encodes, and why)

The model's requirement per operation is the **REST router gate** from
`scripts/e2e/routes.json`. No per-operation permission is documented in
OpenAPI. On top of the gate, the model encodes only these **documented** rules:

- **The FIX-1 grant ceiling.** A role-granting op needs every permission of
  the granted role, at the scope the role will be held. For a group join, that
  is every role the group holds, each at its own scope.
- **The share owner rules**: `ErrShareNotOwner` and `ErrShareOwnerNotMember`
  (`internal/core/share_authz.go`). Only the owner may share, and only while
  holding a live project-scoped grant. A global role is not membership.

Anything else core or a transport enforces is NOT in the model. If it denies
where the model allows, that is reported as `O2:over-denial`, not modelled
away.

Consequences:

- **Oracle 2 vs REST** checks scope resolution, expiry, machine no-bypass,
  the ceiling and the owner rules, but not which permission the route names.
  It is fully independent only for core and gRPC.
- **`group.role.assign` at global scope with a project-tier role** fails the
  admin positive control: project roles are not assignable globally (role
  scope rule, 400). Those legs are `uncalibrated` by design: 105 per layer in
  the sweep. `editor` (arg 3) is assignable globally and is covered.

## Core-leg fidelity

The core leg calls exactly the core method the transport calls for that
principal kind, with the same arguments a transport would derive. That
includes, for a machine actor:

- `UserID = 0`;
- the machine tagged on ctx (`WithActorType`, `WithMachineActor`);
- `WithSelfMachineGranter`, for the four ops whose transports set it
  (`opSpec.selfMachineGranter`, with file citations).

Where a transport calls a non-checking core variant for a principal (machine
actors on secret update/delete/value read), the core leg is `n/a`, not
`allowed`. A first sweep without `WithSelfMachineGranter` produced 4 false
`machine.role.assign` disagreements. That is the "mapping bug" class, caught
and fixed in the harness, not in the product.

## Spec notes added in Phase 4

**Documented rules the model gained.** Each cites the code that states it.
Each was added because a case showed the model missing it, never to make a
layer agree.

- **Account state.** A suspended account may do nothing (`account_state.go`).
- **PAT restriction.** A PAT narrows its owner on the permission check
  (`rules.PATRestriction.Allows`: allowlist plus project scope). The grant
  ceiling reads the principal's own roles, independent of the PAT
  (`principalHasScopedPermission`).
- **Restricted-PAT ungated writes.** A restricted PAT is refused on the
  writes listed in core's table (ADR-042, PAT-GUARD-3:
  `core.RestrictedPATWriteRefusal`). The model reads that table directly,
  keyed by the op's matrix route.
- **Two-scope gates.**
  - `machine.migrate`: `roles.assign`@project plus `users.write`@global
    (`router.go:609-611`).
  - Bulk access-request approve/reject: global `roles.assign` plus per-item
    `roles.assign`@project (`bulk_access_requests.go`).
- **Global admin authority.**
  - OIDC binding create needs an admin role at global scope
    (`requireAdminAuthorityAt(actor, 0)`).
  - Environment restore needs one too, because it reinstates project role
    assignments and the fixture projects hold admin-tier ones
    (`requireAuthorityToReinstateProjectRoles`).
- **Requester-only.** Access-request withdraw: only the requester
  (`WithdrawAccessRequest`).
- **Same-role no-op.** `member.setrole` to the role already held is
  audit-only, so no ceiling applies (`SetProjectMemberRole`).

**Effect-based outcome for bulk ops.**
- Bulk approve/reject answer 200 even when the item was refused. A 2xx
  whose body does not list the request id as approved/rejected is `denied`
  (`2xx-item-refused`).
- The core leg does the same from the returned result (`item-refused`).

**Positive control.** The admin first, then, when the op declares one, an
op-specific principal (`opSpec.controlAs`): the requester, for withdraw. For
owner-only secret ops on s1, the viewer-owner (Phase 3).
