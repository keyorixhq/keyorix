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
