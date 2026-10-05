# Threat Model: Authorization (scoped RBAC)

> Part of [`docs/security/threat-models/`](README.md). Derived from
> [`../threat-model.md`](../threat-model.md) and [`../architecture.md`](../architecture.md)
> §5. See [authentication.md](authentication.md) for *who* a caller is;
> this document covers *what they're allowed to do once identified*.

## 1. System context

Every authorization decision in this codebase — HTTP handler, gRPC
service, in-handler helper — funnels through one function. This
single-chokepoint design is the property that let one fix
(the PAT-restriction filter, §authentication.md) automatically bind
every present and future authorization path without re-implementing it
per transport.

```mermaid
flowchart LR
    subgraph Callers
        HTTP[HTTP handlers]
        GRPC[gRPC services]
        INH[In-handler helpers]
    end

    AUTHZ["core.Authorize /\ncore.AuthorizePrincipal\n(the one chokepoint)"]

    subgraph Decision["Decision inputs"]
        ROLE[Role grants:\nsystem / project / environment scope]
        BYPASS["BypassesPermissionChecks\n(structural field, ADR-084)"]
        PATR[PAT restriction filter\n(narrows below owner, pre-role)]
        CEIL[Privilege ceiling\n(derived from ACTOR, not target)]
    end

    ALLOW[Allow]
    DENY["Deny — 403, identical\nshape for 'no access' and\n'doesn't exist' (ADR-096)"]

    HTTP --> AUTHZ
    GRPC --> AUTHZ
    INH --> AUTHZ
    AUTHZ --> PATR --> ROLE --> BYPASS --> CEIL
    CEIL -->|granted| ALLOW
    CEIL -->|not granted| DENY
```

## 2. Trust boundaries

This component sits *inside* B3/B4 (it's the decision core those
boundaries call into) rather than defining a boundary of its own —
see [server-api.md](server-api.md) for the surrounding transport
boundaries.

## 3. STRIDE

- **Elevation of privilege — role-rename self-escalation (closed).**
  `models.Role.BypassesPermissionChecks` replaced an earlier fixed-name
  lookup (`roleSetContainsAdmin`) at all 8 call sites. It is written only
  by role seeding and a one-time migration snapshot; `CreateRole`/
  `UpdateRole` never accept it from a request DTO on any transport
  (ADR-084) — closing a class of self-escalation-via-role-naming a
  name-matched check would remain exposed to.
- **Elevation of privilege — ceiling checked against the wrong party
  (closed, real historical gap).** A privilege-ceiling check that
  inspects only the *target*'s current privileges (not the *actor*
  requesting the change) lets an attacker with zero standing self-mint
  into an empty or attacker-controlled target and pass trivially. This
  was real: `RequireMachinePrivilegeCeiling` checked only the target
  machine identity's roles until 2026-08-25. Fixed by deriving the
  ceiling from the actor's own effective privileges, checked at creation
  time, not only at credential-mint time.
- **Elevation of privilege — cross-tenant leakage (closed).** Every
  nested-resource route reconciles the child object's project against
  the caller's authorized project before acting — closing a class of
  cross-project privilege-escalation findings the 2026-09 review found
  and fixed across five lifecycle routes.
- **Information disclosure — enumeration via differential error
  shape.** A check that can't distinguish "exists, no access" from
  "doesn't exist" would otherwise leak existence through a differently-
  shaped error. [ADR-096](../../adr-096-anti-enumeration-403-for-both.md):
  the same 403 for both, verified by a call-site guard.
- **Tampering — write-path bypass.** Every write path funnels through
  the same chokepoint as reads — there is no separate, less-guarded
  write path to find.

## 4. Residual risks specific to this component

- **CLI local mode is a structural authorization bypass, not a gap in
  this chokepoint itself.** CLI local mode opens the SQLite database
  directly, which means it never calls `core.Authorize` at all — it
  isn't that the chokepoint has a flaw, it's that an entire client mode
  doesn't go through it. See `../threat-model.md` §4 (B1/B2) and §5.2 for
  the full analysis; ADR-108 (Accepted, implementation in progress)
  removes this by making the CLI a thin network client with no local
  database access.
- No other residual risk specific to the authorization chokepoint
  itself is identified beyond what's listed above as closed.
