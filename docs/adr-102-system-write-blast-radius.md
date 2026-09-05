# ADR-102: Semantics and blast radius of the `system.write` capability

## Status

**Proposed.** This ADR intentionally does not choose between the two candidate
positions below — see "What this ADR does not do." It records the facts #1622's
investigation established so the choice can be made deliberately, not by
default.

## Context

#1622 (ExpireSetupTokenProxy) found that a single `/system` proxy route lets any
`system.write` holder mass-expire setup tokens by ID, with no per-caller rate
limit, ownership check, or (until #1622's own fix) audit trail. The natural
first instinct is to add a rate limit or an ownership check to that one route.
Investigating what `system.write` actually gates first showed that instinct is
premature: the blast-radius question is not a property of this one handler, it
is a question about what `system.write` is *supposed to mean* in this system —
and the answer determines whether a per-route control is even the right shape
of fix, anywhere on this surface.

### What `system.write` currently gates

`server/http/router.go`'s `/system` route group (`r.Route("/system", ...)`,
originally introduced to let a `storage.type: remote` (ADR-049) downstream
server proxy its storage calls to an upstream hub) is gated by exactly one
permission check, applied once at the group level:

```go
r.Route("/system", func(r chi.Router) {
    r.Use(customMiddleware.RequirePermission(permSystemWrite))
    ...
```

There is no second, narrower tier inside the group — every route comment in
this section says so explicitly ("there is no separate system.read tier in
this group"). Counted directly from the router (`148` route registrations
between the group's opening and its closing brace, current `main`), a
`system.write` holder can reach:

- **Every setup-token operation** (create, look up by hash, supersede, expire —
  #1622's own surface) and every project invitation (create, update, list).
- **Every machine identity primitive**: create/update/revoke machine identity
  credentials, OIDC bindings, classification, and role grants — i.e., mint or
  revoke the credential of any non-human principal in the system.
- **User account state**: activate/deactivate any user
  (`UpdateUserIfActiveStateMatches`), revoke all of a user's personal access
  tokens, delete all of a user's sessions except one.
- **RBAC primitives**: role/permission CRUD and role-grant proxying.
- **Break-glass activation and revocation** (the system's own emergency-access
  escape hatch).
- **MFA/WebAuthn administration**: mark TOTP steps used, create/delete MFA
  recovery codes, enable/disable a user's MFA, create/update WebAuthn
  credentials and sessions.
- **Audit-adjacent administration**: SoD policy CRUD, access-review campaign
  and access-request administration, legal holds, risk exceptions, retention
  sweeps (`DeleteExpiredRoleGrants`, `DeleteExpiredShareRecords`).
- **Catalog structure**: projects, environments, groups, project memberships.
- **Secret-adjacent metadata**: secret dependencies, connect-ref grants, share
  records, dynamic-secret configs.
- Login/password-reset rate-limit counters and the login-attempt log itself.

In short: essentially the entire administrative surface of the product, not a
narrow "storage relay" capability. `system.write` was designed for one thing
(letting a downstream node relay storage calls to a hub) and has since become
the gate for everything an admin does through this route group.

### The gate has a second, wider door

`RequirePermission` is not the only way in. `router.go`'s own comment on this
group notes that `adminRoleNames` (`authz.go`) unconditionally bypass every
permission check — so any admin-tier role holder reaches this entire surface
regardless of whether `system.write` was ever explicitly granted to them. The
blast radius below is therefore a floor, not a ceiling: it applies to the
narrowest role that can reach this group, not just to a role explicitly
scoped to `system.write`.

### What a `system.write` holder can do today, concretely

Combining the two points above: a `system.write` holder (or any admin-tier
role holder) can, in a single authenticated session and with no route-specific
throttle:

- Mass-expire or mass-invalidate every outstanding setup token and invitation
  in the system (#1622's own finding).
- Revoke or reclassify every machine identity credential — silently disabling
  every automated integration at once.
- Deactivate every user account, or revoke every user's sessions and PATs,
  effectively locking out the entire org.
- Grant or remove any RBAC role from any principal, including other admins.
- Revoke a break-glass activation that a genuine incident responder is relying
  on.
- Rewrite audit-adjacent records (SoD policies, legal holds, risk exceptions)
  that other controls assume are administrator-only and rare.

None of this requires chaining exploits — it is the literal, intended
capability of the permission as currently scoped, exercised through routes
that (before #1622, and possibly others — see #1622's sibling list) do not all
audit their own use.

## The two candidate positions

**(a) `system.write` is break-glass / root-equivalent.** If that is the
intended model, then the 148-route blast radius above is in-remit by design —
an admin-tier credential is *supposed* to be able to do all of this, the same
way a Unix root shell can. Under this position, a per-route rate limit or
ownership check (the instinct #1622 rejected for its own scope) would be
theater: it would not meaningfully bound what a legitimately-scoped holder can
do, and an illegitimately-obtained credential has already cleared a higher bar
than any in-route check could add. The correct control under this position is
**detection, not prevention**: alerting on the audit stream for anomalous
`system.write` activity (volume spikes, off-hours mass-mutation, a pattern
inconsistent with the relay use case the permission was named for), building
on the anomaly-detection subsystem that already exists in this codebase
(distinct from, and not a duplicate of, that existing machinery — see it
before building anything new here). This position requires every route in the
group to actually emit an audit event for its own use (currently not
universally true — see #1622's sibling list), since detection cannot alert on
what was never recorded.

**(b) `system.write` is a routine operator role.** If instead `system.write`
is meant to be grantable to a narrower, more routine operational function
(e.g., "the person who manages downstream node relays" or "the on-call who
resends invitations"), then the current single flat gate is a scoping defect,
and the whole `/system` surface — not just the setup-token routes — needs to
be split into narrower permissions (e.g., a real `system.read` tier the
group's own comments note doesn't exist, plus resource-scoped write
permissions: `system.setup_tokens.write`, `system.machine_credentials.write`,
etc.) so that a routine grant of "resend invitations" does not silently also
grant "revoke break-glass" and "deactivate any user." Under this position,
#1622's audit-trail fix is necessary but insufficient — the real fix is
narrowing the grant surface itself, of which #1622's route is one symptom
among ~148.

## What this ADR does not do

It does not choose between (a) and (b). That is a product/threat-model
decision this campaign's own standing practice (see `docs/g80-remediation-
notes.md`) requires surfacing to a human rather than resolving unilaterally —
the two positions imply materially different remediation programs (an
alerting-rule backlog vs. a permission-scoping migration touching every
`/system` route and every role that currently holds `system.write`), and
picking wrong wastes real engineering time either building alerting nobody
needed or scoping permissions nobody asked for.

It does not implement anything — no rate limiting, no ownership checks, no new
permission strings, no alerting rules. #1622's own fix (the audit-trail gap on
one route) shipped separately and does not depend on this decision either way.

## Recommendation, offered not decided

If a decision is wanted without further investigation: this system already
documents `system.write` as intended for downstream-node relay (see this same
router group's own introductory comments, and ADR-049), which argues for (a)
narrower in spirit — but the fact that 148 routes across nearly every resource
type in the product have accreted onto it since argues that, whatever the
original intent, the *current, shipped* semantics are already much closer to
(a) in practice. That tension is itself the finding: the permission's name and
original design point toward (b), but 148 routes of accreted reality already
behave like (a). Resolving that tension is exactly the decision this ADR
declines to make unilaterally.

## Consequences

- Until this is decided, every future `/system` route addition should be
  read as adding to an already-root-equivalent surface, not a narrow one —
  reviewers should weigh new routes accordingly regardless of which position
  eventually wins.
- Position (a)'s alerting-rule work and position (b)'s permission-scoping work
  are both real, multi-PR programs; neither should be started speculatively
  before this ADR is resolved.
- #1622's sibling list (raw-storage-bypass audit gaps on other `/system`
  routes, recorded in that PR's own description) is relevant evidence for
  either position: under (a), each is a detection blind spot to close; under
  (b), each is one more reason the surface needs narrowing.
