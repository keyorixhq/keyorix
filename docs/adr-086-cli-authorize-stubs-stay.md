# ADR-086: `GetUserRoleIDsAt`/`GetUserGroupRoleIDsAt`/`RoleSetHasPermission` stay stubbed on `RemoteStorage` — corrects ADR-083's deferred-work section

## Status

**Accepted (2026-08-28).** Partially corrects ADR-083's "Deferred work"
section: `GetUserRoleIDsAt`, `GetUserGroupRoleIDsAt`, and
`RoleSetHasPermission` are **not** part of the now-dead
`storage.type: remote`-as-server topology's cleanup surface. They have a
second, live, CLI-direct caller ADR-083's evidence table did not examine.
**Decision: keep all three as unconditional stubs.** Do not implement them
over the wire, and do not delete them in the Wave 1 cleanup pass ADR-083's
deferred work anticipates.

## Context

G80 Wave 0 (`docs/g80-wave0-remote-storage-partition.md`) set out to
partition `RemoteStorage`'s ~88-method stub surface into LIVE (keep),
DEAD (server-topology-only, safe to delete per ADR-083), and UNRESOLVED.
Tracing `GetUserRoleIDsAt`/`GetUserGroupRoleIDsAt`/`RoleSetHasPermission`
found they're called from `core.Authorize` → `scopedRoleIDs` →
`roleSetContainsAdmin`, and confirmed that chain is invoked directly —
no HTTP router, no gRPC server, no middleware — by four CLI command files
that call `common.InitializeCoreService()` unconditionally (no
`common.NewRemoteClient()`/`common.ResolveRemote()` guard):
`internal/cli/invite/send.go:93`, `internal/cli/request/list.go:87`,
`internal/cli/request/review.go:136`, and
`internal/cli/migrate/user_to_machine.go:119,126`.

G80 Wave 0b confirmed this live, against a real hub server under
`storage.type: remote`: all four commands, plus five more account-lifecycle
commands sharing the same `requireUserAuthority` mechanism
(`user revoke-sessions/suspend/reactivate/resend-setup-link/delete`) and two
more invitation commands (`invite resend/revoke`) — 11 commands total —
fail with `failed to verify --by authority: not supported in remote
storage`. Filed as
[#1575](https://github.com/keyorixhq/keyorix/issues/1575).

### What ADR-083 actually established, and where it stopped

ADR-083's own evidence table (reproduced there) traced `AuthorizePrincipal`
— the entry point `RequirePermission`/`RequireScopedPermission` HTTP/gRPC
middleware uses — and correctly found all three of these methods are hard
stubs with no working caller through that entry point, because no server
process can boot with `storage.type: remote` (`validateRemoteStorageNotServer`).
ADR-083's "Who is actually affected" table explicitly lists
`internal/cli/common.InitializeCoreService` as a **non**-affected consumer:
"one-shot commands calling core methods directly in-process, no
router/gRPC server ever constructed" — correct, as far as it goes.

What ADR-083 did not examine: `core.Authorize` (`internal/core/authz.go:214`)
is a **second**, independent public entry point into the identical
`scopedRoleIDs`/`RoleSetHasPermission` chain — not gated by any HTTP/gRPC
middleware at all, callable directly by any `core.KeyorixCore` consumer,
including the CLI commands ADR-083 itself said are unaffected by the
server-topology gate. ADR-083's deferred-work section lists these three
methods' proxying machinery among the "now-dead code" candidates for a
future cleanup branch — that framing is accurate for the server-side
proxy route registrations it also lists, but not for the `RemoteStorage`
stubs themselves, which this ADR corrects.

### Why the CLI calls `Authorize` directly at all

`requireUserAuthority`/`requireInviteAuthority` (`internal/cli/user/user.go:46-70`,
mirrored in `invite/send.go`, `request/{list,review}.go`,
`migrate/user_to_machine.go`) are a deliberate, correct security control
(#264, #491): the CLI's `--by <admin-email>` flag lets an operator attribute
a destructive account-lifecycle or invitation action to a named admin for
audit purposes, but resolving that email to a user ID proves nothing about
whether that user actually holds the authority to perform the action. The
local CLI process has no session/middleware layer to enforce this, so
without this check, `--by` would let anyone attribute an arbitrary
destructive action to any account's identity in the audit trail — purely
for what the audit log records, not as a bypassable ACL. Neither #264 nor
#491's commit messages mention `storage.type: remote` or `RemoteStorage` —
this check was added with only embedded/local mode in mind, years after the
`RemoteStorage` stubbing decision it silently depends on.

## Decision

**Keep `GetUserRoleIDsAt`, `GetUserGroupRoleIDsAt`, and
`RoleSetHasPermission` as unconditional `RemoteStorage` stubs.** Two options
were considered and rejected:

1. **Implement the three methods over the wire**, so `core.Authorize` works
   against a remote backend. Rejected: this would have the CLI fetch
   role/permission data from the hub and decide, client-side, whether the
   `--by` actor is authorized — the fat-client pattern this campaign has
   spent multiple rounds dismantling elsewhere (the wire-actor bug class,
   where a client's claim about a principal was trusted instead of the
   hub's). The client deciding who is authorized is the wrong shape
   regardless of whether the wire call itself would be correct.
2. **Delete them**, per a literal reading of ADR-083's deferred-work
   section. Rejected: they have a real, current, live caller (11 CLI
   commands under `storage.type: remote`); deleting them breaks CLI
   functionality that works correctly under every other topology.

The correct design is **hub-side authorization**: the CLI sends the
operation and the `--by` actor; the hub evaluates authority against its own
role/permission tables, the same way it does for every other API-routed
request. This is a real design change (a new authenticated endpoint or
endpoint family, plus removing the CLI-local check once the hub-side one is
in place), not a quick fix, and it unifies four issues that are all the
same underlying question about where authority gets evaluated:
[#1546](https://github.com/keyorixhq/keyorix/issues/1546),
[#1551](https://github.com/keyorixhq/keyorix/issues/1551),
[#1572](https://github.com/keyorixhq/keyorix/issues/1572), and
[#1575](https://github.com/keyorixhq/keyorix/issues/1575). Deferred to
Wave 2.

## Consequences

**Positive.** No CLI functionality regresses. The 11 broken commands
(#1575) remain broken until the Wave 2 hub-side authorization design lands,
but fail closed — the check refuses rather than permits, so this is a
functionality gap, not a security hole. The eventual Wave 1 deletion pass
against `docs/g80-wave0-remote-storage-partition.md`'s partition now has a
correct exclusion list and won't silently break these four (of eleven)
commands' underlying mechanism.

**Negative.** `storage.type: remote` remains only partially supported:
the developer workflow (secret/project/rbac/share/group CRUD, access
requests) works; account-lifecycle and invitation-management commands do
not, until Wave 2. This should be documented explicitly in README.md and
`docs/REMOTE_CLI_SETUP.md` (tracked in #1575) so an operator hits
documentation rather than a bare CLI error.

## The recurring mechanism, named

This is the third time in this campaign an ADR's factual claims have been
found to not hold under direct testing (ADR-085's premise, ADR-052's note,
now this). The pattern each time: an ADR is accurate at the moment it's
accepted, records intent and evidence gathered under a specific,
stated scope, and a later reader — including the same author, in a later
session — treats its conclusions as settled fact rather than as evidence
scoped to what was actually checked. ADR-083's evidence table was correct
about `AuthorizePrincipal`; it was never a claim about `core.Authorize`,
but its deferred-work section's phrasing didn't make that scope boundary
visible to a reader planning a deletion. The fix isn't "write more
careful ADRs" — some scope boundary will always exist. It's treating an
ADR's factual claims the same way as any other code claim before relying
on them for a NEW decision: re-verify reachability at the point of use,
don't inherit "this was already established" from a document whose
verification scope you haven't re-read.
