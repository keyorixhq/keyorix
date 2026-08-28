# ADR-089: Deleting the 9 MFA-management and retention-purge `/system` relay proxies — no live caller, on two different grounds

## Status

**Accepted (2026-08-28).** #1593. Deletion executed in this pass.

## What this is

ADR-088's Wave 2 guard fix (closing the `tx.X()` and "no wrapper" blind
spots in `server/http/raw_storage_bypass_guard_test.go`) surfaced 9
previously-invisible `/system` proxy handlers that bypass a real ceiling
their wrapping `internal/core` method enforces:

- **MFA-management family** (5): `ActivateMFASecretProxy`,
  `SetUserMFAEnabledProxy`, `CreateMFARecoveryCodesProxy`,
  `DeleteMFAForUserProxy`, `DeleteMFARecoveryCodesProxy` — bypass
  `requireReauth` (`internal/core/mfa.go`), the step-up gate that stops a
  bearer-token holder from stripping a second factor.
- **Retention-purge family** (4): `PurgeDeletedUsersBeforeProxy`,
  `PurgeDeletedProjectsBeforeProxy`, `PurgeDeletedEnvironmentsBeforeProxy`,
  `PurgeDeletedSecretsBeforeProxy` — bypass the legal-hold check
  `PurgeExpiredSoftDeletes` (`internal/core/purge.go`) enforces before
  hard-deleting soft-deleted records (ISO A.5.34).

Filed as #1593. Initial framing treated both as REAL, live findings,
severe enough to jump the queue ahead of #1589 and #1592. **A liveness
check, done properly only on the third pass, found neither is live.**
Both are deleted here — the RemoteStorage client methods become
`remoteUnsupported` stubs, the `/system` handlers and their route
registrations are removed — closing the finding completely, with no new
mechanism needed.

## The verdict moved three times, and that is worth recording

1. **Filed as REAL** (#1593): correct — the ceiling bypass, once visible,
   is genuinely there in the code.
2. **Reported as LIVE**: WRONG. A real HTTP route
   (`/auth/mfa/activate`) and a real scheduler (`server/main.go`'s
   `startSchedulers`) were found and treated as deployment paths without
   checking whether the specific topology — that route or scheduler
   running against a `RemoteStorage`-backed core — can be constructed at
   all. It cannot: `validateRemoteStorageNotServer`
   (`internal/config/config.go`) rejects `storage.type: remote`
   unconditionally for any server process, EXPLICITLY including a
   scheduler-only one. This is the exact "a Go call-graph edge is not a
   deployment path" trap this campaign's own CLAUDE.md names by example.
3. **Corrected to DEAD**: a repo-wide, non-test grep for every caller of
   `core.ActivateMFA`/`DisableMFA`/`RegenerateMFARecoveryCodes`/
   `PurgeExpiredSoftDeletes` finds exactly the server-side call sites
   above and nothing else. The only process that can legitimately
   construct a `RemoteStorage`-backed core is the CLI (embedded mode,
   `internal/cli/common/remote_client.go`, which does not go through
   `Config.Validate()`). Zero CLI command files exist for MFA or
   retention/purge (`find internal/cli -iname "*mfa*" -o -iname
   "*retention*" -o -iname "*purge*"` → no results).

Each move was better-evidenced than the last. The second move being wrong
is not a reason to distrust the third — it is the reason the third pass
was done at all. Recorded here because the next person tracing this
decision should not have to redo the liveness work to trust the
conclusion.

## The two deletion grounds are different, and the difference matters

Both families are DEAD, but not for the same reason, and collapsing them
into one "no live caller" sentence would silently discard the more
important half of the finding.

**Ground 1 — structurally impossible (server-side path).**
`/auth/mfa/activate`, `/auth/mfa/disable`, and the retention scheduler
cannot run against `RemoteStorage` under any configuration:
`validateRemoteStorageNotServer` rejects it unconditionally, and
`server/main.go` is the only process that serves those routes or runs
that scheduler. Nothing can construct this topology, full stop. This
ground alone would justify deletion on its own — the same ground that
closed ADR-085's node arm.

**Ground 2 — true today, not impossible (CLI path).** The CLI's embedded
mode (`internal/cli/common/remote_client.go`) genuinely CAN construct a
`RemoteStorage`-backed core, bypassing `Config.Validate()` entirely. It
does not reach any of these 9 methods only because **no MFA or
retention/purge CLI command exists yet** — a fact about the current
command set, not a structural constraint. This is premise-true-but-
unexercised, not premise-impossible.

**Why the distinction is load-bearing, not academic:** the day someone
writes `keyorix mfa disable`, the CLI in embedded remote mode reaches
`core.DisableMFA` → `RemoteStorage.SetUserMFAEnabled` → the hub endpoint —
and if this decision is recorded as "impossible" rather than "unbuilt,"
whoever adds that command will restore the client method and the hub
endpoint from git history and never re-ask the `requireReauth` question.
The finding returns, unreviewed — dead code becoming live code without
re-review is the exact failure mode `remoteReachabilityRegistry`'s own
doc comment names by example (`RequireNodeCredentialOrPermission`'s node
arm, ADR-085). Ground 1 alone would license an unconditional "safe to
delete forever" note; Ground 2 requires the note to say what has to
happen before it's re-added.

**Recorded exactly once, precisely, and cross-referenced from every
deletion site** (`remoteReachabilityRegistry` entries, the 9 proxy files'
doc comments, this ADR):

> These endpoints are removed because no caller exists today. The
> server-side path is structurally impossible; the CLI path is not — it
> is merely unbuilt. Adding any MFA or retention CLI command revives this
> surface, and the `requireReauth` and legal-hold gaps documented in
> #1593 must be resolved before it is restored.

## Precondition this decision depends on

This deletion is sound only because `validateRemoteStorageNotServer`
continues to hold (no server process, ever, can run with `storage.type:
remote`) and because no CLI command reaches these 9 `internal/core`
methods. If either changes — a future ADR revisits ADR-083's server/CLI
split, or a `keyorix mfa`/`keyorix retention` command is added — this
decision is void for the affected family and must be re-derived, not
assumed to still hold. This is the same ADR-083 → ADR-085 → here lesson
applied a third time: write the dependency down before it's forgotten.

## Relationship to ADR-085 (not a contradiction)

ADR-085 deleted the node-credential OR-arm from `/system`'s gate: a node
credential no longer gets IN by virtue of being a node — it needs
`system.write` via a real role grant like anyone else. That was a
**restriction removed a privilege**.

This ADR deletes two families of already-privileged (`system.write`-gated)
raw storage relays because nothing ever calls them. That is **deleting an
unused capability**, not narrowing an existing one — the opposite kind of
change. Noting this explicitly so neither decision gets re-litigated by
someone pattern-matching on "ADR-085 deleted something in `/system`,
therefore this must be the same move."

## Relationship to #1592 and IngestAuditEventProxy

#1593's original filing drew the parallel to `IngestAuditEventProxy`
(REAL, deferred to Wave 4: the hub cannot distinguish a genuine spoke
relay from a bare `system.write` holder). That parallel is now moot for
these 9 specifically — there is no relay to attest, because nothing
relays. **The underlying relay-principal problem itself is not retired**:
`IngestAuditEventProxy` and any other proxy whose real ceiling ran
upstream still need it. This ADR removes 9 handlers from that problem's
instance count; it does not solve the problem.

Also not retired: **#1592, the stale-fork sweep** (does a `/system` proxy
carry the fix `internal/core` was rewritten to include, per commit
history). That is a different question — "does this proxy match core's
current shape" — orthogonal to "does anything call this proxy." Some
candidates could appear in both a future liveness sweep and #1592's
history-derived list; they remain two separate passes, not one wave that
grew a second theme.

## What was actually deleted

**RemoteStorage client methods** (now `remoteUnsupported` stubs, same
shape as `UpsertMFASecret`/`DeleteAnomalyAlertsBefore`):
`internal/storage/store/remote_mfa.go` — `ActivateMFASecret`,
`DeleteMFAForUser`, `SetUserMFAEnabled`, `CreateMFARecoveryCodes`,
`DeleteMFARecoveryCodes`; `internal/storage/store/remote_secrets.go` —
`PurgeDeletedSecretsBefore` (and its now-orphaned helper
`postRetentionBeforeCountResp`, removed entirely); `internal/storage/store/remote_users.go`
— `PurgeDeletedUsersBefore`, `PurgeDeletedProjectsBefore`,
`PurgeDeletedEnvironmentsBefore`.

**`/system` proxy handlers and route registrations**:
`server/http/handlers/mfa_management_proxy.go` — `ActivateMFASecretProxy`,
`DeleteMFAForUserProxy`, `SetUserMFAEnabledProxy`,
`CreateMFARecoveryCodesProxy`, `DeleteMFARecoveryCodesProxy` (plus the
now-unused `parseMFAUserIDParam` helper); `server/http/handlers/retention_proxy.go`
— `PurgeDeletedSecretsBeforeProxy`, `PurgeDeletedProjectsBeforeProxy`,
`PurgeDeletedEnvironmentsBeforeProxy`, `PurgeDeletedUsersBeforeProxy`
(plus the now-unused `refuseIfLegalHoldActive` helper — the legal-hold
check design that would have fixed these four IF they were live; kept
out of the tree entirely rather than left as dead code, since nothing
calls it). Route registrations removed from `server/http/router.go`.

**Left untouched, deliberately**: `GetMFASecretProxy`,
`CountUnusedMFARecoveryCodesProxy`, `MarkTOTPStepUsedProxy` (still real,
still called by the login-verification proxy path), and
`DeleteExpiredRoleGrantsProxy`/`DeleteExpiredShareRecordsProxy`/
`ListUsersInStateBeforeProxy` (different `internal/core` callers, live,
out of scope for this finding).

## Population, predicted then verified

Guard registries updated, each cross-checked against actual test output,
not assumed: `knownUnfixedRawStorageBypasses`
(`server/http/raw_storage_bypass_guard_test.go`, 9 entries removed —
they no longer reproduce, since the handlers are gone), `remoteReachabilityRegistry`
(`internal/storage/store/remote_reachability_registry_test.go`, 9 new
`reachabilityDead` entries, each naming both grounds), `remoteUnsupportedAllowlist`
(`internal/storage/store/remote_mfa_purge_deletion_completeness_test.go`,
9 new `statusIntentional` entries), and `knownUnresolvedWireCalls`
(`internal/storage/store/remote_wire_route_coverage_test.go`, 7 stale
line-number entries corrected, 1 removed outright —
`postRetentionBeforeCountResp`'s own entry, since that function no longer
exists).

## Verification

- `go build ./...`, `go vet ./...`: clean.
- `go test ./server/http/...`: clean (including the corrected end-to-end
  `TestRemoteStorageMFAManagement_StoragePrimitives_RealServer`, trimmed
  to the two surviving primitives).
- `go test ./internal/storage/store/...`: clean except two pre-existing,
  unrelated failures (`TestListShares_ExcludeExpiredIncludeActive`,
  `TestListSharesBySecretIDs`) — confirmed via `git diff --stat
  origin/main` that neither failing test's file was touched by this
  change, and both fail in isolation on an otherwise-unmodified tree; not
  investigated further here, out of scope for this deletion.
- Every guard this deletion touches (`TestNoUnjustifiedRawStorageBypass`,
  `TestEveryStructuralStubHasReachabilityVerdict`,
  `TestRemoteUnsupportedStubsAreAllowlisted`,
  `TestRemoteStorageWireCalls_HaveMatchingRoute`) passes green.
- `git tag pre-1593-mfa-purge-deletion` placed before the first removal,
  annotated with what it preserves, in case the liveness question needs
  revisiting a fourth time.

## What this does not resolve

- The relay-principal problem (`/system` cannot distinguish a genuine
  spoke relay from a bare `system.write` holder) — still open, still
  filed against `IngestAuditEventProxy`, unaffected by this deletion.
- #1592 (the stale-fork sweep) — unaffected, still filed, still
  sequenced behind the guard fixes that already landed.
- #1579, #1580, #1585, #1586, #1587 — untouched, out of scope for this
  pass.
