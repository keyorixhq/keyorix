# FINDING: RequestSecretAccess's own admin-notification fan-out had no panic protection, and could report an already-committed request as a failure

**Date:** 2026-09-24
**Component:** `internal/core/classification_gate.go` (`notifySecretAccessRequested`,
called from `RequestSecretAccess`).
**Status:** Fixed, this PR.
**Severity:** Medium — not a privilege-escalation or data-exposure bug, but a
genuine atomicity/response-integrity defect: a caller can be told an operation
failed when it actually succeeded, which risks a client retrying (harmless
here — `RequestSecretAccess`'s own pending-request dedup guard rejects a
retry cleanly) or, worse, an operator concluding the request never happened
and not following up on it.

Found by `server/faultops`' `FuzzStorageFaultOperations`, fuzzing its own new
"REST POST /api/v1/secret-access-requests" operation-catalog entry (added in
the sibling PR that adds fuzz coverage for the newly-merged secret-access-request
routes, #2032) — corpus input `input=3232103231`,
`fault=(method=ListProjectMembers, NthCall=1, kind=panic)`.

## Summary

`RequestSecretAccess` (`classification_gate.go`) commits the new
`AccessRequest` row via `c.storage.CreateAccessRequest`, writes its own audit
event, and only THEN calls `c.notifySecretAccessRequested(ctx, created,
secret)` — a best-effort fan-out that lists the request's project's members
(`c.storage.ListProjectMembers`) and notifies every approver-role member.
That call ran with no panic protection, synchronously, on the same goroutine
as the HTTP request. A panic anywhere inside it (a storage-layer bug, in
production; a fault-injected panic here) propagates straight past the
already-committed write, is caught only by the HTTP layer's Recovery
middleware several frames up, and turns into a 500 response — while the
`AccessRequest` row the client is told failed to create in fact exists.

```
ORACLE (a) VIOLATION — reported an ERROR but logical state changed anyway
(partial commit). Differing tables: [AuditEvent AccessRequest]
```

## Same shape as an already-fixed defect

This is the identical "best-effort helper masks an already-successful
primary operation" pattern
`docs/findings/2026-09-23-FINDING-breakglass-revoke-half-commit.md`'s "Second
defect" section found and fixed in `evictUserSessionCache`
(`internal/core/account.go`) — same fix, too: wrap the best-effort call in
`defer func() { if r := recover(); r != nil { log.Printf("SECURITY: ...") } }()`,
so a panic degrades to a logged, swallowed failure of the NOTIFICATION only,
never of the (already-successful) primary write.

## Fix

`internal/core/classification_gate.go`: `notifySecretAccessRequested` now
recovers from a panic in its own body, logging
`SECURITY: notifySecretAccessRequested panicked for request %d (best-effort,
primary operation already succeeded): %v` and returning normally — the
caller (`RequestSecretAccess`) always reports success once the row is
actually committed, regardless of whether the notification fan-out
succeeded, partially succeeded, or panicked.

## Sibling call sites — found, NOT fixed here

The same unprotected shape (synchronous, no `recover`, calling a storage
`List*` method after a primary write has already committed, to fan a
notification out to multiple recipients) exists at three more sites in
`internal/core/notifications.go`:

- `notifyAccessRequested` (line ~162) — the project/role access-request
  family's own equivalent of `notifySecretAccessRequested`; calls
  `ListProjectMembers` the same way, from `RequestProjectAccess`.
- `notifyGroupSecretShared` (line ~222) — calls `ListGroupMembers`, from
  `ShareSecretWithGroup`.
- `notifyGroupSecretShareRevoked` (line ~255) — calls `ListGroupMembers`,
  from the group-share revoke path.

All three are reachable today and share the exact defect shape this finding
fixes one instance of. Not fixed here, for the same reason the prior
finding's "Out-of-scope observation" section gave: deciding whether the
right general fix is "wrap each site individually" (four near-duplicate
`defer recover()` blocks) or "dispatch the whole notify fan-out via the
existing best-effort/detached-goroutine convention other audit-adjacent code
already uses" is a design call this PR — whose purpose is adding fuzz
coverage, not auditing `notifications.go` — should not make unilaterally in
passing. Flagging for a dedicated follow-up rather than silently leaving it
for the next campaign to rediscover independently at each site.

## Tests

- `internal/core/classification_gate_notify_panic_test.go` (new):
  `TestRequestSecretAccess_NotifyPanicDoesNotUndoAlreadyCommittedRequest` —
  wraps a real `store.LocalStorage` in `faultstorage.FaultyStorage`, arms a
  panic on `ListProjectMembers`'s first call, and asserts `RequestSecretAccess`
  still returns the created request with no error, confirmed by a fresh
  unfaulted re-read (`GetAccessRequest`) rather than trusting the in-memory
  return value alone.
- `internal/core/mfa_stepup_purpose_guard_test.go`: this fix's one-line import
  addition (`"log"`) shifted `checkRestrictedMFAGate`'s
  `GetActiveMFAStepUpGrant` call site from `classification_gate.go:177` to
  `:178` — `TestMFAStepUpConsumersUseExpectedPurpose`'s line-keyed allowlist
  updated to match (two occurrences: the map key and one prose cross-reference
  in the `mfa_stepup_proxy.go:63` entry's own reason string). Confirmed both
  guard tests pass with the corrected line number and the full
  `internal/core`/`internal/core/rules`/`internal/core/storage` suite is
  green.

## Red-proof

`git stash` of just `internal/core/classification_gate.go` in this worktree,
re-running `TestRequestSecretAccess_NotifyPanicDoesNotUndoAlreadyCommittedRequest`:
fails with the panic propagating out of `RequestSecretAccess` itself
(`FAIL github.com/keyorixhq/keyorix/internal/core`, panic trace through
`notifySecretAccessRequested` → `RequestSecretAccess` → the test). Restoring
the fix (`git stash pop`) returns it to green. Not committed as a revert —
verified interactively, matching this repo's established red-proof practice
for a fix landing alongside its own regression test.
