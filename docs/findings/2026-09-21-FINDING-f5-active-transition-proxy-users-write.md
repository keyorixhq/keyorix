# FINDING: `UpdateUserIfActiveStateMatchesProxy` missing its `users.write` ceiling

**Date:** 2026-09-21
**Component:** `server/http/handlers/users_active_transition_proxy.go`
(`PUT /api/v1/system/users/{id}/active-transition`), `internal/core/users.go`
(the reused authority-check wrapper).
**Status:** **Fixed**, this PR. Proving tests:
`TestUpdateUserIfActiveStateMatchesProxy_SystemWriteOnly_CannotRewriteAdminEmail`
(red-before/green-after) and
`TestUpdateUserIfActiveStateMatchesProxy_UsersWriteHolder_CanRewriteOtherUserEmail`
(control case — a properly-authorized caller still succeeds), both in
`server/http/users_active_transition_proxy_ceiling_test.go`.
**Severity: Critical.**

## Summary

Every route under `/api/v1/system` is gated by one blanket permission,
`system.write` (`server/http/router.go`:
`r.Use(customMiddleware.RequirePermission(permSystemWrite))`). That gate is
deliberately broad by design — `system.write` is documented as grantable to a
narrow, unrelated custom role (audit checkpoints, legal holds, risk
exceptions, SoD policies, admin job triggers), not an admin-only permission.

`UpdateUserIfActiveStateMatchesProxy` relied on that blanket gate alone, with
no per-target authority check of its own. The real, human-facing authority
path for editing a user is `users.write` at global scope
(`RequirePermission(permUsersWrite)` on `PUT /api/v1/users/{id}`) —
`core.UpdateUser` itself performs no caller-authority check; the HTTP
transport is the actual ceiling, and this route's transport was the wrong
(too broad) one. A principal holding `system.write` for its documented,
narrow, unrelated purpose could reach this route and rewrite ANY user's
username/email/display_name/active state, including a global admin's.

## Reproduction

Reproduced live against `origin/main` (`bb93b549`) before the fix: a
`system.write`-only caller (no `users.write`) issued
`PUT /api/v1/system/users/{admin_id}/active-transition` with a body changing
the target admin's email. Result: HTTP 200, and the admin's email was
actually changed in storage — confirmed by re-reading the row, not just the
status code.

## Fix

`core.RequireUsersWriteAuthority` — a new exported wrapper around the
existing `requireUserCredentialsRevokeAuthority` (already shared by
`RevokeAllPersonalAccessTokensForUserProxy`/`DeleteSessionsForUserExceptProxy`)
— is called in the handler immediately after body decode, before any storage
read (so an unauthorized caller can't use this route's own uniqueness
pre-checks as a `users.write`-gated username/email existence oracle).

```go
actorType, actorID := requestActorKindAndID(r)
if err := h.coreService.RequireUsersWriteAuthority(r.Context(), actorType, actorID); err != nil {
	writeUserCredentialsRevokeError(w, "active-transition", err)
	return
}
```

## Red-proof

Reverting the check above (commenting it out) makes
`TestUpdateUserIfActiveStateMatchesProxy_SystemWriteOnly_CannotRewriteAdminEmail`
fail (`--- FAIL`); restoring it returns both proving tests to green. Verified
directly on this branch before opening the PR.

## Verification

`gofmt -l`, `go vet ./...`, `go build ./...` all clean. `go test
./server/http/... ./internal/core/...` green (both individually and
combined). No collateral test breakage on this isolated branch — this PR
carries only F5's own fix and its own regression/control tests, cherry-picked
onto a clean `origin/main` base.

## Severity rationale

Rated **Critical**: any principal holding only `system.write` — a permission
this codebase documents and intends as grantable to a narrow, non-admin
custom role (audit checkpoints, legal holds, risk exceptions, SoD policies,
admin job triggers) — could rewrite a GLOBAL ADMIN's email address through
this route, which chains directly into account takeover via that admin's own
password-reset flow. No ownership, project-scoping, or admin-tier check
stood between `system.write` and a full identity rewrite of any user in the
install.
