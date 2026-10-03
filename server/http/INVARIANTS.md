# server/http invariants

Read this before changing anything in `server/http` (+ `server/http/handlers`) — the REST
transport. `internal/core` holds the actual authorization/business logic; this package's job
is to never let a route reach it without the right gate, and to never let a route reimplement
a check `internal/core` already owns. See `internal/core/INVARIANTS.md` for the ceiling logic
itself and `server/middleware/INVARIANTS.md` for the auth-cache/rate-limit machinery this
package's routes sit behind.

Format: `INV-HTTP-NN <rule>. Why: <source>. Guard: <test> | UNGUARDED (#issue)`.

## Structural, repo-wide route sweeps (AST over `router.go`, not hand-maintained lists)

- **INV-HTTP-01** Every direct role-grant call site, repo-wide (`extractAllRouterRoutes` over
  every handler registered in `router.go`, with a population-size tripwire so a router
  refactor can't shrink coverage unnoticed), checks authority via
  `core.RequireAuthorityForRole`/`RequireGranterHoldsRolePermissions` before persisting a
  Role-shaped wire field. Why: found 3 times independently
  (`CreateInvitationProxy`/`CreateMembershipProxy`/`UpdateMembershipProxy`), security-closures
  `INV-1-grant-authority`. Guard: `role_grant_authority_guard_test.go:TestEveryDirectRoleGrantChecksAuthority`.
- **INV-HTTP-02** A node-credential-gated proxy handler that calls
  `h.coreService.Storage().X(...)` directly, when `internal/core` ALSO exposes an exported
  `KeyorixCore` method wrapping `c.storage.X(...)` with its own ceiling checks, must route
  through the core method — bypassing it defeats every real ceiling
  (`requireGranterHoldsRolePermissions`, `requireAuthorityForRole`, `guardLastProjectAdmin`)
  for any `system.write` holder. Why: #1542/#1545/#1546/#1547 — scope widened from an 18-route
  subset to every route in `router.go` after #1545/#1546 were found BY HAND outside that
  subset. Guard: `raw_storage_bypass_guard_test.go` (repo-wide, `extractAllRouterRoutes`).
- **INV-HTTP-03** Every `permSystemWrite`-gated route in `router.go` is in the reviewed
  `systemWriteScopeAllowlist` with a written reason (what it mutates, why `system.write` and
  not a narrower permission). Why: ADR-110. Guard:
  `system_write_scope_test.go:TestSystemWriteRouteAllowlistCoversEveryGateSite`
  (adr-conformance `ADR-110-SYSTEM-WRITE-SCOPE-GUARD`).
- **INV-HTTP-04** Every `permAlertsWrite`-gated route is in `alertsWriteScopeAllowlist` with a
  written reason — `alerts.write` is the narrower "alerting operator" persona ADR-110's F1
  follow-up split off `system.write`; notification-only routes that could let an alert
  operator exfiltrate anomaly/compliance findings deliberately stay on `system.write` instead.
  Guard: `alerts_write_scope_test.go`.
- **INV-HTTP-05** Every `RequirePermission(permSystemRead)`/`RequireScopedPermission(permSystemRead, ...)`
  call site in `router.go` is explicitly reviewed and justified in an allowlist — `system.read`
  is the universal `system_viewer` baseline auto-assigned to every user (including SSO/JIT/SCIM-
  provisioned ones) at creation, so gating a deployment-wide disclosure report on it alone grants
  it to anyone with an account. Why: CP-001/CP-008 disclosure family, 7+ confirmed prior
  instances. Guard: `permission_sweep_test.go` (`TestNoUnjustifiedSystemReadOnlyGates`,
  `TestPermissionSweepAllowlistJustificationsAreNonEmpty`, `TestPermissionSweepAllowlistEntriesStillExist`).
- **INV-HTTP-06** Deployment-wide disclosure/reporting routes (`GET /admin/usage`,
  `GET /admin/billing/report`, and siblings) require `audit.read`, not merely `system.read` — a
  baseline (`system_viewer`) caller is denied (403), an `audit.read` holder (`system_auditor`)
  succeeds with the expected payload. Why: #255/#272-275/#280-281, the 7th+ confirmed instance
  of the same mistake. Guard: `deployment_disclosure_family_test.go`
  (`TestAdminBillingReport_PermissionTiers` + the per-route table).

## Anti-enumeration (ADR-096)

- **INV-HTTP-07** Dynamic-secret config/lease routes follow the house 403-for-both
  anti-enumeration convention — identical denial shape for "exists but not yours" and
  "doesn't exist" — via `RequireScopedPermission` +
  `ScopeFromDynamicSecretConfigParam`/`ScopeFromDynamicSecretLeaseParam` in the router/
  middleware chain, never the old Convention B (uniform 404 regardless of caller privilege)
  the handler itself used to implement. Why: #1645/ADR-096. Guard:
  `dynamic_secrets_403_convention_test.go` — can only be demonstrated through the real
  router+middleware chain, since the authorization decision no longer lives in the handler.
- **INV-HTTP-08** A 403/404 split is never usable as an existence oracle anywhere it's the
  authorization boundary — e.g. SoD policy delete for a non-admin returns an identical denial
  for a non-existent vs. a non-owned policy. Why: security-closures `FIX-6-sod-oracle`. Guard:
  `TestDeleteSoDPolicy_NonAdmin_NonExistentAndNonOwned_IdenticalDenial`.

## Multi-tenant isolation (DAST fuzzers)

- **INV-HTTP-09** Principal A can never read, enumerate, or confirm the existence of principal
  B's secrets, against the REAL wired stack (router + auth middleware + core + crypto +
  storage) — confidentiality, no-enumeration, and no-existence-oracle are all deny-direction/
  equality-only oracles, so none can false-positive. Guard:
  `multitenant_isolation_fuzz_test.go:FuzzMultiTenantIsolation` (SQLite always, Postgres when
  `KEYORIX_TEST_PG_DSN` is set).
- **INV-HTTP-10** REST and gRPC return the identical ALLOW/DENY decision for the same actor and
  the same target secret, and identical plaintext when both allow — a divergence is a
  transport-dependent isolation bypass. Why: both transports share one
  `*core.KeyorixCore`, so a grant/revoke is visible to both instantly; any difference in the
  authorization OUTCOME is a bug, not a timing artifact. Guard:
  `multitenant_isolation_grpc_fuzz_test.go:FuzzMultiTenantIsolationGRPC`. See
  `server/grpc/INVARIANTS.md` for the gRPC-side half of this same invariant.

## Auth-cache interaction (mechanism owned by server/middleware, exercised here)

- **INV-HTTP-11** Reactivating a user does not spuriously tombstone a personal access token
  that was created WHILE the account was suspended and never actually cached — the proactive
  cache-eviction sweep only runs when the TARGET state is more restrictive than plain active.
  Why: security-closures `account-state-reactivate-pat-tombstone-001`, found live by
  `FuzzAuthCacheDifferential` within seconds of its first run. Guard:
  `TestReactivateUser_DoesNotTombstoneNeverCachedPAT`.
- **INV-HTTP-12** A session cache hit refreshes `AccountState`/`Restricted` on every hit —
  `AccountLoginBlocked` and `AccountRestricted` are not the same predicate (e.g.
  `pending_first_login`/`password_reset_required` are restricted but not login-blocked). Why:
  security-closures `session-restricted-cache-race-001`. Guard:
  `TestSessionCacheHit_AccountRestrictionRefreshedOnHit`.
- **INV-HTTP-13** A revoked session's stale positive cache entry can never resurrect
  authentication — `serveAuthCacheHit`'s session branch re-checks whether the session row
  itself still exists (`core.SessionLiveForToken`), not only the owning account's state. Why:
  security-closures `session-revoke-cache-race-001`, found by `FuzzConcurrentOpsLinearizable`.
  Guard: `TestSessionRevoke_ConcurrentRevokeDoesNotResurrectCachedAuth`.
- **INV-HTTP-14** The session-liveness recheck closes the ADR-039 cross-replica
  cache-staleness bound down to the next request — a replica that never heard about a sibling's
  revoke still denies on its own next cache hit, since the liveness check re-reads the same
  shared DB every replica writes to. Why: security-closures `session-revoke-cache-race-002`.
  Guard: `TestSessionRevoke_SecondReplicaNeverInvalidatedCacheHitDenied`.

## Account/machine-identity transitions

- **INV-HTTP-15** `TransitionMachineIdentity`'s post-commit auth-cache eviction panic is
  recovered and fails CLOSED (flushes every machine-token cache entry) rather than letting the
  panic unwind past an already-committed suspend/revoke and misreport a successful revoke as a
  500. Why: security-closures `machine-identity-evict-panic-fail-closed-001`, found by
  `FuzzStorageFaultOperations`. Guard: `TestTransitionMachineIdentity_EvictionPanicStillRevokesAndFailsClosed`.
- **INV-HTTP-16** The `DeleteSecret` handler routes a machine-identity-authenticated caller
  through the route's own scoped-permission gate, never the per-user owner/sharing permission
  check (which requires `userID != 0` and a machine caller can never satisfy). Why:
  security-closures `secret-delete-machine-actor-001`, #1808. Guard:
  `TestDeleteSecret_MachineActorUsesScopedPermissionNotOwnerCheck`.
- **INV-HTTP-17** Logout on an already-invalidated session (double-click, two tabs, client
  retry) returns 401 (an ordinary auth outcome), never 500. Why: security-closures
  `logout-already-invalidated-session-500-001`. Guard: `TestLogout_InvalidToken_S8`.

## Login / MFA rate limiting (ADR-040)

- **INV-HTTP-18** `/auth/mfa/verify` shares the cluster-wide DB-backed login rate limiter —
  it is not unlimited. Why: ADR-034 + ADR-040. Guard: `TestVerifyMFA_RateLimited_S13B`
  (adr-conformance `ADR-034-MFA-VERIFY-RATELIMIT`).
- **INV-HTTP-19** `Login`/`RefreshToken`/`VerifyMFA`/`BeginWebAuthnLogin`/`FinishWebAuthnLogin`/
  `FinishWebAuthnPasswordlessLogin`/`ConsumeSetup`/`BeginWebAuthnPasswordlessLogin` all reserve
  their shared per-IP login-attempt budget (`reserveLoginAttempt`) BEFORE the slow credential
  check runs, not only afterward on failure — otherwise a concurrent burst from one IP all
  observes the same under-budget count and blows through it before the counter catches up. Why:
  security-closures `login-rate-limit-reserve-first-001`/`-002` (the second two endpoints were
  explicitly flagged "out of scope" by the first fix's own PR body and stayed exploitable until
  closed as a follow-up). Guard: `TestLogin_ConcurrentBurst_RateLimitBoundsCredentialChecks`,
  `FuzzLoginThrottleConcurrency` (deterministic controlled-interleaving harness checking
  ground-truth `login_attempts` row counts, never wall-clock timing).

## Fuzzer oracles exercising server/http directly

- `FuzzStorageFaultOperations` (`server/faultops`) drives real REST calls through this
  package's router into `internal/core`; oracles (a) atomicity, (c) fail-closed authz, (d)
  effect-then-error, (e) no secret in error body. See `internal/core/INVARIANTS.md`.
- `FuzzConcurrentOpsLinearizable` (this package, `concurrent_linearizable_fuzz_test.go`) drives
  `core.KeyorixCore` directly through this package's test harness — a revocation must be
  visible to every later read.

See `server/faultops/INVARIANTS.md` if one exists for the oracle definitions themselves.
