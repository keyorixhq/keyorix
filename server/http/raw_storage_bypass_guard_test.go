// raw_storage_bypass_guard_test.go — #1542's guard: a node-credential-gated
// proxy handler that calls h.coreService.Storage().X(...) directly, when
// internal/core ALSO has an exported KeyorixCore method that calls
// c.storage.X(...) itself, is exactly the shape that let AssignRoleWithExpiryProxy/
// AssignRoleToGroupWithExpiryProxy/AssignMachineRoleProxy/RemoveAllProjectRoleGrantsProxy
// bypass every real ceiling (requireGranterHoldsRolePermissions, requireAuthorityForRole,
// guardLastProjectAdmin) for any system.write holder, human or machine -- the
// handler wasn't taking the storage-primitive-name-matches-a-core-method-name
// coincidence as a signal that a real policy path exists for that operation.
//
// Scope: EVERY route in the /api/v1/system group (extractSystemGroupRoutes), not
// the 18-route classifiedNodeCredentialRoutes subset this guard originally shipped
// with. That narrower scope was #1547's own finding: a repo-wide re-run of this
// exact detection logic found 149 flagged call sites (an estimate later corrected
// to 145 -- see docs/g80-raw-storage-bypass-enumeration.md for the reproducible
// count and why the original 149/59 figures don't hold up), 87 of them read-shaped
// (Get*/List*/Count*/Export*, mechanically excludable -- a read confers no new
// access, so there's no ceiling to bypass) and 58 write-shaped. #1545 and #1546
// were both found BY HAND in code the 18-route scope didn't watch -- direct
// evidence the narrowing lost real coverage.
//
// An overnight session (2026-08-23/24) individually triaged all 58: full results
// in docs/g80-raw-storage-bypass-triage.md. One of the 58 (ConsumeMFAChallenge)
// turned out to be registered OUTSIDE the /system group entirely (users.write-gated,
// router.go:874) and is not tracked by this guard -- it stays documented purely in
// the triage doc. The other 57 are ALL within /system and are grandfathered below,
// split into two lists with different meanings:
//
//   - rawStorageBypassAllowlist: REVIEWED AND SAFE. No real gap -- either no
//     independent ceiling exists to bypass, or a deliberate, reasoned exception.
//     Adding an entry here is a claim the call site is fine, not a promise to fix
//     it later.
//   - knownUnfixedRawStorageBypasses: REVIEWED AND NOT SAFE. A genuine ceiling
//     bypass, confirmed real and (for all but one) human-reachable, tracked but
//     NOT yet fixed. Grandfathered so this guard can go live immediately without
//     waiting for all 10+1 to be remediated first -- exactly the
//     knownUnresolvedWireCalls / knownMissingRoutes pattern
//     (internal/storage/store/remote_wire_route_coverage_test.go): name every
//     known-bad instance explicitly so instance #58 (a NEW bypass) cannot be added
//     silently while the existing backlog is worked down, and so a listed entry
//     that gets fixed and forgotten shows up as stale instead of just staying
//     silently correct forever.
//
// TestNoUnjustifiedRawStorageBypass fails on: (a) any /system handler with a
// wrapped write-shaped storage call not in EITHER list (a brand new, unreviewed
// instance of the #1542 shape), (b) any listed entry whose handler no longer
// exists under /system, or (c) any listed entry whose handler no longer makes ANY
// flagged wrapped write-shaped call (fixed and forgotten -- remove it from
// whichever list it's in, or move it from knownUnfixedRawStorageBypasses to
// rawStorageBypassAllowlist with a reason if the fix landed here first).
package http

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// exportedCoreStorageWrappers scans every non-test *.go file in internal/core
// and returns the set of storage.Storage method names called (as
// c.storage.X(...)) from within at least one EXPORTED (c *KeyorixCore) method
// body -- i.e., a real, reachable core-level path exists for that storage
// primitive, not just an incidental reference from an unexported helper no
// handler could ever be near.
func exportedCoreStorageWrappers(t *testing.T) map[string]bool {
	t.Helper()
	wrapped := map[string]bool{}
	coreFuncRe := regexp.MustCompile(`^func \(c \*KeyorixCore\) ([A-Z][A-Za-z0-9_]*)\(`)
	storageCallRe := regexp.MustCompile(`c\.storage\.([A-Za-z0-9_]+)\(`)

	entries, err := os.ReadDir(filepath.Join("..", "..", "internal", "core"))
	if err != nil {
		t.Fatalf("reading internal/core: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		b, err := os.ReadFile(filepath.Join("..", "..", "internal", "core", name))
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		inExported := false
		depth := 0
		for _, line := range strings.Split(string(b), "\n") {
			if depth == 0 {
				if m := coreFuncRe.FindStringSubmatch(line); m != nil {
					inExported = true
				} else if strings.HasPrefix(line, "func ") {
					inExported = false
				}
			}
			depth += strings.Count(line, "{") - strings.Count(line, "}")
			if depth < 0 {
				depth = 0
			}
			if inExported {
				for _, m := range storageCallRe.FindAllStringSubmatch(line, -1) {
					wrapped[m[1]] = true
				}
			}
			if depth == 0 {
				inExported = false
			}
		}
	}
	return wrapped
}

// handlerStorageCalls returns the set of storage.Storage method names called
// as h.coreService.Storage().X(...) (or a local var equivalent — the proxy
// files in this repo always use the receiver form) from within the named
// handler method's body, searched across every non-test *.go file in
// server/http/handlers.
func handlerStorageCalls(t *testing.T, handlerName string) []string {
	t.Helper()
	funcRe := regexp.MustCompile(`^func \([a-zA-Z]+ \*[A-Za-z]+\) ` + regexp.QuoteMeta(handlerName) + `\(`)
	storageCallRe := regexp.MustCompile(`Storage\(\)\.([A-Za-z0-9_]+)\(`)

	dir := filepath.Join("..", "..", "server", "http", "handlers")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading server/http/handlers: %v", err)
	}
	var calls []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		inFunc := false
		depth := 0
		for _, line := range strings.Split(string(b), "\n") {
			if !inFunc && funcRe.MatchString(line) {
				inFunc = true
			}
			if inFunc {
				depth += strings.Count(line, "{") - strings.Count(line, "}")
				for _, m := range storageCallRe.FindAllStringSubmatch(line, -1) {
					calls = append(calls, m[1])
				}
				if depth <= 0 {
					inFunc = false
				}
			}
		}
	}
	return calls
}

// readShapedStoragePrefixes are storage-method name prefixes mechanically
// excluded as read-shaped: a read confers no new access, so there's no ceiling
// to bypass. This is a pure naming heuristic with known gaps in both directions
// -- see docs/g80-raw-storage-bypass-blind-spots.md category (d) -- accepted for
// this guard's scope rather than re-litigated here.
var readShapedStoragePrefixes = []string{"Get", "List", "Count", "Export"}

func isReadShapedStorageMethod(method string) bool {
	for _, p := range readShapedStoragePrefixes {
		if strings.HasPrefix(method, p) {
			return true
		}
	}
	return false
}

// rawStorageBypassAllowlist is the exhaustive, reasoned inventory of every
// /system handler that calls h.coreService.Storage().X(...) directly for a
// write-shaped storage method X that ALSO has an exported internal/core
// wrapper, and has been individually reviewed as SAFE -- i.e., every currently-
// accepted "the wrapper exists but this call site deliberately doesn't use it,
// and that's fine" case. Each entry needs a reason; TestNoUnjustifiedRawStorageBypass
// fails if a route not in this list (or in knownUnfixedRawStorageBypasses) is
// found calling a wrapped storage method (the #1542 shape recurring), or if a
// listed entry no longer applies (fixed and forgotten).
var rawStorageBypassAllowlist = map[string]string{
	"ClearProjectSecretOwnershipProxy": "false positive: the exported core wrapper (RemoveProjectMember) calls this " +
		"storage method only as a best-effort CLEANUP side effect of removing a member, not as its own gated " +
		"operation -- there is no independent ceiling for 'clear ownership' alone to bypass.",
	"DeleteSecretACLsByUserAndProjectProxy": "false positive: same shape as ClearProjectSecretOwnershipProxy above " +
		"-- a best-effort cleanup side effect inside RemoveProjectMember, not an independently-gated operation.",
	"DeleteExpiredRoleGrantsProxy": "false positive: the exported core wrapper (RemoveExpiredRoleGrants) has no " +
		"actor ceiling either -- an unconditional, time-bounded system sweep. Its only extra value over the raw " +
		"call is per-grant audit-event writing, an audit-completeness gap (#1529 territory), not a policy bypass.",
	// VERIFIED 2026-08-25 (G80 documented-exception re-verification sweep,
	// escalation-delta test): this is the highest-suspicion item in the whole
	// bucket -- "create a user AND grant roles atomically" is structurally the
	// closest sibling to #1552 (AssignRoleWithExpiryProxy's node branch, a bare
	// node credential granting ANY role including admin-tier with zero ceiling).
	// Gate: system.write. Ceiling requireAuthorityForRole would apply for an
	// admin-tier grant. Adversarial checks performed, not assumed: (1) node-
	// credential bypass -- grepped the whole file for isNodeCredentialRequest:
	// ZERO matches. ValidateRoleGrantAuthority (users.go:315-331) runs
	// unconditionally for EVERY caller, human or machine, with no special-case
	// branch. (2) per-grant enforcement -- ValidateRoleGrantAuthority loops over
	// EVERY grant in the request (users.go:325), not just the first, calling
	// requireAuthorityForRole per grant, then requireGrantSetNoSoDViolation over
	// the full set (users.go:330) -- byte-identical to CreateUserWithAssignments'
	// own enforcement (users.go:228,297), confirmed by direct code comparison.
	// (3) actorID==0 (a node credential's UserID) -- requireAuthorityForRole ->
	// requireAdminAuthorityAt (invitations.go:61-90) queries actual role
	// assignments for ID 0, finds none, fails closed for any admin-tier grant --
	// the OPPOSITE of #1552's shape (there the raw call skipped the ceiling
	// entirely; here the ceiling runs and correctly denies actorID 0).
	// (4) ADR-028 atomicity -- LocalStorage.CreateUserWithRoleGrants
	// (internal/storage/store/local_users.go:80-105) wraps the user insert +
	// every grant insert in ONE real gorm.DB.Transaction; remote_users.go's own
	// doc explicitly reasons about the RemoteStorage.WithTransaction-no-op trap
	// this campaign found elsewhere and explains why this design (one
	// server-side POST) avoids it -- a correct, load-bearing choice, not blind
	// reuse of an unrelated precedent. Residual, NOT specific to this handler:
	// requireAuthorityForRole only ceilings hardcoded admin role NAMES
	// (isAdminRoleName) -- a custom-named role bundling equivalent admin
	// permissions passes with no ceiling check, identically in both this proxy
	// and its human-facing sibling. Pre-existing, shared characteristic of the
	// whole requireAuthorityForRole design, not a gap this handler introduces.
	"CreateUserWithRoleGrantsProxy": "holds: ValidateRoleGrantAuthority (users.go:315-331) runs unconditionally " +
		"for every caller (grepped -- zero isNodeCredentialRequest branches in this file), per-grant, and fails " +
		"closed for actorID 0 via requireAdminAuthorityAt (invitations.go:61-90) -- the opposite of #1552's " +
		"shape. ADR-028 atomicity is real (local_users.go:80-105, one gorm.DB.Transaction), not a WithTransaction-" +
		"no-op trap.",
	// CORRECTED 2026-08-25 (G80 documented-exception re-verification sweep): the
	// prior reason here ("same reasoning as RemoveGlobalAdminRoleGuardedProxy --
	// no real transaction spans the HTTP hop") was FALSE, not just imprecise --
	// it borrowed an atomicity argument that doesn't apply to this call at all.
	// This handler backs core.DeleteProject's force=TRUE path (see its own doc
	// comment, project_catalog_proxy.go), which internal/core/catalog.go:186-191
	// documents as intentionally skipping the guard+cascade atomicity problem
	// entirely -- force=true has never had a guard to make atomic; it's a plain
	// unconditional cascade with zero actor-authority check in core.DeleteProject
	// either. The real, verified reason this route is safe: no-independent-
	// ceiling -- there is nothing for the raw call to bypass, because
	// core.DeleteProject(force=true) doesn't check anything beyond what
	// already-runs storage.DeleteProject does. (RemoveGlobalAdminRoleGuardedProxy's
	// atomicity story is real for THAT handler -- storage.RemoveGlobalAdminRoleGuarded
	// genuinely folds a check-then-delete into one atomic call -- it just never
	// applied here.)
	"DeleteProjectProxy": "no-independent-ceiling: core.DeleteProject(force=true) (internal/core/catalog.go:186-191) " +
		"intentionally skips the force=false guard+cascade atomicity problem entirely and calls the plain, " +
		"unconditional storage.DeleteProject cascade -- no actor-authority check of any kind exists at the core " +
		"layer for this path, so there's nothing for the raw call to bypass.",
	// VERIFIED 2026-08-25 (G80 documented-exception re-verification sweep,
	// escalation-delta test): gate is system.write; ceiling is "zero secrets"
	// before deleting a non-forced project, which core.DeleteProject(force=false)
	// would otherwise check via a WithTransaction-wrapped guard-then-cascade
	// pair -- broken under storage.type: remote (RemoteStorage.WithTransaction
	// is a no-op) per #528's own commit message (b6e46050, 2026-07-07, "Closes
	// #528": "the guard-count and the cascade... would have reopened a TOCTOU
	// window" as a plain two-call pair). Adversarial check: is
	// DeleteProjectIfEmpty ACTUALLY atomic, or just named "atomic"? Confirmed at
	// internal/storage/store/local_secrets.go:272-290 -- the secret-count check
	// and deleteProjectCascade both run inside ONE .Transaction() call, no
	// separate earlier read. core.DeleteProject's force=false branch
	// (catalog.go:192-199) does nothing beyond calling this primitive and
	// checking the returned blocking count -- no additional ceiling is skipped
	// by the raw call.
	"DeleteProjectIfEmptyProxy": "holds: internal/storage/store/local_secrets.go:272-290 runs the secret-count " +
		"guard and the cascade delete inside ONE .Transaction() call, no TOCTOU window across the HTTP hop -- " +
		"purpose-built for exactly this (#528, commit b6e46050) after the WithTransaction-wrapped two-call " +
		"version proved unsafe under storage.type: remote; core.DeleteProject(force=false) adds nothing beyond " +
		"calling this same primitive.",
	// The following 9 were classified no-independent-ceiling in the 2026-08-23/24
	// overnight triage (docs/g80-raw-storage-bypass-triage.md has full evidence per
	// entry; reasons here are condensed, not abbreviated to the point of losing the
	// falsifiable claim).
	"MarkTOTPStepUsedProxy": "no-independent-ceiling: the core callers (ActivateMFA/VerifyMFACredentials/" +
		"verifyMFAStepUpCode) invoke this only AFTER cryptographic TOTP validation already passed -- it's a pure " +
		"post-validation anti-replay CAS, not an authorization gate, applied identically by every caller.",
	"DeleteEnvironmentProxy": "no-independent-ceiling: core.DeleteEnvironment is a literal 1-line passthrough to " +
		"storage with no check of its own.",
	"TouchMachineIdentityCredentialProxy": "no-independent-ceiling: TouchMachineTokenLastUsed does no authz/" +
		"ownership check even in core -- explicitly best-effort, a target-state-invariant liveness timestamp " +
		"identical regardless of caller.",
	"DeleteExpiredShareRecordsProxy": "no-independent-ceiling: RemoveExpiredShares is an unconditional time-bound " +
		"sweep, same shape as DeleteExpiredRoleGrantsProxy above; its only extra value is a per-row audit event " +
		"(completeness gap, not a policy bypass).",
	"TransitionSecretStatusProxy": "no-independent-ceiling, CONFIRMED BY READING THE CODE (not just the doc's " +
		"framing): SuspendSecret/ResumeSecret enforce only a CAS race guard + audit; permission itself is " +
		"explicitly NOT a core-layer check by design (the transport must enforce scoped secrets.write). The " +
		"handler faithfully reproduces the same CAS (re-fetch, apply only Status/UpdatedAt, call with fromStatus) " +
		"-- this is the correct-pattern precedent docs/g80-remediation-notes.md's follow-up section points to.",
	"SupersedeSetupTokensProxy": "no-independent-ceiling: the IssueSetupToken step this backs " +
		"(SupersedeActiveSetupTokens) has no caller-authorization gate of its own -- an unconditional exact-match " +
		"(purpose, email[, project]) bulk state-flip.",
	// VERIFIED 2026-08-25 (G80 documented-exception re-verification sweep, escalation-
	// delta test): gate is system.write (this route group's baseline); the ceiling
	// OpenAccessReviewCampaign would otherwise apply is "lifecycle fields must start
	// fresh" -- not an authority check at all, so there is no delta to test. Adversarial
	// check performed: does the handler actually FORCE those fields, or just claim to?
	// access_review_campaigns_proxy.go:230-235 unconditionally overwrites State/
	// ClosedBy/ClosedAt/ForcedIncomplete on the decoded body before persisting,
	// regardless of what the caller sent -- confirmed by reading the code, not the
	// comment. That hardening landed in commit 778a027e (2026-07-27, PR #1175, r128,
	// "fabricated campaigns, pre-decided items, self-certification"), with regression
	// tests TestCreateAccessReviewCampaignProxy_IgnoresClosedState_R128/
	// ..._IgnoresForcedIncomplete_R128 (access_review_campaigns_proxy_r128_test.go) --
	// this is a tested property, not an assertion. Residual, non-blocking gap: the
	// `CreatedBy` field is NOT stripped (toModel(), line 113) -- a caller can attribute
	// a campaign to an arbitrary user ID. The real audit event (AuditCampaignCreated,
	// line 244-245) correctly uses the authenticated caller's own actorID(r), so the
	// audit trail itself isn't spoofable; only the campaign row's cosmetic `created_by`
	// display field is. No authorization decision reads CreatedBy back -- not a
	// privilege escalation, worth a low-priority follow-up ticket if that field is
	// ever trusted for anything beyond display.
	"CreateAccessReviewCampaignProxy": "holds: OpenAccessReviewCampaign is explicitly NOT gated on a human actor " +
		"(ARC-003) -- the only caller-relevant invariant is that lifecycle fields (State/ClosedBy/ClosedAt/" +
		"ForcedIncomplete) start fresh, and access_review_campaigns_proxy.go:230-235 unconditionally forces all " +
		"four before persisting (tested: TestCreateAccessReviewCampaignProxy_IgnoresClosedState_R128). Residual, " +
		"non-blocking: CreatedBy is not stripped (cosmetic attribution only, no authz decision reads it back).",
	// VERIFIED 2026-08-25 (G80 documented-exception re-verification sweep, escalation-
	// delta test): same gate (system.write), same "no independent authority check to
	// bypass" shape as the campaign-create row above -- OpenAccessReviewCampaign's
	// item-generation step has no actor-dependent decision, only a fresh-item-state
	// invariant (ARC-004). Adversarial check: access_review_campaigns_proxy.go:358-360
	// unconditionally overwrites Decision/DecidedBy/DecidedAt on every item before
	// persisting (tested: TestCreateAccessReviewItemsProxy_StripsDecisionFields_R128,
	// same 778a027e/#1175/r128 commit as the campaign-create fix -- this file's prior
	// version, 793f702fc, had NO stripping at all, so this is a real, verified fix, not
	// a stale assertion). All OTHER item fields (PrincipalType/PrincipalID/RoleID/
	// AccessLevel/EnvironmentID/SecretID) remain fully caller-controlled, matching the
	// package doc's own explicit disclosure that no campaign-lifecycle POLICY decision
	// is made here -- fabricated item content can't itself grant/revoke access (that
	// logic lives entirely downstream, out of reach of this route), so this doesn't
	// widen what system.write already permits in this group.
	"CreateAccessReviewItemsProxy": "holds: the only caller-relevant invariant (a fresh item starts " +
		"Decision=pending/DecidedBy=0/DecidedAt=nil) is unconditionally forced server-side " +
		"(access_review_campaigns_proxy.go:358-360, tested: TestCreateAccessReviewItemsProxy_StripsDecisionFields_R128) " +
		"-- other item fields are caller-controlled by design (package doc), but fabricated content can't itself " +
		"grant/revoke access, so this introduces no new privilege beyond the route's own system.write gate.",
	// CORRECTED 2026-08-25 (G80 documented-exception re-verification sweep): the
	// prior "documented-exception" reason here was FALSE. The claimed "separate
	// proxied call chain" (core.RevokeBreakGlass's RemoveUserRole step) does not
	// exist end-to-end: for a project-scoped role it resolves to POST
	// /api/v1/rbac/remove-role, a route that was never registered
	// (remote_wire_route_coverage_test.go's knownMissingRoutes, #1511) --
	// confirmed checked in BEFORE this classification was originally written.
	// Under storage.type: remote, this raw proxy was the ONLY path that could
	// ever complete a revoke with a live grant, and it left the role grant LIVE
	// in user_roles with no audit event. FIXED: the handler is now
	// self-contained (state guard, RemoveUserRole, conditional revoke, new
	// LogBreakGlassRevoked audit call) -- see its own doc comment
	// (break_glass_proxy.go) for the full reasoning, including why it does NOT
	// call core.RevokeBreakGlass directly (would break this route's own wire
	// error-code contract).
	"RevokeBreakGlassActivationProxy": "FIXED: was a false documented-exception (the offsetting role-removal " +
		"chain it claimed to travel through never existed end-to-end, #1511) -- now self-contained (state guard " +
		"+ RemoveUserRole + conditional revoke + LogBreakGlassRevoked audit), see the FIXED comment immediately " +
		"above this entry.",
	// RecordLoginAttemptProxy: FIXED 2026-08-25 (G80 documented-exception
	// re-verification sweep) -- was a FALSE documented-exception (ip/at were
	// completely unvalidated, enabling cross-namespace rate-limit poisoning and
	// a permanent future-timestamp lockout; see internal/core/rate_limit.go's
	// RecordLoginAttemptRelay doc comment for the full finding). Entry removed
	// (not moved) -- the handler now routes through core.RecordLoginAttemptRelay
	// instead of calling Storage().RecordLoginAttempt directly, so this guard's
	// AST scan no longer flags it at all.
	// VERIFIED 2026-08-25 (G80 documented-exception re-verification sweep,
	// escalation-delta test): gate is system.write; there is no actor-authority
	// ceiling for BeginSSO/BeginSAML to bypass (pre-login CSRF-state creation is
	// not gated on identity in the local path either), so the real question is
	// injection, not authority. Adversarial check performed: models.SSOLoginState
	// (internal/storage/models/models.go:174-182) carries State (random CSRF
	// token)/Nonce/Provider/ReturnTo/ExpiresAt/CreatedAt -- NO user/session-
	// identity field of any kind. Identity is bound only at CONSUME time via
	// IdP-signed crypto: verifyIDToken (sso.go:839-867, issuer-pinned JWKS,
	// RS256/ES256/PS256) for OIDC, a vetted SAML-assertion-signature library for
	// SAML. So even a caller who fully controls this create call's fields cannot
	// forge a login for another user -- they would still need a genuine,
	// IdP-signed assertion. No injection path found; file unmodified since
	// introduction (efd0abdc, 2026-07-07).
	"CreateSSOLoginStateProxy": "holds: SSOLoginState carries no identity-binding field " +
		"(internal/storage/models/models.go:174-182) -- identity is anchored entirely by IdP-signed crypto at " +
		"consume time (sso.go:839-867 for OIDC id_token/JWKS, SAML assertion-signature verification for SAML), " +
		"so a caller controlling this create call's fields still cannot forge a login for another user.",
	// VERIFIED 2026-08-25 (G80 documented-exception re-verification sweep,
	// escalation-delta test): same gate; adversarial check on the "atomic
	// read-then-conditional-delete" claim, which is the load-bearing property
	// here (a non-atomic version would reopen a double-consume race). Confirmed
	// at internal/storage/store/local_sso.go:44-54: a genuine conditional
	// `DELETE ... WHERE id = ? AND state = ?` + RowsAffected check, i.e. a real
	// CAS, not a plain delete-by-ID -- and the proxy calls this SAME function
	// rather than reimplementing read+delete over HTTP, so the guarantee is
	// inherited unchanged. Provider/expiry re-validation confirmed to run
	// downstream on EVERY path, independent of caller: validateSSOLoginState
	// (sso.go:172-177) and CompleteSAML (sso.go:316-321) each re-check
	// Provider/ExpiresAt on the row consume returns.
	"ConsumeSSOLoginStateProxy": "holds: internal/storage/store/local_sso.go:44-54 is a genuine conditional " +
		"DELETE+RowsAffected CAS (not a plain delete-by-ID) -- the proxy calls this same function rather than " +
		"reimplementing read+delete, so the single-use guarantee is inherited unchanged; provider/expiry checks " +
		"re-run downstream on every path (sso.go:172-177, sso.go:316-321), independent of caller.",
	// VERIFIED 2026-08-25 (G80 documented-exception re-verification sweep,
	// escalation-delta test): same gate; this file ALSO contains three sibling
	// handlers (CreateWebAuthnCredentialProxy/DeleteWebAuthnCredentialProxy/
	// SetUserWebAuthnEnabledProxy) already confirmed REAL, SEVERE bugs in this
	// same campaign -- extra scrutiny applied here for that reason. Adversarial
	// checks: (1) atomicity -- internal/storage/store/local_webauthn.go:160-176
	// is a genuine transactional conditional UPDATE (WHERE used_at IS NULL AND
	// expires_at > ?) + RowsAffected check, re-read inside the SAME transaction;
	// the proxy makes exactly one call to this primitive, no TOCTOU reopened.
	// (2) injection -- the consume call's only body field is `token_hash` (a
	// lookup key, not data); the session's UserID/Data (WebAuthn challenge) were
	// populated earlier by CreateWebAuthnSession, itself only ever called by
	// this server's own storeWebAuthnSession during Begin*, not by this consume
	// call. (3) crypto ordering -- FinishWebAuthnLogin additionally cross-checks
	// sess.UserID != ch.UserID (webauthn.go:321, an independently-established
	// MFA-challenge identity) BEFORE any signature check, and ValidateLogin/
	// CreateCredential/ValidatePasskeyLogin all verify against credentials
	// freshly reloaded from storage for the real user -- an attacker without
	// the victim's authenticator private key cannot produce a valid signature
	// regardless of what the session Data contains. Caveat carried forward: the
	// comment's own cited "#510 precedent" (ConsumeSetupTokenProxy) is NOT
	// actually present in either guard-test map -- it evaded detection because
	// its raw storage call is inside an UNEXPORTED core helper
	// (consumeInspectedToken, internal/core/setup_token.go:210-214), which this
	// guard's AST scan only inspects EXPORTED KeyorixCore method bodies for
	// (exportedCoreStorageWrappers, this file). Verified independently here on
	// ConsumeWebAuthnSessionProxy's own code, not by trusting that citation.
	"ConsumeWebAuthnSessionProxy": "holds: local_webauthn.go:160-176 is a genuine transactional conditional " +
		"UPDATE+RowsAffected CAS, re-read in the same transaction -- no TOCTOU reopened across the HTTP hop; the " +
		"consume call's only caller-controlled field (token_hash) is a lookup key, not injectable session data, " +
		"and FinishWebAuthnLogin cross-checks sess.UserID != ch.UserID (webauthn.go:321) before any crypto check.",
	// FIXED 2026-08-24 (G80 overnight campaign, Tier 1 Group A #1, was in
	// knownUnfixedRawStorageBypasses): the raw conditional write is still here
	// deliberately (preserves the atomic CAS across the HTTP hop, same reasoning as
	// TransitionSecretStatusProxy's precedent), but it's now preceded by
	// core.IsValidMachineTransition(fromState, m.State) -- the same transition-table
	// legality check (machine_identities.go:64-71, revoked is terminal) that
	// core.TransitionMachineIdentity's transaction body enforces, exported
	// specifically for this call site. That check needs only the (from, to) pair,
	// both already on the wire, so this closes the gap with no RemoteStorage
	// wire-protocol change and no risk to existing downstream callers (verified in
	// the overnight session's RemoteStorage impact check before this landed). The
	// cross-project guard and cache eviction TransitionMachineIdentity also applies
	// are NOT re-derived here: the cross-project guard is a caller-side check (does
	// the acting session's own project scope match this machine) that already ran on
	// whichever server's core.TransitionMachineIdentity initiated the relayed call --
	// the wire carries no caller-asserted project scope for the hub to re-check
	// against. Cache eviction is a best-effort, single-process mechanism even in the
	// correct path (each server only evicts its own in-memory auth cache); adding it
	// here would only help hub-originated requests and wasn't the security-relevant
	// gap this fix closes -- left as a known, pre-existing, unrelated limitation.
	"TransitionMachineIdentityStateProxy": "FIXED: preceded by core.IsValidMachineTransition -- see the FIXED " +
		"comment immediately above this entry for the full reasoning (kept as a map comment, not a value, since " +
		"Go doesn't support per-key doc comments on map literals).",
	// FIXED 2026-08-24 (G80 overnight campaign, Tier 1 Group A #2, was in
	// knownUnfixedRawStorageBypasses): the raw call is still here, but it no longer
	// accepts a full caller-supplied replacement row. The handler now fetches the
	// EXISTING credential and applies only Classification from the wire body,
	// matching core.ClassifyMachineToken's actual behavior exactly (confirmed the
	// ONLY exported core caller of this storage primitive by grep before this fix
	// landed -- it never touches TokenHash/Revoked/ExpiresAt). No RemoteStorage
	// wire-protocol change was needed: the only real caller only ever sends a
	// classification change, so narrowing what the hub acts on breaks nothing
	// (verified in the overnight session's RemoteStorage impact check). The route
	// carries no caller-asserted project/machine scope to re-derive
	// ClassifyMachineToken's own machineInProject check against -- same reasoning as
	// TransitionMachineIdentityStateProxy's cross-project guard above; that check is
	// a caller-side concern already satisfied before the relayed call reached here.
	"UpdateMachineIdentityCredentialProxy": "FIXED: narrowed to fetch-existing + apply-Classification-only -- see " +
		"the FIXED comment immediately above this entry for the full reasoning.",
	// FIXED 2026-08-24 (G80 Phase 2, #1529 re-triage): CreateInvitationProxy now
	// re-derives InviteToProject's/InviteGlobal's own requireAuthorityForRole
	// escalation-by-proxy ceiling for every role the wire body can carry (the
	// project-scoped Role, the global SystemRole, and each project assignment
	// bundled into AssignmentsJSON) -- newly exported core.RequireAuthorityForRole,
	// since the /system proxy layer can't call unexported KeyorixCore methods
	// across the package boundary. UpdateInvitationProxy now re-fetches the
	// existing row and applies only State/AcceptedAt/RevokedAt from the wire
	// (the AR-001 field-narrowing pattern, mirroring UpdateAccessRequestProxy):
	// every real caller of storage.UpdateProjectInvitation
	// (completeInvitationAccept/RevokeInvitation/expireInvitationIfOverdue) only
	// ever mutates those three fields on the row it already fetched, never
	// Email/Role/SystemRole/InvitedBy/ProjectID, which are set once at creation.
	"CreateInvitationProxy": "FIXED: re-derives requireAuthorityForRole for Role/SystemRole/each AssignmentsJSON " +
		"entry -- see the FIXED comment immediately above this entry for the full reasoning.",
	"UpdateInvitationProxy": "FIXED: re-fetches the existing row and applies only State/AcceptedAt/RevokedAt from " +
		"the wire -- see the FIXED comment immediately above this entry for the full reasoning.",
	// FIXED 2026-08-24 (G80 Phase 2, #1529 re-triage): CreateAccessRequestProxy no
	// longer accepts a caller-supplied non-pending State -- every legitimate
	// creation path (RequestProjectAccess/RequestSecretAccess) always creates
	// with State=pending, so rejecting anything else needed no RemoteStorage
	// wire-protocol change (the only real caller never sent anything else in the
	// first place). UpdateAccessRequestProxy now re-derives, at the hub, the SAME
	// ceiling the matching core method already applies before ever reaching this
	// storage primitive locally: maker≠checker plus admin authority
	// (core.RequireAdminAuthorityAt, secret-scoped, mirroring
	// ApproveSecretAccessRequest) or role-grant authority
	// (core.RequireAuthorityForRole, project/role-scoped, mirroring
	// ApproveAccessRequestWithExpiry's own ceiling call) -- both newly exported
	// from internal/core since the /system proxy layer can't call unexported
	// KeyorixCore methods across the package boundary. Only the "approved"
	// transition is gated: core.RejectAccessRequest has no actor-authority check
	// of its own (any project member may reject), and core.WithdrawAccessRequest's
	// self-only check has no wire-carried actor field distinct from ResolvedBy to
	// re-derive against here -- left as-is, not silently narrowed.
	"CreateAccessRequestProxy": "FIXED: State is forced to \"pending\" at creation -- see the FIXED comment " +
		"immediately above this entry for the full reasoning.",
	"UpdateAccessRequestProxy": "FIXED: re-derives maker≠checker + admin/role-grant authority on the \"approved\" " +
		"transition -- see the FIXED comment immediately above this entry for the full reasoning.",
}

// knownUnfixedRawStorageBypasses is the set of /system handlers confirmed, by
// individual review (docs/g80-raw-storage-bypass-triage.md), to bypass a REAL
// ceiling -- i.e. the #1542 shape, not yet fixed. Grandfathered so this guard can
// be blocking from today without requiring all of these to be fixed first. This
// is NOT a claim of safety -- the opposite: every entry here is a known, tracked
// gap. TestNoUnjustifiedRawStorageBypass still fails if an entry stops
// reproducing (fixed -- move it to rawStorageBypassAllowlist with a reason, or
// delete the entry) or if its handler is removed from /system entirely.
//
// 10 of these 11 were independently re-verified against an escalation-delta test
// (does an actor holding ONLY the route's gating permission gain a capability the
// gate did not already authorize, traced to a real human auth path) on a 5-item
// sample the same night this list was built; all 5 held up. The reach column
// noted per entry is human-reachable for all but TransitionMembershipProxy
// (reach genuinely unresolved, tracked separately as #1546). (The other 23
// originally-listed entries were deleted outright — G80 liveness sweep found no
// live caller for any of them; see docs/g80-remediation-notes.md.)
var knownUnfixedRawStorageBypasses = map[string]string{
	// MOVED HERE 2026-08-25 (G80 documented-exception re-verification sweep):
	// was classified documented-exception in rawStorageBypassAllowlist on the
	// theory that the handler's own #G79 comment "re-derives and closes the gap"
	// (an internal invitation/user cross-reference check before persisting).
	// That check is real and correctly written for what it explicitly
	// validates (existence + case-insensitive email match) -- but it enforces
	// internal CONSISTENCY between the caller-supplied token_hash/subject_email/
	// subject_user_id/invitation_id, not caller AUTHORIZATION to target a
	// specific account. Because this handler lets the caller choose token_hash
	// directly (the plaintext the caller itself generates and hashes, per its
	// own #G79 comment -- "by design, always caller-supplied"), a caller
	// holding only system.write who already knows (or guesses) a real target's
	// email/user-ID can mint a fully-valid, immediately-redeemable takeover
	// token for that target via the public POST /auth/setup/consume --
	// overwriting the target's real password (and, for a non-MFA account,
	// receiving a live session AS them). Escalation-delta confirmed: no other
	// system.write-gated route in this proxy group lets a caller overwrite an
	// EXISTING arbitrary user's password + mint a session under that identity.
	// The invitation_accept branch (setup_tokens_proxy.go's GetProjectInvitation
	// + email-match check) additionally has ZERO test coverage. NOT fixed here
	// -- reported per explicit instruction, fix approach pending a decision
	// (narrow this route to the node-credential arm only vs. a core-level
	// re-check) since the package doc's own stated legitimate caller is a
	// genuine RemoteStorage node, never a human/service system.write role.
	"CreateSetupTokenProxy": "REAL, human-reachable: the #G79 cross-reference check enforces internal " +
		"consistency of caller-supplied fields, not caller authorization to target the account those fields " +
		"name -- a system.write holder who already knows a target's email/ID can mint and immediately redeem a " +
		"takeover token for that target via the public /auth/setup/consume endpoint.",
	// HALF-FIXED 2026-08-25 (G80 documented-exception re-verification sweep) --
	// do NOT move to rawStorageBypassAllowlist: CLOSED for a direct,
	// non-node-credential caller (now routed through core.RemoveUserRole after
	// an explicit AuthorizePrincipal(roles.assign, global scope) check --
	// mirroring the human-facing DELETE /api/v1/user-roles gate -- which also
	// fixes the missing audit event, since RemoveUserRole calls LogRoleRemoved +
	// evictUserSessionCache. STILL OPEN for a node-credential caller:
	// isNodeCredentialRequest(r) routes around the check entirely to the raw
	// storage.RemoveGlobalAdminRoleGuarded call, on the same unverified
	// relay-trust assumption AssignRoleWithExpiryProxy's node branch made before
	// #1552 (ADR-085's still-unresolved "harder question" -- the wire carries no
	// field attesting which human/decision a relayed action actually traces to).
	// A bare node credential -- zero RBAC permissions by design (ADR-030) --
	// can still strip any admin's global-admin role (down to the last one) by
	// calling this route directly, with nothing distinguishing that from a
	// genuine relay. See system_write_ceiling_table_test.go's
	// RemoveGlobalAdminRoleGuardedProxy rows for the live, asserted evidence
	// (both the fixed direct-caller path and the still-open node-credential
	// path).
	"RemoveGlobalAdminRoleGuardedProxy": "HALF-FIXED: closed for a direct system.write-only human/machine caller " +
		"(core.RemoveUserRole + an explicit roles.assign-at-global-scope check now enforced, which also adds the " +
		"previously-missing audit event); STILL OPEN for a node-credential caller (isNodeCredentialRequest routes " +
		"around the check to the raw storage call -- see the HALF-FIXED comment immediately above this entry).",
	"TransitionMembershipProxy": "UNRESOLVED, not confirmed real or safe -- filed as #1546. The exported wrapper " +
		"(TransitionMembership) gates activation with requireAuthorityForRole and grants/revokes the underlying " +
		"role grant as a side effect neither of which this raw call performs; whether that's covered by a " +
		"separate relayed call from the downstream's own core.TransitionMembership, or a real gap, is undetermined.",
	// UpdateLoginLockoutStateProxy's route was deleted (G80 23-handler no-caller
	// deletion) -- entry removed, no longer applicable.
	// CreateMachineIdentityProxy is FIXED (moved to rawStorageBypassAllowlist);
	// CreateMachineIdentityCredentialProxy is HALF-FIXED (see its entry below) --
	// neither belongs here with its original pre-fix text.
	"RevokeMachineIdentityCredentialProxy": "REAL, human-reachable, narrower: revokes by bare credential ID with " +
		"no project-membership check, skips audit + cache-eviction hand-off. Mirrors this file's own " +
		"already-fixed RemoveMachineRoleProxy pattern; impact is cross-tenant DoS/tampering, not escalation. " +
		"Deferred (not a wire-compatible fix like its siblings): the wire contract carries no project/scope " +
		"parameter at all, so closing it needs a RemoteStorage client-side change first -- filed as #1551.",
	// HALF-FIXED 2026-08-24 -- do NOT move to rawStorageBypassAllowlist: CLOSED for
	// a direct, non-node-credential caller (routes through core.DeleteOIDCBinding,
	// which resolves the binding's real owning machine/project and runs the
	// machineInProject + binding-ownership checks, plus writes the
	// machine_identity.oidc_unbound audit event -- see
	// TestDeleteOIDCBindingProxy_WritesAuditEvent_S21). STILL OPEN for a
	// node-credential caller: isNodeCredentialRequest(r) routes around all of that
	// to the raw storage.DeleteOIDCBinding call, the same unverified relay-trust
	// assumption CreateOIDCBindingProxy/CreateMachineIdentityCredentialProxy above
	// make. A bare node credential can still delete any binding ID with no
	// ownership/project-scope check and no audit event.
	"DeleteOIDCBindingProxy": "HALF-FIXED: closed for a direct system.write-only human/machine caller " +
		"(routes through core.DeleteOIDCBinding's machineInProject + binding-ownership checks and its audit " +
		"event); STILL OPEN for a node-credential caller (isNodeCredentialRequest routes around the check to " +
		"the raw storage call -- see the HALF-FIXED comment immediately above this entry).",
	// HALF-FIXED 2026-08-24 -- do NOT move to rawStorageBypassAllowlist: CLOSED
	// for a direct, non-node-credential caller (routes through
	// core.RequireMachinePrivilegeCeiling, MACH-001, now denying a system.write-only
	// caller minting a credential for an admin-tier machine identity -- see
	// system_write_ceiling_table_test.go's EnforcesPrivilegeCeiling row). STILL OPEN
	// for a node-credential caller: isNodeCredentialRequest(r) routes around the
	// check entirely to the raw storage.CreateMachineIdentityCredential call, on the
	// theory that a genuine relay already ran this check downstream -- an assertion
	// with no wire-level verification (ADR-085's unresolved "harder question": the
	// wire carries no field attesting which human/decision a relayed action actually
	// traces to). A bare node credential -- the single most widely distributed
	// credential class in a deployment (ADR-085) -- can still forge a credential for
	// an admin-tier machine identity by calling this route directly, with nothing
	// distinguishing that from a genuine relay. Tracked under #1552 (the same
	// AssignRoleWithExpiryProxy-precedent pattern, filed Tier 1, ranked above this
	// finding). See system_write_ceiling_table_test.go's node-credential-path rows
	// for the live, asserted-red-in-spirit (documented current-behavior) evidence.
	"CreateMachineIdentityCredentialProxy": "HALF-FIXED: closed for a direct system.write-only human/machine " +
		"caller (core.RequireMachinePrivilegeCeiling now enforced); STILL OPEN for a node-credential caller " +
		"(isNodeCredentialRequest routes around the check to the raw storage call, on an unverified relay-trust " +
		"assumption -- see the HALF-FIXED comment immediately above this entry).",
	// HALF-FIXED 2026-08-24 -- do NOT move to rawStorageBypassAllowlist: CLOSED for
	// a direct, non-node-credential caller (routes through core.CreateOIDCBinding's
	// requireAuthorityForRole(..., "system_admin") install-wide admin-authority
	// check -- see system_write_ceiling_table_test.go's
	// RequiresInstallWideAdminAuthority row). STILL OPEN for a node-credential
	// caller: isNodeCredentialRequest(r) routes around the check entirely to the raw
	// storage.CreateOIDCBinding call, same unverified relay-trust assumption as
	// CreateMachineIdentityCredentialProxy above (and the same assumption
	// AssignRoleWithExpiryProxy's node branch makes, rbac_role_grants_proxy.go --
	// filed as #1552, Tier 1, ranked above CreateMachineIdentityCredentialProxy: a
	// shorter path to global admin, attacker-chosen target account). A bare node
	// credential can still pre-claim any (issuer, subject) OIDC binding for a
	// machine of its choosing by calling this route directly.
	"CreateOIDCBindingProxy": "HALF-FIXED: closed for a direct system.write-only human/machine caller " +
		"(core.CreateOIDCBinding's install-wide admin-authority check now enforced); STILL OPEN for a " +
		"node-credential caller (isNodeCredentialRequest routes around the check to the raw storage call -- see " +
		"the HALF-FIXED comment immediately above this entry).",
	// UpsertMFASecretProxy, CreateMFAStepUpGrantProxy, UpdateProjectProxy,
	// RestoreProjectProxy, DeleteAnomalyAlertsBeforeProxy,
	// DeleteClosedAccessReviewsBeforeProxy, DeleteExpiredBreakGlassBeforeProxy,
	// DeleteResolvedAccessRequestsBeforeProxy, DeleteSecretDependencyProxy: all
	// deleted (G80 23-handler no-caller deletion) -- entries removed, no longer
	// applicable.
	"UpdateUserIfActiveStateMatchesProxy": "PARTIALLY FIXED 2026-08-24 (G80 overnight campaign, Tier 1 Group A " +
		"#3): the last-admin-lockout half is fixed -- core.GuardLastAdminDeactivation now runs before any " +
		"deactivating transition (FromActive:true, Active:false), a target-state check needing only the target " +
		"user ID, no RemoteStorage wire-protocol change required. The PAT/session revocation half (RemoteStorage." +
		"RevokeAllPersonalAccessTokensForUser/DeleteSessionsForUserExcept were both hard-stubbed to " +
		"errUnsupportedRemote, so the 'correct' full deactivation flow failed outright over RemoteStorage) is now " +
		"fixed 2026-08-25 via two new proxy routes -- see the RevokeAllPersonalAccessTokensForUserProxy/ " +
		"DeleteSessionsForUserExceptProxy entries below (this handler itself still makes no PAT/session call; the " +
		"fix lives in the two new routes core.UpdateUser's deactivating branch now succeeds against, and in the " +
		"RemoteStorage client methods themselves).",
	// HALF-FIXED 2026-08-25 -- do NOT move to rawStorageBypassAllowlist: CLOSED for
	// a direct, non-node-credential caller (routes through
	// core.RevokeAllPersonalAccessTokensForUser/core.DeleteSessionsForUserExcept,
	// which require "users.write" authority at global scope -- derived, not
	// chosen, from the ONLY caller-authority check that actually governs a user
	// deactivation today (RequirePermission(permUsersWrite) on PUT
	// /api/v1/users/{id}, router.go) since core.UpdateUser/core.DeleteUser
	// perform no authority check of their own; see
	// internal/core/users.go's requireUserCredentialsRevokeAuthority doc for the
	// full derivation, and system_write_ceiling_table_test.go's
	// RequiresUsersWriteAuthority rows). STILL OPEN for a node-credential
	// caller: isNodeCredentialRequest(r) routes around the check entirely to the
	// raw storage call, the same unverified relay-trust assumption
	// CreateOIDCBindingProxy/CreateMachineIdentityCredentialProxy above make. A
	// bare node credential can still revoke any user's PATs/sessions with no
	// authority check and no audit event.
	"RevokeAllPersonalAccessTokensForUserProxy": "HALF-FIXED: closed for a direct human/machine caller " +
		"(core.RevokeAllPersonalAccessTokensForUser's users.write-authority check now enforced, plus an audit " +
		"event); STILL OPEN for a node-credential caller (isNodeCredentialRequest routes around the check to the " +
		"raw storage call -- see the HALF-FIXED comment immediately above this entry).",
	"DeleteSessionsForUserExceptProxy": "HALF-FIXED: closed for a direct human/machine caller " +
		"(core.DeleteSessionsForUserExcept's users.write-authority check now enforced, plus an audit event); " +
		"STILL OPEN for a node-credential caller (isNodeCredentialRequest routes around the check to the raw " +
		"storage call -- see the CreateOIDCBindingProxy HALF-FIXED comment above for the shared reasoning).",
}

// TestNoUnjustifiedRawStorageBypass is #1542's guard, extended by #1547 to cover
// every route in the /api/v1/system group (not just the 18-route subset this
// guard originally shipped with): for every such route, if its handler calls
// h.coreService.Storage().X(...) for a write-shaped storage method X that an
// EXPORTED internal/core method also wraps, that handler must have an entry in
// rawStorageBypassAllowlist (reviewed safe) or knownUnfixedRawStorageBypasses
// (reviewed real, tracked, not yet fixed) explaining why. A newly-added route (or
// a regression in an already-fixed one) that reintroduces this shape fails
// immediately, instead of waiting for the next manual audit round to notice --
// and neither list can silently drift from reality: a stale entry (handler gone,
// or the flagged call site no longer reproduces) fails too.
func TestNoUnjustifiedRawStorageBypass(t *testing.T) {
	wrapped := exportedCoreStorageWrappers(t)
	routerPath := filepath.Join(".", "router.go")
	actual := extractSystemGroupRoutes(t, routerPath)

	// handlerFlagged[handler] = true iff that handler currently makes at least one
	// call to a write-shaped storage method an exported core method also wraps.
	handlerFlagged := map[string]bool{}
	seenHandlers := map[string]bool{}
	var flagged []string
	for _, r := range actual {
		if r.Handler == "" || seenHandlers[r.Handler] {
			continue
		}
		seenHandlers[r.Handler] = true
		for _, storageMethod := range handlerStorageCalls(t, r.Handler) {
			if !wrapped[storageMethod] || isReadShapedStorageMethod(storageMethod) {
				continue
			}
			handlerFlagged[r.Handler] = true
			_, safe := rawStorageBypassAllowlist[r.Handler]
			_, unfixed := knownUnfixedRawStorageBypasses[r.Handler]
			if !safe && !unfixed {
				flagged = append(flagged, r.Handler+" calls Storage()."+storageMethod+"(...) directly, but "+
					"internal/core has an exported method that also wraps "+storageMethod)
			}
		}
	}
	sort.Strings(flagged)

	if len(flagged) > 0 {
		t.Errorf("found %d /system handler(s) bypassing a wrapped core ceiling via raw storage (the #1542 "+
			"shape): %v\nEither route the handler through the core method that wraps this storage call, or add a "+
			"reasoned entry to rawStorageBypassAllowlist (if genuinely safe) or knownUnfixedRawStorageBypasses "+
			"(if it's a real, tracked, not-yet-fixed gap) in this file.", len(flagged), flagged)
	}

	// Staleness: an allowlist/unfixed-list entry is stale if its handler is no
	// longer registered under /system at all, or if it no longer makes any
	// flagged write-shaped wrapped call (fixed and forgotten).
	checkStale := func(listName string, m map[string]string) {
		var stale []string
		for handler := range m {
			found := false
			for _, r := range actual {
				if r.Handler == handler {
					found = true
					break
				}
			}
			if !found {
				stale = append(stale, handler+" (no longer registered under /system)")
				continue
			}
			if !handlerFlagged[handler] {
				stale = append(stale, handler+" (no longer makes a flagged write-shaped wrapped storage call)")
			}
		}
		sort.Strings(stale)
		if len(stale) > 0 {
			t.Errorf("%s entr(y/ies) no longer reproduce: %v\nRemove the entry, or move it to the other list if "+
				"its status changed (e.g. a real gap just got fixed).", listName, stale)
		}
	}
	checkStale("rawStorageBypassAllowlist", rawStorageBypassAllowlist)
	checkStale("knownUnfixedRawStorageBypasses", knownUnfixedRawStorageBypasses)
}
