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
//     waiting for all 35+1 to be remediated first -- exactly the
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
	"RemoveGlobalAdminRoleGuardedProxy": "deliberate exception, not a gap: no real transaction spans the HTTP hop " +
		"back to the calling server (RemoteStorage.WithTransaction is a no-op), so the last-global-admin invariant " +
		"can only be enforced atomically by whichever server owns the row -- see rbac_role_grants_proxy.go's package doc.",
	"ClearProjectSecretOwnershipProxy": "false positive: the exported core wrapper (RemoveProjectMember) calls this " +
		"storage method only as a best-effort CLEANUP side effect of removing a member, not as its own gated " +
		"operation -- there is no independent ceiling for 'clear ownership' alone to bypass.",
	"DeleteSecretACLsByUserAndProjectProxy": "false positive: same shape as ClearProjectSecretOwnershipProxy above " +
		"-- a best-effort cleanup side effect inside RemoveProjectMember, not an independently-gated operation.",
	"DeleteExpiredRoleGrantsProxy": "false positive: the exported core wrapper (RemoveExpiredRoleGrants) has no " +
		"actor ceiling either -- an unconditional, time-bounded system sweep. Its only extra value over the raw " +
		"call is per-grant audit-event writing, an audit-completeness gap (#1529 territory), not a policy bypass.",
	"CreateUserWithRoleGrantsProxy": "deliberate exception (C2), documented in its own handler doc: must be ONE " +
		"atomic DB transaction (ADR-028), which a naive validate-via-core-then-create-via-core two-call proxy " +
		"would break. ValidateRoleGrantAuthority re-applies the same escalation-ceiling + SoD checks the core " +
		"wrapper (CreateUserWithAssignments, a different exported method than the storage method name this " +
		"guard matched) uses, before the single atomic raw-storage create.",
	"DeleteProjectProxy": "deliberate exception, same reasoning as RemoveGlobalAdminRoleGuardedProxy above: no " +
		"real transaction spans the HTTP hop, so a guard here couldn't be atomic anyway.",
	"DeleteProjectIfEmptyProxy": "false positive / by design: DeleteProjectIfEmpty is a purpose-built atomic " +
		"storage-layer primitive that enforces DeleteProject(force=false)'s guard across the hop (#528) -- the " +
		"raw call IS the guard, not a bypass of it.",
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
	// The following 8 were classified documented-exception in the overnight triage.
	"CreateAccessReviewCampaignProxy": "documented-exception: OpenAccessReviewCampaign is explicitly NOT gated on " +
		"a human actor (opening a campaign is a scheduled/automatic action); State=open always, which the handler " +
		"itself already forces server-side (ARC-003).",
	"CreateAccessReviewItemsProxy": "documented-exception: the only caller-relevant invariant (a fresh item starts " +
		"Decision=pending/DecidedBy=0) is already enforced server-side by the handler (ARC-004); item content " +
		"mirrors a live snapshot, not a core-enforced authorization ceiling.",
	"RevokeBreakGlassActivationProxy": "documented-exception, per this file's own package doc (lines 15-26, " +
		"38-42): the role-removal side effect (RemoveUserRole) travels through its own separate proxied call " +
		"chain, not through RevokeBreakGlassActivation; the conditional WHERE state='active' update this handler " +
		"performs is faithfully preserved.",
	"RecordLoginAttemptProxy": "documented-exception, per this file's own package doc: the real rate-limit policy " +
		"(threshold/window) lives in the separate IsLoginRateLimited READ path, not in the record path -- " +
		"RecordFailedLogin itself does nothing but canonicalize the IP and persist.",
	"CreateSetupTokenProxy": "documented-exception: the handler's own #G79 comment explicitly re-derives and " +
		"closes the gap a naive raw call would have (a direct system.write caller minting a takeover token) by " +
		"implementing the invitation/user cross-reference check itself before persisting.",
	"CreateSSOLoginStateProxy": "documented-exception, per this file's own package doc: no SSO policy decision is " +
		"made here; BeginSSO/BeginSAML have no caller-dependent check either (pre-login CSRF-state creation).",
	"ConsumeSSOLoginStateProxy": "documented-exception, per this file's own package doc: the atomic read-then-" +
		"conditional-delete single-use guarantee is preserved verbatim; provider-match/expiry checks are state-" +
		"machine invariants identical regardless of caller, and run downstream of consume either way.",
	"ConsumeWebAuthnSessionProxy": "documented-exception, per this file's own package doc: mirrors " +
		"ConsumeSetupTokenProxy's #510 precedent -- the atomic single-use consume is preserved verbatim, and the " +
		"actual assertion/attestation crypto verification runs downstream, never in this call.",
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
// 35 of these 36 were independently re-verified against an escalation-delta test
// (does an actor holding ONLY the route's gating permission gain a capability the
// gate did not already authorize, traced to a real human auth path) on a 5-item
// sample the same night this list was built; all 5 held up. The reach column
// noted per entry is human-reachable for all but TransitionMembershipProxy
// (reach genuinely unresolved, tracked separately as #1546).
var knownUnfixedRawStorageBypasses = map[string]string{
	"TransitionMembershipProxy": "UNRESOLVED, not confirmed real or safe -- filed as #1546. The exported wrapper " +
		"(TransitionMembership) gates activation with requireAuthorityForRole and grants/revokes the underlying " +
		"role grant as a side effect neither of which this raw call performs; whether that's covered by a " +
		"separate relayed call from the downstream's own core.TransitionMembership, or a real gap, is undetermined.",
	"CreateAccessRequestProxy": "REAL, human-reachable, CRITICAL: State is caller-writable with no restriction -- " +
		"POST {state:\"approved\", secret_id, user_id:self} bypasses ApproveSecretAccessRequest's admin-authority " +
		"+ maker≠checker dual-control entirely for restricted-secret access.",
	"UpdateAccessRequestProxy": "REAL, human-reachable, CRITICAL: same dual-control bypass as " +
		"CreateAccessRequestProxy, applied to an EXISTING pending request via PUT {state:\"approved\", " +
		"resolved_by:self}.",
	"UpdateAccessReviewCampaignProxy": "REAL, human-reachable: raw PUT force-closes a campaign regardless of " +
		"pending items or ARC-002's self/group/machine conflict-of-interest independence check, and emits no " +
		"audit event at all (unlike the Create path).",
	"CreateBreakGlassActivationProxy": "REAL, human-reachable, narrower blast radius: fabricates an activation " +
		"row for any user/project/any-contained-role with no membership check, but never invokes " +
		"assignUserRoleWithExpirySkipSoD -- impact is compliance-evidence/audit-trail fabrication, not live RBAC " +
		"escalation.",
	"UpdateBreakGlassActivationProxy": "REAL, human-reachable, narrower blast radius: the \"at most one active " +
		"activation per (project,user)\" invariant is enforced only at INSERT (a DB unique index), never on " +
		"UPDATE -- can resurrect a revoked/expired row to active with an unclamped ExpiresAt. Same limited blast " +
		"radius as CreateBreakGlassActivationProxy.",
	"CreateConnectRefGrantProxy": "REAL, human-reachable: connector-existence and not-platform-scoped checks " +
		"(#1479) plus an audit event are all skipped by the raw call.",
	"DeleteConnectRefGrantProxy": "REAL, human-reachable: raw delete leaves zero audit trail (EventConnectRefGrantDelete).",
	"UpdateDynamicSecretConfigProxy": "REAL, human-reachable: raw PUT can set an invalid classification or " +
		"silently flip Disabled with no audit and no CAS, defeating the dedicated CAS-guard proxy " +
		"(TransitionDynamicSecretConfigDisabledProxy) that exists specifically to protect that field.",
	"TransitionDynamicSecretConfigDisabledProxy": "REAL, human-reachable, narrow: atomicity (the CAS write) is " +
		"faithfully preserved; only the audit event is skipped.",
	"CreateDynamicSecretLeaseProxy": "REAL, human-reachable: raw POST can inject a fabricated lease for a " +
		"disabled config or exceed MaxActiveLeases (the resource-exhaustion ceiling), no audit.",
	"UpdateDynamicSecretLeaseProxy": "REAL, human-reachable: raw PUT can resurrect a revoked lease to active with " +
		"an arbitrary far-future ExpiresAt, bypassing RenewLease's MaxTTLSeconds ceiling and audit.",
	"RestoreEnvironmentProxy": "REAL, human-reachable: no actorID/authority parameter at all -- skips " +
		"requireAuthorityToReinstateProjectRoles (the same #161 escalation guard RestoreProject uses) and emits " +
		"no audit event; this file's own package doc names this exact check as one NOT made by the proxy.",
	"CreateInvitationProxy": "REAL, human-reachable: a system.write-only caller (no project-admin authority) can " +
		"create a pending admin-role invitation, bypassing the escalation-by-proxy guard (requireAuthorityForRole) " +
		"entirely -- this file's own package doc names this as NOT made here.",
	"UpdateInvitationProxy": "REAL, human-reachable: raw proxy can flip state straight to accepted/revoked with " +
		"NO grants ever applied and no audit -- strands the real invitee (a state-machine sequencing bypass, not " +
		"just a permission gap).",
	"UpdateLoginLockoutStateProxy": "REAL, human-reachable: UnlockUser requires users.write (a DIFFERENT " +
		"permission from this route's system.write) and always audits; the raw proxy lets any system.write " +
		"holder silently clear a lockout (no audit, no users.write) or force-lock any account for up to 30 days " +
		"(DoS).",
	"RevokeMachineIdentityCredentialProxy": "REAL, human-reachable, narrower: revokes by bare credential ID with " +
		"no project-membership check, skips audit + cache-eviction hand-off. Mirrors this file's own " +
		"already-fixed RemoveMachineRoleProxy pattern; impact is cross-tenant DoS/tampering, not escalation. " +
		"Deferred (not a wire-compatible fix like its siblings): the wire contract carries no project/scope " +
		"parameter at all, so closing it needs a RemoteStorage client-side change first -- filed as #1551.",
	"DeleteOIDCBindingProxy": "REAL, human-reachable: deletes any binding ID with no ownership/project-scope " +
		"check and no audit event, versus core.DeleteOIDCBinding's machineInProject + binding-ownership checks.",
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
	"UpsertMFASecretProxy": "REAL, human-reachable: raw proxy takes user_id/SecretEnc/Activated straight from the " +
		"JSON body -- plant or overwrite an \"Activated\" MFA secret for ANY user, even an already-MFA-enabled " +
		"one, even with at-rest encryption disabled, versus BeginMFAEnrollment's fail-closed + already-enabled " +
		"refusal + handler-layer self-only scoping.",
	"CreateMFAStepUpGrantProxy": "REAL, human-reachable, SEVERE: VerifyMFAStepUp requires a valid TOTP/recovery " +
		"code (verifyMFAStepUpCode) before granting the step-up that satisfies checkRestrictedMFAGate for " +
		"restricted-secret reads. The raw proxy creates a grant for any UserID with an attacker-chosen ExpiresAt " +
		"and ZERO code verification -- full bypass of the restricted-secret MFA gate. Verified against the " +
		"escalation-delta test: requireReauth-family checks verify the TARGET user's own password/TOTP, " +
		"orthogonal to any RBAC permission including system.write.",
	"UpdateProjectProxy": "REAL, human-reachable, HIGH VALUE: catalog.go's human-facing UpdateProject handler " +
		"explicitly gates a RequireMFA change on roles.assign at project scope (ADR-037; its own comment: " +
		"\"otherwise a developer could silently disable the project's MFA enforcement\") plus an audit event on " +
		"any flip. roles.assign and system.write are distinct permission strings -- the raw proxy has no such " +
		"check at all. Verified against the escalation-delta test directly in code (catalog.go:240-248 vs. " +
		"project_catalog_proxy.go:186-198).",
	"RestoreProjectProxy": "REAL, human-reachable: raw handler restores any project with zero authority check, " +
		"resurrecting admin-tier role grants that requireAuthorityToReinstateProjectRoles (the #161 escalation " +
		"guard) would otherwise refuse -- same shape as the already-fixed C1/RemoveGlobalAdminRoleGuardedProxy " +
		"bug (a wrapper that resolves its own admin/ceiling list; the raw call skips it entirely).",
	"DeleteAnomalyAlertsBeforeProxy": "REAL, human-reachable, different shape from the others: legalHoldGuard " +
		"checks global state (IsLegalHoldActive), not caller identity -- purges unconditionally with no check, " +
		"destroying evidence a deployment-wide legal hold (ADR-032/033) is meant to protect. Verified against the " +
		"escalation-delta test: the capability gained (purge during an active hold) is denied to EVERY actor, " +
		"including full admins, through the correct path -- not a privilege-tier escalation, but a genuine " +
		"capability gain no one should have while a hold is active.",
	"DeleteClosedAccessReviewsBeforeProxy": "REAL, human-reachable: same legalHoldGuard gap as " +
		"DeleteAnomalyAlertsBeforeProxy -- PurgeExpiredComplianceRecords re-checks the hold before this delete " +
		"too, and the raw proxy has no equivalent check.",
	"DeleteExpiredBreakGlassBeforeProxy": "REAL, human-reachable: same legalHoldGuard gap as " +
		"DeleteAnomalyAlertsBeforeProxy, applied to break-glass records.",
	"DeleteResolvedAccessRequestsBeforeProxy": "REAL, human-reachable: same legalHoldGuard gap as " +
		"DeleteAnomalyAlertsBeforeProxy, applied to resolved access requests.",
	"DeleteSecretDependencyProxy": "REAL, human-reachable: RemoveSecretDependency verifies the edge references " +
		"the caller's authorized FOCAL secret, then independently authorizes the caller on the PEER endpoint " +
		"(#G32 defense -- an ACL grant on one endpoint doesn't extend to the other), then audits. The raw proxy " +
		"deletes any edge ID with only the route's own gate -- no focal-secret scoping, no peer-authz, no audit.",
	"UpdateUserIfActiveStateMatchesProxy": "PARTIALLY FIXED 2026-08-24 (G80 overnight campaign, Tier 1 Group A " +
		"#3): the last-admin-lockout half is fixed -- core.GuardLastAdminDeactivation now runs before any " +
		"deactivating transition (FromActive:true, Active:false), a target-state check needing only the target " +
		"user ID, no RemoteStorage wire-protocol change required. STILL REAL, STILL UNFIXED: the PAT/session " +
		"revocation half. Separately discovered while checking RemoteStorage impact before this fix: " +
		"RemoteStorage.RevokeAllPersonalAccessTokensForUser and DeleteSessionsForUserExcept are BOTH stubbed to " +
		"errUnsupportedRemote (remote_auth.go), and DeleteSessionsForUserExcept's error is NOT discarded -- it " +
		"propagates and fails core.UpdateUser's whole deactivating-branch transaction. This means the 'correct' " +
		"full deactivation flow already fails outright over RemoteStorage today, independent of this proxy -- an " +
		"offboarding failure (cannot deactivate ANY user in connected mode, not just a missing side effect on " +
		"this one raw call), tracked and assessed separately against the Tier 1 line, not fixed as part of this " +
		"change.",
	"CreateWebAuthnCredentialProxy": "REAL, human-reachable, SEVERE: FinishWebAuthnRegistration calls " +
		"requireReauth (re-prove the TARGET account's current password/TOTP) before persisting; its own doc says " +
		"this \"must not be reachable by a bearer token alone.\" The raw proxy has ZERO reauth -- implant an " +
		"attacker-controlled passkey on ANY account. Verified against the escalation-delta test: requireReauth " +
		"checks possession of the target user's own credentials, unrelated to any RBAC permission the caller " +
		"holds.",
	"DeleteWebAuthnCredentialProxy": "REAL, human-reachable: same requireReauth gap as " +
		"CreateWebAuthnCredentialProxy -- strip any user's real passkeys with no proof of ownership.",
	"SetUserWebAuthnEnabledProxy": "REAL, human-reachable: the only two core callers of SetUserWebAuthnEnabled " +
		"(FinishWebAuthnRegistration, DeleteWebAuthnCredential) both run it only AFTER their own requireReauth -- " +
		"the raw proxy flips any user's webauthn_enabled flag directly, no reauth, no paired session-purge/audit " +
		"-- silent 2FA downgrade or bogus force-enable on an arbitrary account.",
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
