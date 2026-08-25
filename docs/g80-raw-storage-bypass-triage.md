# Raw-storage-bypass guard — full candidate triage

Companion to `docs/g80-overnight-handoff-2.md`. Full table for all 58 write-shaped
candidates in `docs/g80-raw-storage-bypass-enumeration.md`, the reproducible baseline
(AST-based, committed generator at `scripts/analysis/raw_storage_bypass_enumerate.go`).
The previously-recorded count was 59 (`docs/g80-remediation-notes.md`'s #1547 entry);
that figure could not be reproduced by two independent implementations of its own stated
methodology and should be treated as the incorrect one — see the enumeration doc for the
full resolution. This is a reach-scoped count: `docs/g80-raw-storage-bypass-blind-spots.md`
names five categories not examined by this guard at all.

Columns: verdict is one of `no-independent-ceiling` / `documented-exception` / `real` /
`unresolved`. Reach (only meaningful for `real`/`unresolved`) is `human-reachable` /
`machine-only` / `unknown`.

## Already resolved before this session (8 of 58)

| Call site (file:line) | Handler | Core function | Ceiling | Verdict | Reach |
|---|---|---|---|---|---|
| rbac_role_grants_proxy.go:241 | ClearProjectSecretOwnershipProxy | RemoveProjectMember (best-effort cleanup side effect) | No independent ceiling — cleanup side effect, not its own gated op. | no-independent-ceiling | — |
| rbac_role_grants_proxy.go:268 | DeleteSecretACLsByUserAndProjectProxy | RemoveProjectMember (best-effort cleanup side effect) | Same shape as above. | no-independent-ceiling | — |
| retention_proxy.go:373 | DeleteExpiredRoleGrantsProxy | RemoveExpiredRoleGrants | No actor ceiling — unconditional time-bounded sweep; only extra value is per-grant audit writing (completeness gap, not policy bypass). | no-independent-ceiling | — |
| misc_remote_proxy.go:342 | CreateUserWithRoleGrantsProxy | CreateUserWithAssignments | Deliberate exception (C2): must be ONE atomic DB transaction (ADR-028); ValidateRoleGrantAuthority re-applies the same escalation-ceiling + SoD checks before the single atomic raw-storage create. | documented-exception | — |
| rbac_role_grants_proxy.go:410 | RemoveGlobalAdminRoleGuardedProxy | RemoveGlobalAdminRoleGuarded | No real transaction spans the HTTP hop (RemoteStorage.WithTransaction is a no-op) — the last-global-admin invariant can only be enforced atomically by the row-owning server. | documented-exception | — |
| project_catalog_proxy.go:221 | DeleteProjectProxy | DeleteProject(force=false) | Same reasoning as RemoveGlobalAdminRoleGuardedProxy above. | documented-exception | — |
| project_catalog_proxy.go:246 | DeleteProjectIfEmptyProxy | DeleteProjectIfEmpty | Purpose-built atomic storage-layer primitive enforcing DeleteProject(force=false)'s guard across the hop (#528). | documented-exception | — |
| project_memberships_proxy.go:199 | TransitionMembershipProxy | TransitionMembership | Gates activation with requireAuthorityForRole + grants/revokes underlying role grant as side effect, neither performed by raw call. Reach genuinely unresolved — may be a real gap, or safe-by-design if the side effect lands via a separate relayed call from downstream's own core.TransitionMembership. | unresolved | unknown — filed as #1546, not resolved further tonight per the stopping rule (2-unresolved-in-a-row is not the reason here; this one was already filed before this session and out of tonight's scope to re-investigate). |

## Investigated tonight (50 of 58)

### Access requests / access review campaigns / break-glass

| Call site (file:line) | Handler | Core function | Ceiling | Verdict | Reach |
|---|---|---|---|---|---|
| access_request_proxy.go:170 | CreateAccessRequestProxy | RequestProjectAccess/RequestSecretAccess (invitations.go:491, classification_gate.go:215) | State is caller-writable — hasApprovedSecretAccessRequest (classification_gate.go:198) treats any row with State=Approved+SecretID+UserID as proof of dual-control-approved restricted access, normally gated by requireAdminAuthorityAt + maker≠checker in ApproveSecretAccessRequest. | real | human-reachable — router.go:1089 gate, route :1168. POST {state:"approved", secret_id:X, user_id:self} bypasses admin-authority + maker≠checker entirely. **CRITICAL.** |
| access_request_proxy.go:249 | UpdateAccessRequestProxy | ApproveAccessRequestWithExpiry/ApproveSecretAccessRequest | Maker≠checker, admin-authority escalation ceiling, TTL recheck, dual-control threshold. ResolvedBy/State/GrantedRole caller-writable. | real | human-reachable — route :1169. PUT {state:"approved",resolved_by:self} self-approves existing restricted-secret request. **CRITICAL.** |
| access_review_campaigns_proxy.go:236 | CreateAccessReviewCampaignProxy | OpenAccessReviewCampaign | Opening explicitly not gated on human actor; State=open always, forced server-side (ARC-003). | documented-exception | — |
| access_review_campaigns_proxy.go:379 | UpdateAccessReviewCampaignProxy | CloseAccessReviewCampaign | State-machine guard (0 pending unless force), ARC-002 force-close self/group/machine conflict-of-interest check, mandatory audit write. | real | human-reachable — route :1614. Raw PUT force-closes regardless of pending items/self-review conflict, NO audit event at all. |
| access_review_campaigns_proxy.go:416 | CreateAccessReviewItemsProxy | OpenAccessReviewCampaign item-generation | Only invariant (fresh item starts pending) already enforced server-side (ARC-004). | documented-exception | — |
| break_glass_proxy.go:195 | CreateBreakGlassActivationProxy | ActivateBreakGlass | Policy-enabled check, min-justification, real-project-member check, one-active-grant-per-user, role must be the CONFIGURED emergency role, TTL clamp, real role grant+audit+notification. | real | human-reachable — route :1644. Fabricates activation row for any user/project/any-contained-role/arbitrary ExpiresAt, no membership check. Blast radius limited: never invokes assignUserRoleWithExpirySkipSoD, so impact is compliance-evidence/audit-trail fabrication, not live RBAC escalation. |
| break_glass_proxy.go:276 | UpdateBreakGlassActivationProxy | ActivateBreakGlass's create-time unique index | "≤1 active activation per (project,user)" enforced ONLY at INSERT, never on UPDATE; handler is documented unconditional full-row Save. | real | human-reachable — route :1645. Can resurrect a revoked/expired row to active with fresh unclamped ExpiresAt. checkBreakGlassRoleContainment IS replicated, narrowing gap to state/TTL only. Same limited blast radius as above. |
| break_glass_proxy.go:312 | RevokeBreakGlassActivationProxy | RevokeBreakGlass | Extra step is RemoveUserRole (live role removal) + audit — travels through its own separate proxied call chain per package doc. | documented-exception | — |

### Connect grants / dynamic secrets / environments / invitations

| Call site (file:line) | Handler | Core function | Ceiling | Verdict | Reach |
|---|---|---|---|---|---|
| connect_grants_proxy.go:126 | CreateConnectRefGrantProxy | CreateConnectRefGrant | Connector must exist, must NOT be platform-scoped (#1479), audit write. | real | human-reachable — package doc's "already validated" assumption doesn't hold for a direct human caller. |
| connect_grants_proxy.go:147 | DeleteConnectRefGrantProxy | DeleteConnectRefGrant | Audit write with best-effort project-ID lookup; no other ceiling. | real | human-reachable — raw delete, zero audit trail. |
| dynamic_secrets_proxy.go:289 | UpdateDynamicSecretConfigProxy | ClassifyDynamicSecretConfig + CreateDynamicSecretConfig phase-2 | Classification validation + diff audit; dedicated TransitionDynamicSecretConfigDisabledProxy exists specifically to CAS-guard Disabled. | real | human-reachable — raw PUT sets invalid classification or silently flips Disabled with no audit/CAS, defeating the dedicated CAS-guard proxy. |
| dynamic_secrets_proxy.go:327 | TransitionDynamicSecretConfigDisabledProxy | SetDynamicSecretConfigEnabled | Same CAS write preserved; only the audit write is skipped. | real (narrow) | human-reachable — atomicity preserved, enable/disable leaves no audit trail. |
| dynamic_secrets_proxy.go:363 | CreateDynamicSecretLeaseProxy | IssueLease | Refuses if disabled/project-env not live, enforces MaxActiveLeases resource-exhaustion ceiling, audits. | real | human-reachable — raw POST injects fabricated lease for a disabled config or exceeds MaxActiveLeases, no audit. |
| dynamic_secrets_proxy.go:440 | UpdateDynamicSecretLeaseProxy | RevokeLease/RenewLease | Both require Status=="active"; RenewLease enforces MaxTTLSeconds ceiling + refuses expired lease; both audit. | real | human-reachable — raw PUT resurrects a revoked lease to active with arbitrary far-future ExpiresAt, bypasses TTL ceiling + audit. |
| environment_catalog_proxy.go:148 | DeleteEnvironmentProxy | DeleteEnvironment | Literal 1-line passthrough, no check of its own. | no-independent-ceiling | — |
| environment_catalog_proxy.go:177 | RestoreEnvironmentProxy | RestoreEnvironment | requireAuthorityToReinstateProjectRoles (same #161 check RestoreProject uses) before restore + audit. File's own doc names this exact check as NOT made by the proxy. | real | human-reachable — no actorID/authority param at all, no audit. |
| invitations_proxy.go:137 | CreateInvitationProxy | InviteToProject/InviteToProjectWithLink | Role validation, email-domain allowlist, escalation-by-proxy guard (requireAuthorityForRole). Package doc names this as NOT made here. | real | human-reachable — system.write-only caller creates a pending admin-role invitation, full escalation-guard bypass. |
| invitations_proxy.go:188 | UpdateInvitationProxy | completeInvitationAccept/RevokeInvitation | Grants applied BEFORE flip to accepted (so failed grant never leaves falsely-accepted row); RevokeInvitation checks ProjectID + audits. | real | human-reachable — raw proxy flips state to accepted/revoked with NO grants applied, no audit — strands the real invitee. |

### Login attempts/lockout, machine identities

| Call site (file:line) | Handler | Core function | Ceiling | Verdict | Reach |
|---|---|---|---|---|---|
| login_attempts_proxy.go:97 | RecordLoginAttemptProxy | RecordFailedLogin/RecordPasswordResetAttempt/RecordSSOBeginAttempt | Real policy (threshold/window) lives in the separate IsLoginRateLimited READ path, not here. | documented-exception | — |
| login_lockout_proxy.go:98 | UpdateLoginLockoutStateProxy | UnlockUser (admin path)/recordFailedLogin (login-flow path) | UnlockUser requires `users.write` (DIFFERENT permission than this route's system.write) + always audits. recordFailedLogin computes real exponential-cooldown policy. | real | human-reachable — a system.write role need not also hold users.write. Silently clears a lockout (no audit) or force-locks any account up to 30 days (DoS). |
| machine_identities_proxy.go:299 | CreateMachineIdentityProxy | CreateMachineIdentity | Validates identityType/classification, forces State=MachineActive, audits. | real | human-reachable — raw proxy only checks Name/ProjectID non-empty, arbitrary IdentityType/Classification/State, zero audit. |
| machine_identities_proxy.go:391 | TransitionMachineIdentityStateProxy | TransitionMachineIdentity via transitionMachineInTx | canTransitionMachine legality check (revoked is terminal), cross-project guard, auth-token cache eviction, audit. storage layer itself has NO legality check. | real | human-reachable — can un-revoke a revoked machine identity or jump to any state, no audit, no cache eviction. |
| machine_identities_proxy.go:469 | CreateMachineIdentityCredentialProxy | IssueMachineToken | Requires MachineActive + requireMachinePrivilegeCeiling (non-global-admin cannot mint credential for an admin-tier machine identity). Core generates TokenHash itself via crypto/rand. | real | human-reachable — **raw proxy accepts attacker-chosen TokenHash for ANY existing MachineIdentityID, NO privilege-ceiling check — forge a credential for an admin-tier machine identity and authenticate as it. MOST SEVERE FINDING — full privilege escalation.** |
| machine_identities_proxy.go:573 | UpdateMachineIdentityCredentialProxy | ClassifyMachineToken | Only mutates Classification on an already-scoped credential, leaves TokenHash/Revoked/ExpiresAt untouched, audits. Storage layer is unconditional full-row Save. | real | human-reachable — raw proxy submits entire replacement row: un-revoke any credential, overwrite TokenHash to hijack identity/roles, clear ExpiresAt — no ownership check, no audit. |
| machine_identities_proxy.go:605 | RevokeMachineIdentityCredentialProxy | RevokeMachineToken | Verifies machine belongs to caller's project + credential belongs to machine, audits + cache-eviction hand-off. | real | human-reachable — raw revoke by bare credential ID, no project-membership check, skips audit + cache eviction. Mirrors this file's own already-fixed RemoveMachineRoleProxy pattern. Impact: cross-tenant DoS/tampering, not escalation. |
| machine_identities_proxy.go:642 | TouchMachineIdentityCredentialProxy | TouchMachineTokenLastUsed | No authz/ownership check even in core — explicitly best-effort, pure throttled liveness timestamp. | no-independent-ceiling | — |
| machine_identities_proxy.go:810 | CreateOIDCBindingProxy | CreateOIDCBinding | requireAuthorityForRole(system_admin) install-wide authority check (#127), machineInProject scope, issuer-trust validation. | real | human-reachable — none of admin-tier/system.write imply system_admin-authority. |
| machine_identities_proxy.go:895 | DeleteOIDCBindingProxy | DeleteOIDCBinding | Verifies binding belongs to the target machine + machineInProject, audits. | real | human-reachable — deletes any binding ID, no ownership/scope check, no audit. |

### MFA, projects, retention (legal hold)

| Call site (file:line) | Handler | Core function | Ceiling | Verdict | Reach |
|---|---|---|---|---|---|
| mfa_management_proxy.go:137 | UpsertMFASecretProxy | BeginMFAEnrollment | Fails closed if at-rest encryption disabled; refuses if already MFA-enabled; handler-layer scopes to session's own UserID only. | real | human-reachable — raw proxy takes user_id/SecretEnc/Activated from body — plant/overwrite an "Activated" MFA secret for ANY user, even MFA-enabled, even with encryption disabled. |
| mfa_management_proxy.go:285 | MarkTOTPStepUsedProxy | ActivateMFA/VerifyMFACredentials/verifyMFAStepUpCode | Pure post-validation anti-replay CAS, not an authz gate — called only after crypto TOTP validation already passed. | no-independent-ceiling | — |
| mfa_stepup_proxy.go:60 | CreateMFAStepUpGrantProxy | VerifyMFAStepUp | Requires active/unlocked account + valid TOTP/recovery code — this grant satisfies checkRestrictedMFAGate. | real | human-reachable — **raw handler creates a grant for any UserID + attacker-chosen ExpiresAt with ZERO code verification — full bypass of restricted-secret MFA gate.** |
| project_catalog_proxy.go:198 | UpdateProjectProxy | UpdateProject | ADR-037: RequireMFA changes additionally gated on roles.assign at project scope + audits any MFA-requirement flip. | real | human-reachable — **any system.write/admin caller can silently flip a project's MFA requirement off with no audit and without roles.assign. HIGH VALUE.** |
| project_catalog_proxy.go:266 | RestoreProjectProxy | RestoreProject | requireAuthorityToReinstateProjectRoles — refuses restore if it would reinstate an admin-tier role the actor can't hold (#161 escalation guard) + audit. | real | human-reachable — raw handler restores any project with zero authority check, resurrecting admin-tier role grants. Same shape as the already-fixed C1/RemoveGlobalAdminRoleGuardedProxy bug. |
| retention_proxy.go:242 | DeleteAnomalyAlertsBeforeProxy | PurgeExpiredComplianceRecords | legalHoldGuard refuses ALL compliance purges while a deployment-wide legal hold is active (TOCTOU-safe). | real | human-reachable — purges unconditionally, no legal-hold check, destroys evidence ADR-032/033 protects. |
| retention_proxy.go:266 | DeleteClosedAccessReviewsBeforeProxy | PurgeExpiredComplianceRecords | Same legalHoldGuard re-check. | real | human-reachable — same gap. |
| retention_proxy.go:283 | DeleteExpiredBreakGlassBeforeProxy | PurgeExpiredComplianceRecords | Same legalHoldGuard re-check. | real | human-reachable — same gap. |
| retention_proxy.go:300 | DeleteResolvedAccessRequestsBeforeProxy | PurgeExpiredComplianceRecords | Same legalHoldGuard re-check. | real | human-reachable — same gap. |

### Secrets, setup tokens, SSO state, users, WebAuthn

| Call site (file:line) | Handler | Core function | Ceiling | Verdict | Reach |
|---|---|---|---|---|---|
| retention_proxy.go:405 | DeleteExpiredShareRecordsProxy | RemoveExpiredShares | Unconditional time-bound sweep, only extra value is per-row audit event. | no-independent-ceiling | — |
| secret_dependencies_proxy.go:259 | DeleteSecretDependencyProxy | RemoveSecretDependency | Verifies edge references caller's authorized focal secret, independently authorizes caller on the PEER endpoint (#G32 defense), audits. | real | human-reachable — deletes any edge ID with only the route's own gate: no focal-secret scoping, no peer-authz, no audit. |
| secrets_status_proxy.go:105 | TransitionSecretStatusProxy | SuspendSecret/ResumeSecret | Only a CAS race guard + audit; permission is explicitly not a core-layer check by design. | no-independent-ceiling | Confirmed as the correct-pattern precedent — handler faithfully reproduces the CAS. |
| setup_tokens_proxy.go:173 | CreateSetupTokenProxy | IssueSetupToken | Only issues tokens bound to a real matching-email invitation/user by convention. | documented-exception | Handler's own #G79 comment implements the invitation/user cross-reference check itself, closing exactly this gap. |
| setup_tokens_proxy.go:230 | SupersedeSetupTokensProxy | IssueSetupToken's SupersedeActiveSetupTokens step | Unconditional exact-match bulk state-flip, no ceiling at the core layer to bypass. | no-independent-ceiling | — |
| sso_state_proxy.go:100 | CreateSSOLoginStateProxy | BeginSSO/BeginSAML | Pre-login CSRF-state creation, no auth/ownership check even in core. | documented-exception | — |
| sso_state_proxy.go:133 | ConsumeSSOLoginStateProxy | validateSSOLoginState | Provider-match/expiry checks run AFTER consume, state-machine invariants identical regardless of caller. | documented-exception | — |
| users_active_transition_proxy.go:119 | UpdateUserIfActiveStateMatchesProxy | UpdateUser deactivating branch | guardLastAdminDeactivation (fail-closed last-global-admin lockout) BEFORE conditional write; same tx revokes all PATs+sessions. | real | human-reachable — **raw proxy never calls guardLastAdminDeactivation, never revokes PATs/sessions — can deactivate the install's LAST ADMIN, or leave a "deactivated" user's live sessions/PATs valid.** |
| users_crud.go:710 | ConsumeMFAChallenge | FinishWebAuthnLogin/VerifyMFACredentials | Assertion/crypto verification + session binding + account gates all run AFTER consume; consuming alone yields only UserID/expiry (`generateSecureToken`-minted, crypto/rand, unguessable — auth.go:624-625). Atomicity confirmed at storage layer (local_mfa.go:123-148, conditional `UPDATE ... WHERE used_at IS NULL AND expires_at > ?`). VERIFIED 2026-08-25 (G80 documented-exception re-verification sweep, escalation-delta test): **holds.** | documented-exception | **CORRECTED reach**: NOT pre-auth/mid-login as the endpoint's name might suggest. The full `/api/v1` `Authentication` middleware (server/middleware/auth.go:253) — requiring a valid session/PAT/machine/OIDC token — runs BEFORE the route's `users.write` permission check (router.go:300,874). A user mid-login holds only the ephemeral MFA-challenge secret, not any of those credentials, so they cannot reach this route at all. Reachable only by an already-fully-authenticated, `users.write`-holding principal — machine-only in the intended hub-spoke design (a RemoteStorage spoke's own service credential relaying its own end users' logins), not human-mid-login-reachable. |
| webauthn_proxy.go:171 | CreateWebAuthnCredentialProxy | FinishWebAuthnRegistration | requireReauth (re-prove password/TOTP) BEFORE storage write; doc: "must not be reachable by a bearer token alone." | real | human-reachable — **ZERO reauth — implant an attacker-controlled passkey on ANY account. SEVERE.** |
| webauthn_proxy.go:336 | DeleteWebAuthnCredentialProxy | DeleteWebAuthnCredential | Same requireReauth ceiling before deleting. | real | human-reachable — strip any user's real passkeys without proving ownership. |
| webauthn_proxy.go:382 | SetUserWebAuthnEnabledProxy | Only 2 core callers, both gated behind requireReauth first | No core method flips this flag standalone. | real | human-reachable — flips any user's webauthn_enabled directly, no reauth, no paired session-purge/audit — silent 2FA downgrade or bogus force-enable. |
| webauthn_proxy.go:447 | ConsumeWebAuthnSessionProxy | FinishWebAuthnRegistration/Login/PasswordlessLogin | Session-binding + assertion/attestation crypto verification run downstream after consume. | documented-exception | Atomic single-use consume preserved verbatim, mirrors ConsumeSetupTokenProxy's #510 precedent. |

## Summary counts

| Verdict | Count |
|---|---|
| no-independent-ceiling | 9 |
| documented-exception | 13 |
| real (all human-reachable) | 35 |
| unresolved | 1 (TransitionMembershipProxy, #1546) |
| **Total** | **58** |

## Issue filing — SUPERSEDED, see docs/g80-tracking-issue-draft.md

This section originally planned one GitHub issue per `real` finding (35 total). A
follow-up instruction changed that: **one tracking issue, not 35**, grouping the 35 by
shared remedy (16 distinct fix patterns), framed as one architectural property (the
`/system` proxy layer bypasses `internal/core`'s ceilings, making `system.write` a de
facto superuser) rather than a bug count. Full content, including the fix-pattern
grouping table, is in `docs/g80-tracking-issue-draft.md` (not yet filed — `gh` auth
blocked, see the handoff doc). The rough manual priority order below is superseded by
that grouping table but kept for reference since two of its entries (worst blast radius)
match the two patterns flagged standalone-and-first there too. **Re-ranked 2026-08-24**:
`AssignRoleWithExpiryProxy`'s node-credential exemption (filed as
[#1552](https://github.com/keyorixhq/keyorix/issues/1552), see "Re-examined" below)
moves to #1 — a shorter path to global admin than the original #1 (grants a role
directly to an attacker-chosen user account; CreateMachineIdentityCredentialProxy
required an admin-tier machine identity to already exist as a target):
1. **AssignRoleWithExpiryProxy (node-credential branch) — #1552** — arbitrary role
   grant (including admin-tier) to an arbitrary user, via a bare node credential
   (zero RBAC permissions by design), bypassing requireGranterHoldsRolePermissions
   entirely. Not yet fixed.
2. CreateMachineIdentityCredentialProxy — privilege escalation. HALF-FIXED: closed
   for a direct caller, still open for a node credential (same #1552 pattern) — see
   "Fix status" below.
3. CreateWebAuthnCredentialProxy / DeleteWebAuthnCredentialProxy / SetUserWebAuthnEnabledProxy — account takeover / 2FA bypass
4. CreateAccessRequestProxy / UpdateAccessRequestProxy — dual-control bypass on restricted secrets
5. CreateMFAStepUpGrantProxy — MFA gate bypass with zero verification
6. UpdateUserIfActiveStateMatchesProxy — last-admin lockout + stale-credential bypass
7. UpdateProjectProxy / RestoreProjectProxy — MFA-policy silent disable / admin-role resurrection
8. Everything else in the table (24 more), roughly in the order listed above

## Fix status (updated 2026-08-24, machine-identity/OIDC-binding sub-wave)

Authoritative current status lives in `server/http/raw_storage_bypass_guard_test.go`'s
`knownUnfixedRawStorageBypasses` / `rawStorageBypassAllowlist` maps (CI-enforced —
`TestNoUnjustifiedRawStorageBypass` fails if an entry stops matching reality). This
section records what changed in this sub-wave and why, since the map's own per-entry
comments don't carry cross-references to this doc's original investigation rows above.

- **CreateMachineIdentityProxy** — FIXED (moved to `rawStorageBypassAllowlist`). Now
  routes through `core.CreateMachineIdentity`: forces `State=MachineActive`, validates
  `IdentityType`/`Classification`, writes an audit event. No node/direct-caller split
  needed — `core.CreateMachineIdentity` has no actor-authority check for either.
- **CreateMachineIdentityCredentialProxy** ("MOST SEVERE FINDING" above) — **HALF-FIXED,
  still in `knownUnfixedRawStorageBypasses`, NOT closed.** A direct (non-node-credential)
  `system.write` caller is now denied via `core.RequireMachinePrivilegeCeiling`
  (MACH-001) when the target machine holds an admin-tier role. A **node-credential**
  caller still reaches the raw storage call unconditionally — `isNodeCredentialRequest(r)`
  routes around the new check on the theory that a genuine relay already ran it
  downstream, an assumption with no wire-level verification (see "Re-examined" below,
  and [#1552](https://github.com/keyorixhq/keyorix/issues/1552)). The original finding's
  worst-case (forge a credential for an admin-tier machine identity) is still reachable
  by anyone holding a bare node credential.
- **CreateOIDCBindingProxy** — **HALF-FIXED, still in `knownUnfixedRawStorageBypasses`,
  NOT closed.** Same shape as above: a direct caller now routes through
  `core.CreateOIDCBinding`'s `requireAuthorityForRole(..., "system_admin")` check; a
  node-credential caller still reaches the raw storage call unconditionally, on the
  same unverified relay-trust assumption tracked in
  [#1552](https://github.com/keyorixhq/keyorix/issues/1552).
- **RevokeMachineIdentityCredentialProxy** — still fully open, for both caller types.
  Deferred and filed as **[#1551](https://github.com/keyorixhq/keyorix/issues/1551)**:
  unlike the fixes above, its wire contract (`POST .../revoke` with only a bare
  credential ID) carries no project/scope parameter at all, so closing the
  `machineInProject` gap needs a `RemoteStorage` client-side wire change first, not a
  server-only fix.
- **DeleteOIDCBindingProxy** — still open, not part of this sub-wave.

### Re-examined: is the node-credential exemption itself sound?

The `isNodeCredentialRequest(r)` carve-out used above (and originally established by
`AssignRoleWithExpiryProxy`, `server/http/handlers/rbac_role_grants_proxy.go`) rests on
an assumption stated in that file's own package doc: a node relay is "trusted... for the
one check that can't distinguish 'the real acting human already passed this' from 'the
node itself holds no permissions' without a wire-level actor-identity field that doesn't
exist yet." That field does not exist. Nothing on the wire distinguishes a genuine relay
of an already-checked downstream decision from a bare node credential calling the route
directly with attacker-chosen parameters — the trust is asserted, not verified.

For `AssignRoleWithExpiryProxy` specifically, this means: a node credential — deliberately
designed to carry zero RBAC permissions of its own (ADR-030, `MachineTypeNode`'s doc
comment) and the single most widely distributed credential class in a deployment
(ADR-085) — can single-handedly grant ANY role, including admin-tier, to ANY user, in
ANY scope, via the raw `storage.AssignRoleWithExpiry` call, entirely bypassing
`requireGranterHoldsRolePermissions`. This was **not** re-derived when `actorIsMachine`
awareness was added to that check (`internal/core/authz.go:588`) — the node branch skips
`core.AssignUserRoleWithExpiry` (and therefore that check) entirely, going straight to
raw storage. This reads as a genuine, uncatalogued instance of the exact `#1542` shape
this campaign has been fixing, not a reviewed-safe design difference — and it is broader
in scope than #1545 (`AssignPermissionToRole`'s self-permission-bundling check,
`BulkDeleteSecrets`' per-secret ACL check), which covers different call sites entirely.
**Not fixed here** — reported per explicit instruction. Filed as
[**#1552**](https://github.com/keyorixhq/keyorix/issues/1552), Tier 1, ranked #1 above
(shorter path to global admin than CreateMachineIdentityCredentialProxy: grants a role
directly to an attacker-chosen user account, no pre-existing admin-tier machine
required). This is exactly ADR-085's own still-open "harder question" (whose authority
a relayed action is actually exercised under), materialized as a concrete, reachable
finding rather than a design question.

## Re-triage against the current 34 (2026-08-24, post-#1550/#1553)

`scripts/analysis/raw_storage_bypass_enumerate.go` reports **34 write-shaped candidates
today, down from 58 at baseline** — the same tool, same methodology, run against the
current tree. The 58→35/16/11 arithmetic above was derived before 23 handlers were
deleted (G80 liveness sweep, no live caller in either topology — see
`docs/g80-remediation-notes.md`) and `CreateMachineIdentityProxy` was fixed by routing
through `core.CreateMachineIdentity` (no longer makes a raw storage call at all, so it
no longer appears as a candidate — the other 23 disappeared by deletion, this one by a
genuine fix). Nobody had re-run the arithmetic against the 34 until now. This section is
that re-derivation, not an update to the rows above (which stay as the historical record
of the original 58).

Every one of the 34 was already carrying a verdict in
`server/http/raw_storage_bypass_guard_test.go`'s `rawStorageBypassAllowlist` /
`knownUnfixedRawStorageBypasses` maps before this pass — confirmed mechanically, not by
inspection: `TestNoUnjustifiedRawStorageBypass` passes today, and that test fails on any
candidate missing from both maps. What this pass added: per the standing practice ("a Go
call graph is not a deployment path... trace an actual auth path, don't infer"), every
`real`/`unresolved` entry's escalation-delta and reach claim was re-verified against
current code, not carried forward from the maps' text unread. Two were checked for the
first time individually (`DeleteOIDCBindingProxy` — no comment previously stated whether
it had been through this specific test; the handler and `core.DeleteOIDCBinding` were
read fresh) and everything else was re-read against its current line numbers to confirm
the code the reasoning describes still exists as described.

| Verdict | Count | Candidates |
|---|---|---|
| no-independent-ceiling | 9 | ClearProjectSecretOwnershipProxy, DeleteSecretACLsByUserAndProjectProxy, DeleteExpiredRoleGrantsProxy, MarkTOTPStepUsedProxy, DeleteEnvironmentProxy, TouchMachineIdentityCredentialProxy, DeleteExpiredShareRecordsProxy, TransitionSecretStatusProxy, SupersedeSetupTokensProxy |
| documented-exception | 14 | RemoveGlobalAdminRoleGuardedProxy, CreateUserWithRoleGrantsProxy, DeleteProjectProxy, DeleteProjectIfEmptyProxy, CreateAccessReviewCampaignProxy, CreateAccessReviewItemsProxy, RevokeBreakGlassActivationProxy, RecordLoginAttemptProxy, CreateSetupTokenProxy, CreateSSOLoginStateProxy, ConsumeSSOLoginStateProxy, ConsumeWebAuthnSessionProxy, TransitionMachineIdentityStateProxy (FIXED — raw call preserved deliberately, now preceded by `core.IsValidMachineTransition`), UpdateMachineIdentityCredentialProxy (FIXED — narrowed to fetch-existing + apply-Classification-only) |
| out-of-scope (not a `/system` route) | 1 | ConsumeMFAChallenge — registered outside the `/system` group (`users.write`-gated, `router.go:874`), never tracked by this guard; unchanged since the original triage |
| unresolved | 1 | TransitionMembershipProxy — #1546, explicitly out of scope for this task, not re-investigated |
| **real** | **9** | CreateAccessRequestProxy, UpdateAccessRequestProxy, CreateInvitationProxy, UpdateInvitationProxy, DeleteOIDCBindingProxy, UpdateUserIfActiveStateMatchesProxy, RevokeMachineIdentityCredentialProxy, CreateMachineIdentityCredentialProxy (residual), CreateOIDCBindingProxy (residual) |
| **Total** | **34** | |

**Of the 9 `real`: all 9 are human-reachable** (every one sits behind
`RequireNodeCredentialOrPermission(system.write)`, reachable directly by any human or
machine holding the `system.write` permission — traced via `server/http/router.go:1089`,
not inferred from the permission's name). Zero machine-only, zero unknown-reach among the
`real` set.

**3 of the 9 are ADR-BLOCKED, set aside per instruction, not touched:**
- `RevokeMachineIdentityCredentialProxy` — #1551 (wire contract carries no project/scope
  parameter; closing it needs a `RemoteStorage` client-side change gated on the same
  node-credential-relay-trust question ADR-085 hasn't resolved).
- `CreateMachineIdentityCredentialProxy` (residual half) — #1552, node-credential path
  only; the direct-caller half is already fixed (`core.RequireMachinePrivilegeCeiling`).
- `CreateOIDCBindingProxy` (residual half) — #1552, node-credential path only; the
  direct-caller half is already fixed (`core.CreateOIDCBinding`'s
  `requireAuthorityForRole`).

**6 of the 9 are real, human-reachable, and NOT ADR-blocked — the actionable set:**
1. `CreateAccessRequestProxy` — CRITICAL. Re-verified fresh (`access_request_proxy.go:170`):
   `body.toModel()` accepts `State` directly with no validation beyond non-empty; POST
   `{state:"approved", secret_id, user_id:self}` bypasses `ApproveSecretAccessRequest`'s
   admin-authority + maker≠checker dual-control entirely. Unchanged since original triage.
2. `UpdateAccessRequestProxy` — CRITICAL. Re-verified fresh (`access_request_proxy.go:219`):
   the AR-001 fix already landed (narrowed the writable field set to the five legitimate
   transition fields, closing an identity-rewrite side channel) but did NOT add an
   authority check on the `State` transition itself — `existing.State = body.State` with
   `resolved_by: self` still bypasses the same dual-control gate as above on an existing
   pending request.
3. `CreateInvitationProxy` — re-verified fresh (`invitations_proxy.go:123`): accepts
   `SystemRole`/`AssignmentsJSON` directly via `CreateProjectInvitation`, no
   `requireAuthorityForRole` escalation check.
4. `UpdateInvitationProxy` — re-verified fresh (`invitations_proxy.go:172`): full-row
   `UpdateProjectInvitation` with caller-controlled `State` straight to `accepted`, no
   grants ever applied, no audit — strands the real invitee.
5. `DeleteOIDCBindingProxy` — **not individually confirmed before this pass.** Verified
   fresh: the handler (`machine_identities_proxy.go:1056`) calls
   `storage.DeleteOIDCBinding(id)` directly; `core.DeleteOIDCBinding`
   (`internal/core/oidc.go:277`) requires `machineInProject` (the binding's machine
   belongs to the stated project) and binding-ownership (`b.MachineIdentityID ==
   machineID`) before deleting, plus an audit event — none of which the raw call performs.
   Escalation-delta: `system.write`'s documented footprint doesn't extend to
   cross-project/cross-machine OIDC-binding tampering; the raw call lets any
   `system.write` holder delete a binding belonging to a machine outside their own
   project scope, with no audit trail. Not ADR-blocked — this is a referential-integrity
   check (does the binding belong to this machine/project), not a node-credential-vs-human
   trust question; independently fixable the same way `CreateOIDCBindingProxy`'s
   direct-caller half already was.
6. `UpdateUserIfActiveStateMatchesProxy` — residual half. Re-verified fresh
   (`internal/storage/store/remote_auth.go:128,168`):
   `RevokeAllPersonalAccessTokensForUser`/`DeleteSessionsForUserExcept` are still both
   hard-stubbed to `errUnsupportedRemote`. Not ADR-blocked — a `RemoteStorage`
   wire-completeness gap, unrelated to node-credential trust — but the largest lift of the
   6 (needs new system-proxy routes for PAT/session revocation, not a handler-local fix).

**Answer to "how much is left" for this bug class: 6.**

## Fix wave complete (2026-08-25) — all 6 actionable items addressed

All 6 of the above are now fixed for a direct (non-node-credential) caller — the same
direct-caller/node-credential split established by the earlier machine-identity/OIDC-binding
sub-wave (see "Fix status" above), not a full close in every case. Authoritative status
lives in `server/http/raw_storage_bypass_guard_test.go`'s maps, as always; this is a
pointer, not a duplicate of that record.

1. `CreateAccessRequestProxy`/`UpdateAccessRequestProxy` — **FIXED** (moved to
   `rawStorageBypassAllowlist`). PR #1557: `CreateAccessRequestProxy` forces
   `State=AccessRequestPending`; `UpdateAccessRequestProxy`'s `State=approved` transition
   now requires maker≠checker plus admin or role-grant authority, re-deriving the same
   ceiling `ApproveSecretAccessRequest`/`ApproveAccessRequestWithExpiry` already enforce
   locally.
2. `CreateInvitationProxy`/`UpdateInvitationProxy` — **FIXED** (moved to
   `rawStorageBypassAllowlist`). PR #1558: `CreateInvitationProxy` now checks
   `RequireAuthorityForRole` for every role the wire body would grant (`Role`,
   `SystemRole`, each `AssignmentsJSON` entry); `UpdateInvitationProxy` narrows to the
   legitimate transition fields (AR-001 pattern) instead of a full-row overwrite.
3. `DeleteOIDCBindingProxy` — **HALF-FIXED, still in `knownUnfixedRawStorageBypasses`,
   NOT closed.** PR #1560: a direct caller now routes through `core.DeleteOIDCBinding`
   (`machineInProject` + binding-ownership + audit event, `machine_identity.oidc_unbound`).
   A node-credential caller still reaches the raw storage call unconditionally, same
   `isNodeCredentialRequest(r)` relay-trust assumption as `CreateOIDCBindingProxy`/
   `CreateMachineIdentityCredentialProxy` above. Also fixed in the same PR: a pre-existing
   bug in `GetOIDCBindingByID` (`local_machine_credentials.go`) that mislabeled every
   storage error, not just a genuine not-found, as 404 — surfaced by this fix's new
   pre-delete read, same root cause and fix shape as the sibling `local_sod.go`
   `GetSoDPolicy` bug (see item 4 below).
4. `UpdateUserIfActiveStateMatchesProxy` (PAT/session-revocation residual) —
   **HALF-FIXED, still in `knownUnfixedRawStorageBypasses`, NOT closed.** Two new routes
   (`POST /system/users/{id}/personal-access-tokens/revoke-all`,
   `POST /system/users/{id}/sessions/delete-except`) replace the `RevokeAllPersonalAccessTokensForUser`/
   `DeleteSessionsForUserExcept` hard stubs in `remote_auth.go` with real implementations.
   Unlike every other proxy in this file, these do NOT rely on the group's blanket
   `system.write` baseline alone for a direct caller: the ceiling was **derived, not
   chosen** — `core.UpdateUser`/`core.DeleteUser` perform no caller-authority check of
   their own on a deactivating transition (only `guardLastAdminDeactivation`, a
   target-state invariant with no actor parameter); the actual ceiling governing "who may
   deactivate a user" lives entirely at `RequirePermission(permUsersWrite)` on
   `PUT /api/v1/users/{id}` (`server/http/router.go`). The new routes require exactly that
   — `users.write` at global scope — for a direct caller, plus an audit event
   (`user.credentials_revoked`) with real actor attribution (the same node-credential
   actor-0 gap #1530 tracks still applies to the node-credential branch here). A
   node-credential caller still reaches the raw storage calls unconditionally, the same
   documented gap as every other HALF-FIXED entry.

   Separately, this PR also fixed a pre-existing bug independent of the proxy layer:
   `core.UpdateUser`'s deactivating branch treated `DeleteSessionsForUserExcept`'s error
   as fatal to the whole transaction while `RevokeAllPersonalAccessTokensForUser`'s was
   already best-effort (an unexplained asymmetry) — meaning a transient session-deletion
   failure reported total deactivation failure even after the actual state flip had
   already durably committed. Now best-effort on both, matching `SetAccountState`'s own
   suspend/deactivate path, which already treated this the same way. `DeleteUser` remains
   fully fatal on both, deliberately unchanged — a delete's revocation semantics are a
   separate question.

Not part of this wave: `RevokeMachineIdentityCredentialProxy` (#1551) and the
`CreateMachineIdentityCredentialProxy`/`CreateOIDCBindingProxy` node-credential residuals
(#1552) remain ADR-085-blocked, as recorded above — untouched, per instruction.
**Superseded 2026-08-25 — see "ADR-085 resolution" below: all node-credential residuals
this paragraph deferred are now closed.**

## ADR-085 resolution (2026-08-25): the node-credential OR-arm is removed

A Phase-1 liveness check (see `docs/adr-085-node-credential-permission-scope.md`, now
Accepted) found no live caller anywhere for `RequireNodeCredentialOrPermission`'s
node-credential arm: `createNodeToken` is test-only in every reference across the repo, no
Helm chart/compose file/CLI flow provisions a node credential for runtime use, and ADR-083's
`validateRemoteStorageNotServer` (`internal/config/config.go`) already rejects
`storage.type: remote` for any server process — the "downstream Keyorix node relaying an
already-authorized human action" topology every one of this file's HALF-FIXED entries
assumed cannot exist in this codebase at all. The arm is deleted (`server/middleware/
node_credential.go`, `server/http/router.go`); `/api/v1/system` now requires `system.write`
for every caller, node-typed or not, with no OR-arm exemption. Every handler's
`isNodeCredentialRequest(r)` branch is removed along with it. This closes the
node-credential axis on all six routes this campaign tracked as HALF-FIXED for that reason,
plus two more found to have the identical shape during the sweep:

- **`AssignRoleWithExpiryProxy`** (#1552, the campaign's original "MOST SEVERE FINDING") —
  now routes through `core.AssignUserRoleWithExpiry` unconditionally; a bare node credential
  is refused at the group's own `system.write` gate before ever reaching
  `requireGranterHoldsRolePermissions`. See
  `TestSystemWriteCeiling_AssignRoleWithExpiryProxy_NodeCredential_DeniedAtGate`
  (`system_write_ceiling_table_test.go`).
- **`RevokeMachineIdentityCredentialProxy`** (#1551) — the node-credential axis into it is
  closed the same way (denied at the group gate); #1551's own underlying gap (any
  `system.write` holder, human or machine, can revoke any credential cross-tenant with no
  project-scope check — a wire-contract limitation, not a node-credential one) is
  **unchanged** and remains open, tracked in `knownUnfixedRawStorageBypasses`. See
  `TestSystemWriteCeiling_RevokeMachineIdentityCredentialProxy_NodeCredential_DeniedAtGate`.
- **`CreateMachineIdentityCredentialProxy`** — closed for every caller; moved from
  `knownUnfixedRawStorageBypasses` to `rawStorageBypassAllowlist` (still makes a flagged raw
  storage call, but `core.RequireMachinePrivilegeCeiling` now runs unconditionally first).
- **`CreateOIDCBindingProxy`** — closed at the group gate for a bare node credential; entry
  removed from both guard-test lists (no longer makes a flagged raw call at all — routes
  through `core.CreateOIDCBinding`). Note this route's ceiling
  (`requireAuthorityForRole("system_admin")` → `scopedRoleIDs`) resolves authority via a
  USER's direct/group role grants only — no machine actor, however permissioned, can ever
  satisfy it, a pre-existing, unrelated characteristic confirmed against a genuinely
  system.write-holding node credential in
  `remote_storage_machine_identities_test.go`'s `OIDCBindingCreateGetListDelete_RealServer`.
- **`RemoveGlobalAdminRoleGuardedProxy`** — closed at the group gate; entry removed (no
  longer makes a flagged raw call — routes through `core.RemoveUserRole`).
- **`RevokeAllPersonalAccessTokensForUserProxy`** / **`DeleteSessionsForUserExceptProxy`** —
  closed at the group gate; entries removed (no longer make a flagged raw call).

`docs/adr-085-node-credential-permission-scope.md` is Accepted and records the full
mechanism and the general lesson (a framing inherited from a superseded ADR was never
re-derived after the superseding ADR landed). `MachineTypeNode` itself is retained as an
identity type (`keyorix machine create --type node` is still user-facing); only its special
gate privilege is removed — a node identity is authorized exactly like any other caller,
via a real role grant it either has or doesn't.

## Open question: the 14 `documented-exception` verdicts are not settled (not work for now)

The 34-candidate re-triage table above records **14** entries as `documented-exception`
(row: "no-independent-ceiling | 9 ... documented-exception | 14 ..."). That verdict means
"a code comment asserts this raw call is safe" — it does NOT mean the assertion has been
independently verified the way every `real` finding above was (escalation-delta test:
does an actor holding ONLY the route's gating permission gain a capability the gate did
not already authorize, traced to a real human auth path).

This matters because `AssignRoleWithExpiryProxy` (`rbac_role_grants_proxy.go`) was ALSO a
documented exception before this campaign — its own doc comment asserted the node-credential
relay could be trusted, an assumption stated but never verified. It became
[#1552](https://github.com/keyorixhq/keyorix/issues/1552), the campaign's highest-severity
finding, and its exact "assert, don't verify" shape is now the precedent this campaign cites
for treating every OTHER node-credential relay assumption as an open half-fix (see
`CreateOIDCBindingProxy`/`CreateMachineIdentityCredentialProxy`'s HALF-FIXED entries above).
Fourteen routes justified by a comment, never independently re-derived, is the same shape as
the suppression lists (`rawStorageBypassAllowlist` entries accepted on read, not re-verified)
this campaign has spent multiple sessions dismantling elsewhere.

**Not work for now** — this is a scope flag, not a to-do list. Before anyone treats the
14-count as settled, each entry needs the same escalation-delta test applied to the 9 `real`
findings above: trace the actual gating permission's documented footprint against what the
raw call would let a caller holding ONLY that permission do, against a real human auth path,
not the comment's own claim. Until that pass runs, "documented-exception" should be read as
"unverified-exception."
