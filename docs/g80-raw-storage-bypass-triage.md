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
| users_crud.go:710 | ConsumeMFAChallenge | FinishWebAuthnLogin/VerifyMFACredentials | Assertion/crypto verification + session binding + account gates all run AFTER consume; consuming alone yields only UserID/expiry. | documented-exception | — |
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
match the two patterns flagged standalone-and-first there too:
1. CreateMachineIdentityCredentialProxy — privilege escalation
2. CreateWebAuthnCredentialProxy / DeleteWebAuthnCredentialProxy / SetUserWebAuthnEnabledProxy — account takeover / 2FA bypass
3. CreateAccessRequestProxy / UpdateAccessRequestProxy — dual-control bypass on restricted secrets
4. CreateMFAStepUpGrantProxy — MFA gate bypass with zero verification
5. UpdateUserIfActiveStateMatchesProxy — last-admin lockout + stale-credential bypass
6. UpdateProjectProxy / RestoreProjectProxy — MFA-policy silent disable / admin-role resurrection
7. Everything else in the table (24 more), roughly in the order listed above

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
  downstream, an assumption with no wire-level verification (see "Re-examined" below).
  The original finding's worst-case (forge a credential for an admin-tier machine
  identity) is still reachable by anyone holding a bare node credential.
- **CreateOIDCBindingProxy** — **HALF-FIXED, still in `knownUnfixedRawStorageBypasses`,
  NOT closed.** Same shape as above: a direct caller now routes through
  `core.CreateOIDCBinding`'s `requireAuthorityForRole(..., "system_admin")` check; a
  node-credential caller still reaches the raw storage call unconditionally, on the
  same unverified relay-trust assumption.
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
**Not fixed here** — reported per explicit instruction, filing/fixing left to a
follow-up decision. This is exactly ADR-085's own still-open "harder question" (whose
authority a relayed action is actually exercised under), materialized as a concrete,
reachable finding rather than a design question.
