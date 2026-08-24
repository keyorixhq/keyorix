# DRAFT — one GitHub issue, not yet filed (file whenever gh device-flow login is convenient, not a gate — see bottom)

## Headline (2026-08-24, post-reconciliation)

**35 confirmed findings → 2 already fixed (Group A) + 23 deleted (no live caller in
either topology — 18 originally no-caller, 5 orphaned by the scheduler boot-gate fix,
including the WebAuthn trio + `CreateMFAStepUpGrantProxy`, see ADR-085's "Removed
implementations") + 10 requiring a real ceiling fix (live caller confirmed).** Deletion
PR: removes the 23, tagged `pre-system-proxy-deletion` beforehand for archaeology. The
10 remaining are next: 5 confirmed solid, 5 narrower (their CLI command bypasses the
proxy in connected mode via a direct REST call, so the fix protects the embedded-mode
path — verify the direct REST endpoint carries its own ceiling before fixing the proxy,
per the standing "don't protect nothing" check) — see the Liveness sweep section below
for the full breakdown.

**Title**: The /system proxy layer is a parallel API surface that bypasses the ceilings
`internal/core` enforces on the human-facing routes — 35 confirmed instances, 16 distinct
fix patterns

**Body**:

## The architectural finding

This is not a list of 35 unrelated bugs. It's one property of how `/api/v1/system`
(`server/http/handlers/*_proxy.go`, the RemoteStorage-relay surface) was built: these
handlers call `h.coreService.Storage().X(...)` directly, bypassing `internal/core`'s
`KeyorixCore` methods even where an exported wrapper for that exact storage primitive
already exists and already enforces a real ceiling — dual-control, admin-authority,
reauth, privilege ceilings, legal holds. The human-facing routes for the same operations
go through `internal/core` and get those ceilings. The `/system` routes don't.

Because `/system` is gated by `RequireNodeCredentialOrPermission(system.write)` — not
node-credential-only — any actor holding the `system.write` permission reaches this
entire surface directly. `system.write`'s documented footprint
(`internal/core/auth_bootstrap.go:59-83`) is "audit checkpoints, legal holds, risk
exceptions, SoD policies, admin job triggers." In practice, because of this architectural
gap, **`system.write` is a de facto superuser permission**: its actual footprint includes
privilege escalation to admin-tier machine identities, account takeover via passkey
implant, dual-control bypass on restricted-secret access, and evidence destruction during
an active legal hold — none of which its documentation describes or its designers
intended (the permission's own bootstrap comment already flags this exact class of
over-grant as a known risk from the #G79 node-credential-gate change; this issue is the
concrete enumeration of how far it actually extends).

**The count (35 real, all but 1 human-reachable — full detail:
`docs/g80-raw-storage-bypass-triage.md`, reproducible enumeration:
`docs/g80-raw-storage-bypass-enumeration.md`) is evidence for this property, not the
finding itself.** Fixing 35 call sites one at a time treats the symptom; the underlying
property (a parallel storage-access surface with no ceiling parity) will keep producing
new instances until either every `/system` proxy is routed through its `internal/core`
equivalent, or the raw-storage escape hatch is removed from this route group entirely.
`raw_storage_bypass_guard_test.go` now blocks a NEW instance (#36) from being added while
the existing 36 are worked down (grandfathered as a frozen, reasoned allowlist — see the
test file for the split between "reviewed safe" and "reviewed real, not yet fixed").

## The real estimate of the work: 16 distinct fix patterns, not 35 PRs

| # | Pattern | Shared remedy shape | Findings |
|---|---|---|---|
| 1 | Legal-hold guard missing | Add `legalHoldGuard` (or route through `PurgeExpiredComplianceRecords`) — no actor-context plumbing needed, one shared helper likely closes all 4 in one PR | `DeleteAnomalyAlertsBeforeProxy`, `DeleteClosedAccessReviewsBeforeProxy`, `DeleteExpiredBreakGlassBeforeProxy`, `DeleteResolvedAccessRequestsBeforeProxy` |
| 2 | WebAuthn reauth-proof missing | Wire DTO needs a reauth-proof field threaded to `requireReauth`; all three route through reauth-gated core methods | `CreateWebAuthnCredentialProxy`, `DeleteWebAuthnCredentialProxy`, `SetUserWebAuthnEnabledProxy` |
| 3 | Machine-identity/credential integrity | Route through the matching core method (validation, state-legality, ownership/project-scope, audit), thread actorID where needed | `CreateMachineIdentityProxy`, `TransitionMachineIdentityStateProxy`, `UpdateMachineIdentityCredentialProxy`, `RevokeMachineIdentityCredentialProxy` |
| 4 | Dynamic-secret config/lease ceilings | Classification validation, `MaxActiveLeases`, TTL ceiling, active-only status guard — one core wrapper family | `UpdateDynamicSecretConfigProxy`, `TransitionDynamicSecretConfigDisabledProxy`, `CreateDynamicSecretLeaseProxy`, `UpdateDynamicSecretLeaseProxy` |
| 5 | Escalation-by-proxy / role-grant authority | `requireAuthorityForRole`, threaded actorID | `CreateInvitationProxy`, `CreateOIDCBindingProxy`, `DeleteOIDCBindingProxy` |
| 6 | Restore-authority ceiling | `requireAuthorityToReinstateProjectRoles` — literally the same helper function for both | `RestoreEnvironmentProxy`, `RestoreProjectProxy` |
| 7 | Cross-permission gate missing | The operation needs a DIFFERENT, stricter permission than `system.write` (`roles.assign`, `users.write`) — add the same in-handler check the human-facing route already has | `UpdateProjectProxy`, `UpdateLoginLockoutStateProxy` |
| 8 | Dual-control / admin-authority for restricted-secret access | `requireAdminAuthorityAt` + maker≠checker, one shared core flow (`ApproveSecretAccessRequest`) | `CreateAccessRequestProxy`, `UpdateAccessRequestProxy` |
| 9 | Break-glass activation integrity | Membership check, uniqueness-on-update, TTL clamp — both route through the same `ActivateBreakGlass`-shaped logic | `CreateBreakGlassActivationProxy`, `UpdateBreakGlassActivationProxy` |
| 10 | MFA/secret possession-proof missing | Self-only scoping + already-enrolled refusal (secret upsert); real code verification (step-up) — both "don't grant MFA-adjacent trust without proof" | `UpsertMFASecretProxy`, `CreateMFAStepUpGrantProxy` |
| 11 | Connect-grant / audit-completeness gaps | Connector validation + missing audit event — smallest fix in the list | `CreateConnectRefGrantProxy`, `DeleteConnectRefGrantProxy` |
| 12 | Machine-identity credential privilege ceiling | `requireMachinePrivilegeCeiling`/`IsGlobalAdmin`, threaded actorID — **standalone: full privilege escalation, highest priority regardless of grouping** | `CreateMachineIdentityCredentialProxy` |
| 13 | Access-review campaign close integrity | State-machine guard + `checkForceCloseIndependence` + audit | `UpdateAccessReviewCampaignProxy` |
| 14 | Invitation state-machine integrity | Apply grants before flipping to `accepted` (sequencing, not just a permission gap) + audit | `UpdateInvitationProxy` |
| 15 | Secret-dependency peer-endpoint authorization | `AuthorizeSecretPrincipal` on the peer secret (#G32 defense) + focal-secret scoping + audit | `DeleteSecretDependencyProxy` |
| 16 | User-deactivation integrity | `guardLastAdminDeactivation` + PAT/session revocation — **standalone: can lock out the install's last admin, or leave a "deactivated" account's credentials live** | `UpdateUserIfActiveStateMatchesProxy` |

**16 distinct fix patterns for 35 findings** (~2.2 findings/pattern average). Patterns 1,
2, 3, 4, 6, 9 are pure mechanical/plumbing fixes (thread an existing check through, no new
design). Patterns 5, 7, 8, 10, 11, 13, 14, 15 need a small amount of wire-DTO extension
(an actor-context or proof field that doesn't exist on the wire today). Patterns 12 and 16
are standalone, severe, and should not wait for batching — they're the two to fix first
regardless of how the rest get sequenced.

## Severity ranking and the launch line

Three criteria, applied per pattern: **(A) does the bypass grant privilege** (the actor
ends the call with a capability — access, authentication material, a role — they didn't
have before) **vs. skip a state guard** (the bypass causes damage, data loss, or a policy
downgrade, but doesn't hand the actor a new capability); **(B) is it reachable by a
non-admin** — uniformly YES for all 35 (every one sits behind the same `system.write`-or-
admin-tier gate, and `system.write` is explicitly documented as a narrow, non-admin,
grantable-to-a-custom-role permission — this was verified, not assumed, in the prior
escalation-delta pass); this criterion doesn't further separate the 35 from each other, it's
why they're findings at all, so severity here is driven by (A) and (C); **(C) would it
matter on a single controlled install with a small, mostly-trusted user set** — this
CUTS BOTH WAYS: some findings (dual-control bypass, audit-completeness, cross-tenant
tampering) matter less with only 2-3 trusted operators and one tenant; others (losing the
one admin, account takeover of whichever few users exist, silently disabling the only
2FA/MFA control) matter MORE, because there's no redundancy or scale to absorb the damage.

### Tier 1 — fix before a first customer runs Keyorix

Grants privilege or enables account takeover, unconditionally (no rare precondition
needed beyond making the API call), and the damage doesn't shrink on a small install —
if anything it's worse there (fewer admins, less redundancy, "revoke access" and "require
2FA" are exactly the promises a small trusted-team deployment leans on hardest).

| Pattern | Handlers | Why Tier 1 |
|---|---|---|
| 12 | `CreateMachineIdentityCredentialProxy` | **STILL OPEN.** Unconditional full privilege escalation — forge a working credential for an admin-tier machine identity. Worst finding of the 35. Needs `actorID` on the wire (genuinely missing, unlike the access-request case) — its own follow-up decision, not resolved this session. |
| 3 (partial) — **FIXED** | `UpdateMachineIdentityCredentialProxy`, `TransitionMachineIdentityStateProxy` | Both fixed 2026-08-24, red-then-green tested, no RemoteStorage wire-protocol change needed (verified before fixing). `TransitionMachineIdentityStateProxy`: `core.IsValidMachineTransition` now runs before the CAS write (revoked is terminal). `UpdateMachineIdentityCredentialProxy`: narrowed to fetch-existing + apply-Classification-only, matching `core.ClassifyMachineToken`'s real behavior — `TokenHash`/`Revoked`/`ExpiresAt` are no longer caller-writable. |
| 2 | `CreateWebAuthnCredentialProxy`, `DeleteWebAuthnCredentialProxy`, `SetUserWebAuthnEnabledProxy` | Zero re-auth — implant an attacker-controlled passkey on ANY account, including whichever account is the install's actual admin. On a 3-person install, this is a path to becoming the top admin, not just "any user." |
| 16 | `UpdateUserIfActiveStateMatchesProxy` | **FIXED** (2026-08-24): last-admin-lockout half closed via `core.GuardLastAdminDeactivation`, a target-state check needing only the target user ID — no RemoteStorage wire-protocol change, verified with a red-then-green test. PAT/session revocation half is a SEPARATE, confirmed-real functional defect — see the new row below, not fixed as part of this handler. |
| N/A — functional defect, not a bypass | (none — a RemoteStorage primitive gap, not a handler) | **NEW, confirmed live, not "wired but unused":** `RemoteStorage.RevokeAllPersonalAccessTokensForUser` and `RemoteStorage.DeleteSessionsForUserExcept` are both hard-stubbed to `errUnsupportedRemote` (`internal/storage/store/remote_auth.go:128,168`), and the latter's error is NOT discarded — it propagates and fails `core.UpdateUser`'s entire deactivating-branch transaction. Confirmed this is a REAL, exercised path (not dormant like the WebAuthn finding below): `internal/cli/user/update.go`'s `keyorix user update --active false` calls `service.UpdateUser` directly with no connected-mode branch at all — unlike most other CLI user/secret commands, it never checks `common.NewRemoteClient()` first. **Result: an admin running the one confirmed-working `storage.type: remote` deployment mode (ADR-083) cannot deactivate ANY user at all** — the command errors out instead of silently succeeding-but-incomplete. This is an offboarding failure, not a missing side effect: "revoke this person's access" is a basic administrative operation that currently cannot be performed in that mode. Recommend Tier 1 on its own merits, per the same "matters more on a small controlled install" reasoning as the rest of this tier — a small team is exactly the profile most likely to run a single hub + CLI-only spokes. |
| 8 | `CreateAccessRequestProxy`, `UpdateAccessRequestProxy` | **STILL OPEN, but the fix is confirmed to hold (Group C check, 2026-08-24).** Self-approve access to the product's core asset (restricted secret values), full bypass of dual control. Matters MORE on a small team, not less. Group C asked: does the hub share a user/role directory with the spoke, making a hub-side re-derivation of `requireAdminAuthorityAt(ResolvedBy, projectID)` meaningful? **Yes** — there is only one authoritative directory (the hub's `LocalStorage`); a spoke has none of its own (`RemoteStorage` relays everything). Re-deriving the check using the hub's own data is sound. Bonus finding while checking: `requireAdminAuthorityAt` (and `AuthorizePrincipal` generally) can **never succeed on a `RemoteStorage`-backed core at all** — `GetUserRoleIDsAt`/`RoleSetHasPermission` are hard-stubbed `"not supported in remote storage"` — confirmed independently by ADR-083's own evidence table. Combined with ADR-083 (ACCEPTED): a "downstream server" relaying an already-authorized human's action, the scenario this proxy's own package doc assumes, **never functioned and is now boot-rejected**. The real legitimate caller of this route, if any, is a one-shot CLI command using `RemoteStorage` directly, not a second server — worth confirming (same standard as the WebAuthn check) before finishing this fix. Not implemented this session; flagged for next pass. |
| 10 | `CreateMFAStepUpGrantProxy` unconditionally; `UpsertMFASecretProxy` **partially fixed** | `CreateMFAStepUpGrantProxy`: zero-verification grant that satisfies the restricted-secret MFA gate — no precondition, straightforward Tier 1, **decided as part of Group B (2026-08-24): restrict to the hub, same proof-of-possession reasoning as WebAuthn** (see ADR-085) — not yet implemented, but confirmed low-risk to implement (needs the same "is this actually exercised by a real caller" check ADR-085 flags as not yet independently traced for this specific route). `UpsertMFASecretProxy`: **2 of its checks FIXED** (already-enrolled refusal + encryption-enabled check, both target-state/hub-local, no wire change needed, red-then-green tested). Full account takeover severity was and remains CONDITIONAL on whether the attacker can produce ciphertext `authEncryptor` will decrypt to a chosen TOTP seed — still not verified this session, per instruction not to spend time resolving it. The 2 fixes landed regardless close real gaps (planting a secret on an already-enrolled user, or while encryption is off) independent of that open question. |

### Tier 2 — fix soon after launch, not blocking

Real, privilege-adjacent, but either needs an extra step beyond the single API call
(accept an invitation, actually exploit an OIDC federation), needs a specific
pre-existing state (a previously soft-deleted admin-role-bearing project), or the feature
itself (dynamic secrets) is unlikely to be in use by a brand-new first customer.

| Pattern | Handlers | Why not Tier 1 |
|---|---|---|
| 5 | `CreateInvitationProxy`, `CreateOIDCBindingProxy`, `DeleteOIDCBindingProxy` | Real escalation, but requires a second step (the invitation must be accepted; the OIDC binding must actually be exploited via a real federated login) rather than completing in one call. |
| 7 | `UpdateProjectProxy` (MFA-disable), `UpdateLoginLockoutStateProxy` | Undermines the auth posture (silent 2FA-requirement downgrade) and enables a targeted DoS against the sole admin (force-lock for 30 days) — serious, but a pre-step toward compromise rather than compromise itself. |
| 6 | `RestoreEnvironmentProxy`, `RestoreProjectProxy` | Needs a specific historical state (a soft-deleted project/environment that used to carry admin-tier role grants) to matter at all — plausible but not guaranteed present on a brand-new install. |
| 3 (remainder) | `CreateMachineIdentityProxy`, `RevokeMachineIdentityCredentialProxy` | Integrity/DoS-shaped (fabricated identity metadata; cross-tenant credential tampering) rather than privilege-granting — cross-tenant impact is also less relevant on a single-tenant first install. |
| 4 | `UpdateDynamicSecretConfigProxy`, `TransitionDynamicSecretConfigDisabledProxy`, `CreateDynamicSecretLeaseProxy`, `UpdateDynamicSecretLeaseProxy` | Real (a resurrected lease is a working credential to an EXTERNAL system), but dynamic secrets is an advanced/optional feature a first customer is unlikely to have configured yet. Re-prioritize to Tier 1 the moment a customer actually uses it. |

### Tier 3 — can follow comfortably

State-guard or compliance/audit-completeness bypasses with no privilege grant, dormant
unless a rare event or underused feature is actually in play.

| Pattern | Handlers | Why Tier 3 |
|---|---|---|
| 9 | `CreateBreakGlassActivationProxy`, `UpdateBreakGlassActivationProxy` | Explicitly narrower blast radius already noted in the triage — never invokes the real role-grant path, so impact is compliance-evidence fabrication, not live RBAC. |
| 1 | `DeleteAnomalyAlertsBeforeProxy`, `DeleteClosedAccessReviewsBeforeProxy`, `DeleteExpiredBreakGlassBeforeProxy`, `DeleteResolvedAccessRequestsBeforeProxy` | Dormant unless a legal hold is actually placed — a deliberate, rare compliance event, unlikely in a first customer's early weeks. |
| 13 | `UpdateAccessReviewCampaignProxy` | Governance-process integrity (a periodic access-review control), not secret-value access — a brand-new customer is unlikely to be mid-cycle on their first access review yet. |
| 11 | `CreateConnectRefGrantProxy`, `DeleteConnectRefGrantProxy` | Validation + audit-completeness only, no ceiling to speak of. |
| 15 | `DeleteSecretDependencyProxy` | Metadata-only tampering (a dependency-tracking edge between secrets, not secret content). |
| 14 | `UpdateInvitationProxy` | A functional/integrity bug (stranded invitee) more than a security issue — nothing is granted to the attacker. |

**The line: everything in Tier 1 (11 handlers across 6 patterns, with `UpsertMFASecretProxy`
included on the conservative side) should be fixed before a first customer is running
Keyorix. Tiers 2 and 3 can follow in the weeks after, roughly in that order, with Tier 2's
dynamic-secrets group (pattern 4) re-prioritized to Tier 1 the moment dynamic secrets is
actually in use by a customer.**

## Reach

All 35 are `human-reachable`: any actor holding `system.write` (or any admin-tier role,
which bypasses permission checks entirely — `internal/core/authz.go:173-209`) reaches
every one of these routes directly, no node credential required. A 5-item sample was
independently re-verified against an escalation-delta test (does an actor holding ONLY
`system.write` gain a capability the gate did not already authorize, traced to an actual
human auth path) — all 5 held up, none collapsed.

## Links

- `docs/g80-raw-storage-bypass-triage.md` — full 58-row table, verdict + reach + evidence per candidate
- `docs/g80-raw-storage-bypass-enumeration.md` — reproducible candidate list + the 149→145/59→58 discrepancy resolution
- `docs/g80-raw-storage-bypass-blind-spots.md` — five categories this guard's scope doesn't cover
- `server/http/raw_storage_bypass_guard_test.go` — now blocks new instances; existing 36 grandfathered

---

## Liveness sweep (2026-08-24) — the answer to "how much work remains"

After Group A (4 handlers fixed) and the ADR-083/config fix above, the remaining 33
unfixed `/system` proxy routes were swept for real callers — same method that produced
the original G80 severity correction and settled #1545. For each route's storage
primitive, traced every real caller of the `internal/core` method wrapping it:
`internal/cli` commands (direct grep for `service.MethodName(...)`), then every one of
`server/main.go`'s 17 schedulers (enumerated in full — see the `validateRemoteStorageNotServer`
commit above).

**Three buckets, now two after the config fix:**

- **10 live-caller** — a real CLI command exercises the underlying core method today.
  Per-command `NewRemoteClient` check (does the CLI branch to a direct REST call in
  `keyorix connect` mode, bypassing the proxy entirely — the exact mistake the original
  G80 severity correction caught):
  - **5 confirmed solid — no bypass, the proxy fix protects a real path in both embedded
    and connected mode:** `CreateAccessRequestProxy`, `UpdateAccessRequestProxy`,
    `CreateInvitationProxy`, `UpdateInvitationProxy`, `UpdateUserIfActiveStateMatchesProxy`.
    These CLI commands have no `common.NewRemoteClient()` branch for the underlying
    operation — connected mode goes through the same `/system` proxy path as embedded
    mode. Fix as originally planned.
  - **5 narrower — connected-mode traffic bypasses the proxy; the fix only protects the
    embedded/direct-`storage.type:remote` case:** `CreateMachineIdentityProxy`,
    `CreateMachineIdentityCredentialProxy`, `RevokeMachineIdentityCredentialProxy`,
    `CreateOIDCBindingProxy`, `DeleteOIDCBindingProxy`. Their CLI commands check
    `common.NewRemoteClient()` first and, when connected, call a human-facing REST route
    directly — the same shape the original G80 correction found for several of the first
    59 candidates. A ceiling fix on these proxy handlers is still worth doing (it closes
    the embedded-mode / non-CLI-client path, and matches every other Tier 1/2 fix's
    reasoning), but the severity write-up should say explicitly that connected-mode CLI
    usage is not what makes these worth fixing.
  - **Net: fix all 10.** The narrower 5 aren't false positives — they're real bypasses
    with a smaller reachable surface than the solid 5, not zero surface.
- **~~5 uncertain~~ → moved to no-caller.** `DeleteAnomalyAlertsBeforeProxy`,
  `DeleteClosedAccessReviewsBeforeProxy`, `DeleteExpiredBreakGlassBeforeProxy`,
  `DeleteResolvedAccessRequestsBeforeProxy` (all via the `data_retention` scheduler) and
  `UpdateDynamicSecretLeaseProxy` (via `dynamic_secret_sweep`'s `RevokeExpiredLeases`)
  were reachable ONLY through a scheduler, and only because `validateRemoteStorageNotServer`
  had a gap letting `storage.type: remote` boot with schedulers running. That gap is now
  closed (unconditional rejection, not just enumerated flags — 3 of the 17 schedulers have
  no enable flag at all and would have kept the gap open under a flag-enumeration fix).
  With that closed, these 5 have no live caller anywhere: CLI never called them, and the
  only theoretical scheduler path is now boot-rejected. **Moved to the no-caller bucket.**
- **23 no-caller-found** (18 original + 5 moved) — no CLI command, no scheduler, no other
  in-repo consumer. Recommended remedy: **deletion, not a ceiling fix.** A privileged route
  with no caller is attack surface with no benefit; deleting it needs no test, no
  maintenance, and cannot be bypassed later by a future bug in a ceiling check.

  **Reference check complete — zero of the 23 are referenced as planned work.** Checked:
  - `docs/` (repo-wide, excluding this campaign's own `g80-*`/`adr-085` files): all 23
    literal handler names, zero matches. The 5 moved-from-uncertain names, zero matches.
  - Branches with plausible topical relevance by name — `rescope-adr-085` (no diff at all
    against `main` under `server/http/handlers/`), `remotes/origin/adr-085-node-credential-permission-scope`
    (touches only `docs/adr-085-node-credential-permission-scope.md` itself, an earlier
    draft of the doc already in this worktree — no handler code), and
    `remotes/origin-tmp/security-hardening-backlog` (a 10,000+ line backlog file — grepped
    `BUGS.md`, `HARDENING-BACKLOG.md`, `FIX-PRIORITY-BRIEF-437-471.md` for all 23 names:
    zero matches). That branch does mention `RevokeLease`/`RevokeLeasesForConfig` (11 hits)
    and `PurgeExpiredComplianceRecords` (2 hits), but read in context these are about a
    retry/status-handling bug in the *core* lease-revocation logic
    (`internal/core/dynamic_secrets.go:246-343`) and general retention-function naming —
    not about `UpdateDynamicSecretLeaseProxy` or the `DeleteAnomalyAlertsBeforeProxy`
    family specifically. Not planned work on the routes in question.
  - Did not exhaustively check the ~650 other branches (mostly `backup/*` mirrors and old
    per-sprint coverage-blitz branches per `git log --all --not main -G` on a sample
    batch — all pre-`efc14d6a`, already-superseded historical work, not open threads).
    Diminishing returns past the topically-plausible candidates; flagging the limitation
    rather than claiming exhaustive coverage.

  **All 23 clear for deletion.** Standalone, clearly-labeled deletion PR (not mixed with
  fixes), removing their entries from `knownUnfixedRawStorageBypasses` and route
  registration together — prepared, not yet executed pending this report reaching you.

**One reconciliation flag before fixing:** Group B (see ADR-085) decided to restrict the
WebAuthn trio (`CreateWebAuthnCredentialProxy`, `DeleteWebAuthnCredentialProxy`,
`SetUserWebAuthnEnabledProxy`) and `CreateMFAStepUpGrantProxy` to hub-only, reasoning that
proof-of-possession can't be relayed spoke-to-hub. The liveness sweep now shows these 4
have **zero live callers at all** — not "hub-only," genuinely no CLI command or other
in-repo consumer reaches them, so they sit in the 23-item no-caller/delete bucket, not the
10-item live-caller/fix bucket. Group B's premise ("restrict to the hub, since spoke
relay can't work") assumed a live hub caller worth preserving; if there is no live caller
at all, hub-restriction is moot and deletion is the more consistent remedy — same logic
as the other 23. Recommendation: fold these 4 into the deletion batch rather than
implementing a hub-restriction fix for a route nothing calls; note in ADR-085 that the
spoke-relay concern is now moot because the routes have no caller in either topology, not
because of the restriction that was designed for them.

**Final number: 10 handlers actually need a ceiling fix** (the 5 solid + 5 narrower
live-caller handlers above) — down from 33, and down from the original 58. 4 more
(the WebAuthn trio + `CreateMFAStepUpGrantProxy`) move from "planned hub-restriction fix"
to "delete" per the reconciliation above, making the no-caller/delete bucket 23 as
enumerated (they were already counted there by the liveness sweep — this just confirms
Group B's fix plan for them is superseded, not that the bucket count changes).

### New issue to file (separate from the main tracking issue above): ADR-083 scheduler gap

**Title**: `validateRemoteStorageNotServer` didn't cover scheduler-only server processes — closed

**Body**:

`internal/config.Config.Validate()`'s `validateRemoteStorageNotServer` (ADR-083's
enforcement) only rejected `storage.type: remote` when `server.http.enabled` or
`server.grpc.enabled` was true. But `server/main.go`'s `startSchedulers` (main.go:157)
runs unconditionally on every boot of the server binary, independent of both flags —
`#G12`'s own doc comment: "starting the loop in every process (regardless of which
transport it serves) is the existing, intended coordination model." A `storage.type:
remote` server with both HTTP and gRPC disabled — a "scheduler-only worker" — passed
validation and would run background jobs (`data_retention`, `dynamic_secret_sweep`, and
14 others) against a `RemoteStorage`-backed core. Three schedulers
(`anomaly_detection`, `login_attempt_prune`, `mfa_stepup_grant_prune`) have no enable
flag at all — they always run — so this wasn't closeable by enumerating `cfg.X.Enabled`
checks; a future scheduler addition would silently reopen the same gap.

Fixed by making the rejection unconditional rather than flag-dependent, verified safe by
confirming `Config.Validate()` has zero callers anywhere under `internal/cli` (the CLI's
own connected-mode validates a distinct, narrower `internal/storage/remote.Config`) — this
function is only ever reached from `server/main.go`'s own boot path, so there's no
legitimate caller the stricter check could break. Fixed in `internal/config/config.go`
(commit `e98141b7`, branch `fix-1524-machine-actor-fail-closed`). Also closed 5 of the
G80 raw-storage-bypass campaign's 33 unfixed `/system` proxy findings, whose only
remaining theoretical caller was exactly this now-rejected scheduler-only shape — see
`docs/g80-tracking-issue-draft.md`'s liveness sweep section for detail.

References: ADR-083, the G80 raw-storage-bypass campaign (issue #1547 and this
tracking issue).

---

## Filing status

**NOT FILED — not urgent, this doc is the tracking artifact until it is.**
`gh auth refresh -h github.com` requires an interactive device-flow authorization (visit
a URL, enter a code) that can't be completed by an unsupervised session. File whenever the
device flow is convenient, no rush: `! gh auth refresh -h github.com`, then
`gh issue create` with this file's title/body (strip this "Filing status" section first).

Same content also works as a comment on issue #1547 (the "one architectural property, not
a count" framing above) — `gh issue comment 1547` with the same body once filed.
