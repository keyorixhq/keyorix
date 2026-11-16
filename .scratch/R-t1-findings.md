# Review R-t1 — Machine-token issuance path (`IssueMachineToken`)

Target: `internal/core/machine_token.go` (`IssueMachineToken` + privilege ceiling),
HTTP caller `server/http/handlers/machine_identities.go`, gRPC caller
`server/grpc/services/machine_identity_service.go`, plus the ceiling itself in
`internal/core/authz.go` (`requireMachinePrivilegeCeiling`,
`requireActorHoldsTargetPermissions`, the self-machine-granter context plumbing).

## Verdict

I could not construct a working privilege-escalation or access-denial exploit on
this path. The ceiling is derived from the *actor's* own effective privileges
(not just the target's), both transports gate the route on `roles.assign` and
set the self-machine-granter + caller-credential tags symmetrically, the
impersonation block exists on both transports, and every storage-lookup failure
in the ceiling fails closed (unwrapped error → `Internal`/500, never read as
"not admin"). What follows is one real asymmetry worth recording and several
claims I disproved-attempts on that held up.

---

## Finding 1 — Admin-tier detection is deliberately asymmetric between user and machine actors (EXPECTED-DIFFERENCE / HARDENING)

**Classification:** EXPECTED-DIFFERENCE (verified safe), noted because the
asymmetry is the sort of thing a future edit could "unify" and break.

**File:** `internal/core/authz.go:677-699` (inside `requireMachinePrivilegeCeiling`).

**The claim under test:** the doc comment (authz.go:640-662) says a non-admin
actor cannot mint a token for a machine that holds admin-tier roles. The
extended admin-tier test — canonical admin *name* (`isAdminRoleName`) OR
administrative *bundle* (`roleIsAdminTier`), not just the structural
`bypasses_permission_checks` flag — is gated on `actorType == ActorTypeMachine`
(line 677). For a **user** actor, only `roleSetContainsAdmin` (the bypass flag)
feeds the `containsAdmin` branch.

**Why it is NOT exploitable for a user actor:** when `containsAdmin` is false,
the code falls through to `requireActorHoldsTargetPermissions(ActorTypeUser, …)`
(line 731), which requires the user to already hold *every* permission the
target's roles bundle, at each scope. A custom "project_admin"-named role with
real admin permissions but no bypass flag is therefore caught by the bundled-
permission check; a name-only role with zero permission rows confers nothing, so
minting a token for it is no escalation. The machine-only extra check exists
because a machine can *never* be a global admin (ADR-030), so for a machine actor
"deny" is the only safe answer and the detection has to be maximal. The
asymmetry is correct as written.

**Trigger considered:** user U with `roles.assign` at project P (not global
admin) → `POST /projects/{P}/machine-identities/{M2}/tokens` where M2 holds a
custom admin-named role. Result: refused by the target-permission check unless U
already holds those permissions. No escalation.

**Reachability:** live — `server/http/router.go:619`
(`RequireScopedPermission(roles.assign)` + handler at machine_identities.go:245)
and `MachineIdentityService/IssueMachineToken`.

**Confidence:** HIGH (safe as-is; flagged only as a maintenance hazard).

---

## Finding 2 — gRPC `IssueMachineToken` silently drops `AllowedCIDRs` and `ReplaceCredentialID` (EXPECTED-DIFFERENCE)

**Classification:** EXPECTED-DIFFERENCE (feature gap, not a security defect).

**File:** `server/grpc/services/machine_identity_service.go:167-171` vs the HTTP
handler passing both `AllowedCIDRs` and `ReplaceCredentialID`
(machine_identities.go:284-290).

The gRPC request type carries no CIDR / replace fields, so a token minted over
gRPC is unrestricted (the default) and gRPC cannot do atomic rotation. This
weakens nothing that the HTTP path guaranteed — the default minted token is
already unrestricted on both transports, and the ceiling/auth checks are
identical. Noted only for parity-tracking. **Confidence:** HIGH.

---

## Claims I tried to disprove and could not (all held up)

- **"The ceiling is evaluated for the real caller; a machine caller has actorID 0
  and is identified by the self-granter tag"** (machine_token.go:188-203). If the
  self-granter tag is absent, `ceilingType` stays `ActorTypeUser` with
  `actorID==0`; `requireMachinePrivilegeCeiling(user, 0, …)` then fails
  `AuthorizePrincipal(user 0, roles.assign)` closed. Both transports set the tag
  only when `ActorKind()==machine`, and no live caller sets the system-proxy
  relay tag that would suppress it (grep: only tests/definition reference
  `WithSystemProxyMachineGranter`). Fail-closed confirmed.

- **`requireMachineCallerMayIssue` (machine_token.go:152-174):** refuses
  self-issuance (`callerID==targetID`), refuses a federated/unidentified
  credential, re-reads the caller credential from storage and refuses it if it
  does not belong to the caller, is revoked, or has a CIDR allowlist. The CIDR
  check reads storage, not the cached request identity, so a restriction added
  since login applies. No bypass found.

- **PAT-restricted user minting (machine_token.go:210-212):** a restricted PAT is
  refused before the ceiling; `IsGlobalAdmin` also returns false under a PAT
  restriction (authz.go:374). Double-covered.

- **Cross-project / cross-machine reach:** `machineInProject` (machine_token.go:64)
  verifies `m.ProjectID == projectID` and reports a mismatch as not-found;
  `validateReplacementCredential` (line 92) confirms the replaced credential
  belongs to the same machine. The ceiling uses the path project, which equals
  the machine's project by that check. No cross-tenant path.

- **Fail-closed on lookup errors:** every storage error in
  `requireMachinePrivilegeCeiling` / `requireActorHoldsTargetPermissions` is
  returned unwrapped (no sentinel) → `errclass.Internal` → 500, never read as
  "not admin" / "no permissions". `sendMachineRefusal` only maps the typed
  `ErrMachinePrivilegeCeilingDenied` to 403.

- **Impersonation block parity:** HTTP route has `BlockWhenImpersonating`
  (router.go:619); gRPC lists `IssueMachineToken` in `credentialMintingMethods`
  (interceptors/auth.go:181). Both refuse minting while impersonating.

- **Rotation (`rotateMachineToken`, machine_token.go:285):** revoke-then-issue
  with the old credential evicted from cache before the owed audit row; a
  commit-2 failure leaves the old one revoked and answers `PartialMutationError`
  (503). No overlap window, no unaudited credential. Not a security defect.

## Bottom line

No VULNERABILITY or SECURITY-DEFECT found. The one structural asymmetry
(Finding 1) is intentional and safe; Finding 2 is a feature gap. The ceiling
correctly derives authority from the actor, not only the target — the exact
class of bug CLAUDE.md warns about ("a ceiling that inspects only the target is
not a ceiling") is specifically guarded against here.
