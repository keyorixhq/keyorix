/**
 * @name Security-state check-then-act without a compare-and-set
 * @description A function reads an entity by ID via a Get<Entity>(id)-shaped call,
 *              branches on one of that entity's security-state fields (a boolean
 *              toggle like Revoked/Approved/IsActive/Disabled, or a lifecycle
 *              State/Status/AccountState field on one of a specific list of
 *              security-sensitive entity types), and then persists the mutated
 *              entity back via an Update<Entity>(entity)-shaped call keyed only by
 *              the entity's ID -- a plain "WHERE id = ?" write with no precondition
 *              on the field just checked. Two callers racing this same
 *              read-modify-write window (an admin's revoke racing a holder's
 *              accept/approve, or a suspend racing a resume) can silently clobber
 *              each other: whichever write lands second wins outright, with no
 *              error surfaced to either caller -- including the one whose intended
 *              transition was just discarded.
 *
 *              This codebase's own fix for the same bug class elsewhere (#388,
 *              #412/#277, #306/#307) replaced the plain write with one of two
 *              patterns, both of which this query treats as safe: (1) a conditional
 *              "WHERE id = ? AND <field> = ?" persist that reports via an extra
 *              bool return whether the row actually matched (so the caller can
 *              detect and handle a lost race), or (2) a row-locked read -- a
 *              Lock<Entity>ForUpdate call instead of a plain Get, serializing the
 *              read against a concurrent writer for the lifetime of the
 *              transaction/mutex. A read via Lock<Entity>ForUpdate is naturally
 *              excluded here since it doesn't match the Get<Entity> shape this
 *              query looks for.
 * @kind problem
 * @problem.severity warning
 * @id go/keyorix-state-toctou-missing-cas
 * @tags security
 *       external/cwe/cwe-362
 *       external/cwe/cwe-367
 */

import go

/** The package declaring the storage-layer entity structs this query cares about. */
private string modelsPkg() { result = "github.com/keyorixhq/keyorix/internal/storage/models" }

/**
 * Holds if `f` is one of this codebase's named security-state fields.
 *
 * Generically-named boolean toggles (Revoked/IsRevoked/Locked/IsLocked/Active/
 * IsActive/Approved/IsApproved/Disabled) are matched on ANY declaring type --
 * confirmed against the real models (internal/storage/models/models.go) to be
 * specific enough on their own not to need type-scoping: e.g. RiskException.Revoked/
 * .Approved, User.IsActive, WebAuthnCredential.Disabled. (Locked/IsLocked do not
 * currently exist as literal field names anywhere in this codebase -- kept for
 * forward-compatibility, at zero current cost since they simply never match.)
 *
 * State/Status/AccountState, by contrast, are also used all over this codebase for
 * purely non-security bookkeeping (DriftStatus, RotationStatus,
 * AccessReviewCampaign.State, DynamicSecretLease.Status, SSOLoginState.State, ...),
 * so those three are scoped to the specific entity types where the field is
 * actually a security-lifecycle gate, per the real struct definitions:
 *   - State:        MachineIdentity, ProjectInvitation, AccessRequest,
 *                    BreakGlassActivation (pending/active/suspended/revoked-shaped
 *                    state machines)
 *   - Status:       SecretNode (active/suspended -- see internal/core/secret_suspend.go)
 *   - AccountState:  User (active/pending_first_login/password_reset_required/suspended)
 */
predicate isSecurityStateField(Field f) {
  f.getName().toLowerCase() =
    ["revoked", "isrevoked", "locked", "islocked", "active", "isactive", "approved",
      "isapproved", "disabled"]
  or
  f.hasQualifiedName(modelsPkg(),
    ["MachineIdentity", "ProjectInvitation", "AccessRequest", "BreakGlassActivation"], "State")
  or
  f.hasQualifiedName(modelsPkg(), "SecretNode", "Status")
  or
  f.hasQualifiedName(modelsPkg(), "User", "AccountState")
}

/** Holds if `call` is a plain by-ID point-read, shaped like storage.Storage's Get<Entity>(ctx, id) family. A row-locking Lock<Entity>ForUpdate read does not match this (different name), which is deliberate -- see the header doc. */
predicate isEntityGetCall(DataFlow::CallNode call) { call.getTarget().getName().matches("Get%") }

/** Holds if `call` is a plain by-ID write, shaped like storage.Storage's Update<Entity>(ctx, entity) family. */
predicate isEntityUpdateCall(DataFlow::CallNode call) {
  call.getTarget().getName().matches("Update%")
}

/**
 * Holds if `call`'s target function returns a bool among its results. This
 * codebase's established fix for this exact bug class converts the write into a
 * conditional "WHERE id = ? AND <field> = ?" persist that reports whether the row
 * actually matched -- UpdateProjectInvitation, UpdateAccessRequest,
 * UpdateAccessReviewItem, TransitionMachineIdentityState, and
 * AdvanceWebAuthnCredentialCounter all follow this shape (confirmed by reading
 * internal/core/storage/interface.go and the corresponding fix commits). A
 * bool-returning "Update"-named call is therefore treated as already CAS-safe.
 */
predicate returnsBool(DataFlow::CallNode call) {
  exists(int i | call.getTarget().getResultType(i).getUnderlyingType() instanceof BoolType)
}

/**
 * Explicit named blessed atomic-transition helpers for this exact bug class, kept
 * as documentation even though today every one of them is already excluded by
 * construction -- either it doesn't match the Update%-name filter at all
 * (RevokeBreakGlassActivation, CreateSecretDependencyExclusive), or it does and
 * also returns a bool (UpdateProjectInvitation, UpdateAccessRequest,
 * TransitionMachineIdentityState, AdvanceWebAuthnCredentialCounter). Listed
 * explicitly so a future rename that drops the bool return (but keeps the name)
 * doesn't silently re-admit one of these as a false positive.
 */
predicate isBlessedTransitionCall(DataFlow::CallNode call) {
  call.getTarget().getName() =
    ["TransitionMachineIdentityState", "AdvanceWebAuthnCredentialCounter",
      "RevokeBreakGlassActivation", "CreateSecretDependencyExclusive", "UpdateProjectInvitation",
      "UpdateAccessRequest"]
}

from
  DataFlow::CallNode getCall, DataFlow::CallNode updateCall, Field stateField,
  DataFlow::ReadNode fieldRead, DataFlow::Node entityBase
where
  isEntityGetCall(getCall) and
  isEntityUpdateCall(updateCall) and
  not returnsBool(updateCall) and
  not isBlessedTransitionCall(updateCall) and
  getCall.getEnclosingCallable() = updateCall.getEnclosingCallable() and
  isSecurityStateField(stateField) and
  fieldRead.readsField(entityBase, stateField) and
  // The read and write must be operating on the exact same entity object the Get
  // call returned -- not just any two Get.../Update... calls that happen to share
  // an enclosing function -- and the field check must sit between the read and the
  // write, matching the real check-then-act shape rather than a coincidental pair.
  DataFlow::localFlow(getCall.getResult(0), entityBase) and
  exists(int argIdx | DataFlow::localFlow(getCall.getResult(0), updateCall.getArgument(argIdx))) and
  getCall.asExpr().getLocation().getStartLine() <= fieldRead.asExpr().getLocation().getStartLine() and
  fieldRead.asExpr().getLocation().getStartLine() <= updateCall.asExpr().getLocation().getStartLine()
select updateCall,
  "This unconditional by-ID update persists a value read from the " + stateField.getName() +
    " field obtained via $@, with no compare-and-set guard on that field -- a concurrent transition racing this read-modify-write window can be silently lost.",
  getCall, "this plain by-ID read"
