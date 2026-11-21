- **INV-CORE-route-gates-decided-in-core** Every core entry point the cross-layer
  differential binds as core-enforced decides the transports' route gate itself, from the
  actor the context identifies (`gateActor`: the tagged machine identity for a machine
  actor, `actorID` for a human; the internal pseudo-actor 0 stays exempt as in every other
  core ceiling). `requireScopedGate`/`requireScopedGates` are `RequirePermission` and
  `RequireScopedPermission` in core; `requireSecretActionGate` is
  `RequireScopedSecretPermission` (ACL, role, allowlisted share; no owner pass). Since
  #4161 (authzdiff waiver known-04) that holds for: `SetSecretAutoRotate`,
  `RotateSecretOnDemand`, `RollbackSecret` (secrets.write with the op's `SecretAction`),
  `CopySecret` (secrets.write at the target environment), `CloneEnvironment` and
  `CopyEnvironmentSecrets` (secrets.write on the project, secrets.read on the source
  environment), `UpdateRole`, `DeleteRole`, `AssignPermissionToRole` (roles.read +
  roles.write, global; `UpdateRole` also requires the actor to hold every permission it
  grants), `RestoreGroup`, `AssignRoleToGroup`, `AddUserToGroup`, `SetUserRoles`
  (users.read + roles.assign, global), `CreateUserAudited` and `CreateUserWithAssignments`
  (users.read + users.write, global), `InviteGlobalWithLink` (users.write, global),
  `RestoreProject` (roles.assign at the project), `RevokeShare` (secrets.write at the
  secret's scope, in front of the owner-or-manager rule) and
  `BulkApproveAccessRequests`/`BulkRejectAccessRequests` (roles.assign, global, in front
  of the per-item check). Why: core allowed where every transport denied on about 4,500
  differential cases over these ops, so the transport was the only gate; a core entry
  point any caller can drive directly is an authorization layer only if it decides for
  itself. Guard: `TestCoreGateParity_RouteGatesDecidedInCore` (per op: a principal with a
  real grant short of the gate is refused with `ErrPermissionDenied`, an admitted one still
  succeeds; red before the gates), `TestCoreGateParity_InternalPseudoActorIsExempt`, and the
  strict differential sweep (`server/authzdiff`), whose known-04 waiver is narrowed to the
  four owner-pass ops still open (secret.tags, secret.description, secret.move: #4508;
  bulk.suspend: PR #4557 item 2), so a core-only over-allow anywhere else is
  `unexplained` and fails the sweep (the reassign-owner plant proves it). **Not covered**:
  the four narrowed ops until that waiver is removed, and ops the matrix classifies
  `transport-enforced` (core performs no authorization there by design, `MATRIX.md`).
