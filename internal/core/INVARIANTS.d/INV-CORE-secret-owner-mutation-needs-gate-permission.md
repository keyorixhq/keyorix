- **INV-CORE-secret-owner-mutation-needs-gate-permission** Ownership alone never authorizes
  a secret update or delete in core. `UpdateSecretWithPermissionCheck` and
  `DeleteSecretWithPermissionCheck` re-check an owner-sourced grant with `AuthorizeSecretAction`
  for the permission the per-secret route/RPC gate names (`secrets.write` with the update's
  `SecretAction`, `secrets.delete`), through `requireOwnerHoldsGatePermission`; a refusal is typed
  (`ErrPermissionDenied`, or the share refusal when a share covers the permission but not the
  action). A grant from a share, ACL or role is already that gate's decision and is not re-checked.
  Why: #4160 (authzdiff known-03: viewer-owned secret, core allowed, REST and gRPC refused). Guard:
  `server/authzdiff/core_owner_gate_test.go` (`TestCoreOwnerWithoutPermissionIsRefused`, red before
  #4160) and the strict authzdiff sweep (no waiver absorbs the shape any more). **Not covered**:
  other owner-gated core paths (share, ownership transfer, ACL grant) keep their own owner rules;
  this invariant is about update and delete only.
