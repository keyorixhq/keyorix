- **INV-CORE-secret-owner-mutation-needs-gate-permission** Ownership alone never authorizes
  a secret update, delete, tag change, description change or move in core.
  `UpdateSecretWithPermissionCheck`, `DeleteSecretWithPermissionCheck`, `SetSecretTags`,
  `SetSecretDescription` and `MoveSecret` (the last three through `enforceSecretWriteGate`) re-check an owner-sourced grant with `AuthorizeSecretAction`
  for the permission the per-secret route/RPC gate names (`secrets.write` with the update's
  `SecretAction`, `secrets.delete`), through `requireOwnerHoldsGatePermission`; a refusal is typed
  (`ErrPermissionDenied`, or the share refusal when a share covers the permission but not the
  action). A grant from a share, ACL or role is already that gate's decision and is not re-checked.
  Why: #4160 (authzdiff known-03: viewer-owned secret, core allowed, REST and gRPC refused). Guard:
  `server/authzdiff/core_owner_gate_test.go` (`TestCoreOwnerWithoutPermissionIsRefused`, red before
  #4160) and the strict authzdiff sweep (no waiver absorbs the shape any more); tags, description
  and move (#4508): `internal/core` `TestOwnerWithoutSecretsWrite_CannotSetTagsDescriptionOrMove`
  and the same authzdiff test, which runs `secret.tags`, `secret.description` and `secret.move`
  as the viewer-owner (red on the pre-#4508 core: core allowed, REST refused; the strict sweep
  had not flagged that case).
  **Not covered**: other owner-gated core paths (share, ownership transfer, ACL grant) keep their
  own owner rules; and the project-scope bulk ops `BulkRenameSecrets`,
  `SuspendProjectSecretsWithOptions`, `ResumeProjectSecrets` and `ExtendExpiringSecrets`, whose
  per-item core decision is still `EnforceSecretWritePermission` (owner pass alone). Their REST
  gate is project-scope `secrets.write`, so only a direct core caller is affected (found by
  SECURITY-WAVE1-REVIEW, 2026-11-20; follow-up, not fixed here).
