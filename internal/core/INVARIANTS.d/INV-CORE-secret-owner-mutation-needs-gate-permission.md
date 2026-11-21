- **INV-CORE-secret-owner-mutation-needs-gate-permission** Ownership alone never authorizes
  a secret update, delete, tag change, description change or move in core, nor a secret's
  part in a project-scope bulk rename, suspend, resume or expiry extension.
  `UpdateSecretWithPermissionCheck`, `DeleteSecretWithPermissionCheck`, `SetSecretTags`,
  `SetSecretDescription`, `MoveSecret`, and per secret `BulkRenameSecrets`,
  `SuspendProjectSecretsWithOptions`, `ResumeProjectSecrets` and `ExtendExpiringSecrets` (all
  but the first two through `enforceSecretWriteGate`) re-check an owner-sourced grant with `AuthorizeSecretAction`
  for the permission the per-secret route/RPC gate names (`secrets.write` with the update's
  `SecretAction`, `secrets.delete`), through `requireOwnerHoldsGatePermission`; a refusal is typed
  (`ErrPermissionDenied`, or the share refusal when a share covers the permission but not the
  action). A grant from a share, ACL or role is already that gate's decision and is not re-checked.
  Why: #4160 (authzdiff known-03: viewer-owned secret, core allowed, REST and gRPC refused). Guard:
  `server/authzdiff/core_owner_gate_test.go` (`TestCoreOwnerWithoutPermissionIsRefused`, red before
  #4160) and the strict authzdiff sweep (no waiver absorbs the shape any more); tags, description
  and move (#4508): `internal/core` `TestOwnerWithoutSecretsWrite_CannotSetTagsDescriptionOrMove`;
  the four bulk ops (CORE-AUTHZ-RACE-NOV-1 item 2, the #4508 sibling SECURITY-WAVE1-REVIEW
  found on 2026-11-20): `TestOwnerWithoutSecretsWrite_BulkOpsSkipTheirSecrets` (a viewer who
  owns every secret in the project renames, suspends, resumes and extends nothing; the
  developer owner acts on all of them). In a bulk op the refusal is a per-secret SKIP, as every
  other per-secret refusal there is, so the op's count is of the secrets the actor may actually
  affect and a viewer-owner gets zero. **Not covered**: other owner-gated core paths (share,
  ownership transfer, ACL grant) keep their own owner rules.
