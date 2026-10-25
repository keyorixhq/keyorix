- **INV-CORE-identity-names-validated-at-write-only** A username or role name is checked
  against the name rule only where it is chosen: user create (`validateCreateUserRequest`,
  reached by admin REST/gRPC create, setup-link and one-time-password create, invitation
  acceptance and `BootstrapSystem`), user rename (`UpdateUser`, only when the name actually
  changes) and `CreateRole`. Usernames: `validateUsernameCharset` (ASCII `[A-Za-z0-9 ._@+-]`,
  no edge or repeated whitespace); role names: `validateIdentifier`. Login, session and token
  validation, `GetUserByUsername` and `GetRoleByName` never apply it, so an account or role
  stored before the rule keeps working. SCIM and SSO/SAML JIT never pass an IdP string to it:
  `deriveSCIMUsername` normalizes to `[a-z0-9]` first, so a non-ASCII IdP name provisions
  rather than fails. `identity.NewFoldedName` and the `*_folded` columns are unchanged (ask
  identity-fold-space-width (b): no re-key migration).
  Why: IDENTITY-FOLD-SPACE-WIDTH — "admin"/"ａｄｍｉｎ", "ad min"/"ad min", "admin"/"admin "
  folded to different keys and were accepted as different principals.
  Guard: `internal/core/identity_name_validation_test.go` (`TestCreateUserPaths_RejectSpoofedUsernames`,
  `TestUpdateUser_RenameRejectsSpoofedUsernames`, `TestBootstrapSystem_RejectsSpoofedAdminUsername`,
  `TestCreateRole_RejectsSpoofedRoleNames`, `TestLegacyStoredUsernameFailingRule_KeepsWorking`,
  `TestLegacyStoredRoleNameFailingRule_KeepsWorking`, `TestProvisionSCIMUser_NonASCIIUserNameProvisions`,
  `TestProvisionSSOUser_NonASCIIEmailProvisions`).
  **Not covered**: SCIM group displayNames and group names (not in this rule's scope); a new
  user-creating path that builds `models.User` itself instead of going through
  `buildUserForCreate` or `deriveSCIMUsername` is not detected by any static guard.
