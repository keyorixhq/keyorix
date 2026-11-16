- **INV-CORE-sso-scim-external-identity-folded-at-boundary** Every SSO/SCIM path that
  maps an EXTERNAL identifier to a Keyorix principal or account-link folds it through
  `identity.NewFoldedName` with the SAME fold storage uses, so the NFC-not-NFKC decision
  (keyorix#4335, fuzz-corpus#112) cannot be bypassed at a provider boundary. Concretely:
  JIT/SCIM provisioning folds username+email at the insert (`provisionSSOUser`
  `sso.go`, `ProvisionSCIMUser`/`scimUpdateUserTx` `scim.go`, SCIM group displayName
  `scim_groups.go`); every email/username LOOKUP goes through
  `LocalStorage.GetUserByEmail`/`GetUserByUsername`, which fold the lookup key the same
  way and treat an un-normalizable key as not-found; `GetUserByExternalID` is an exact
  match on an opaque address (subject/externalId), correctly NOT folded. Account linking
  by email (`resolveSSOUser`) can claim an EXISTING account only when the email is
  EXPLICITLY verified — OIDC `email_verified==true`, or a SAML provider's
  `TrustAssertedEmail` opt-in (off by default) — so an unverified or merely-asserted
  email never links to a local account, and a verified confusable (fullwidth/Cyrillic)
  email folds to a DISTINCT key and cannot take over the victim (NFC, not NFKC).
  Why: IDENTITY-FOLD-SPACE-WIDTH / NFC-not-NFKC — a confusable external identifier that
  folded to a victim's key would be account takeover; NFKC would have merged them.
  Guard: `internal/core/identity_boundary_sso_scim_sweep_test.go`
  (`TestIdentityBoundary_UserLookupFold_NoConfusableMerge` over the confusable corpus —
  fullwidth, ligature, roman numeral, circled digit, NBSP/ZWSP/ZWJ, Turkish dotted/
  dotless i, NFC-vs-NFD, Cyrillic homograph, case, email plus-tag/dot — and
  `TestIdentityBoundary_ResolveSSOUser_EmailLinkGate` for the email-verified link gate),
  plus existing `TestProvisionSSOUser_NonASCIIEmailProvisions`,
  `TestProvisionSCIMUser_NonASCIIUserNameProvisions`, and
  `TestNewFoldedName_CompatibilityFormsAreDistinctPrincipals` (internal/identity).
  **Not covered**: SSO native-group-name matching (`applySSOGroupReconcile`) and
  `GroupRoleMap` key matching (`buildSSORoleMaps`) are RAW exact byte matches, NOT folded
  — a deliberate, fail-closed exception: an exact match is the narrowest possible, so a
  normalization mismatch only ever fails-to-grant or removes (de-escalating), never
  over-grants, and the admin-conferring backstop is keyed on the resolved group/role ID,
  not the asserted name. `domainAllowed` compares with `strings.ToLower`, not the NFC
  fold (fail-closed allowlist, not a principal-link). The HTTP transport (SAML/OIDC/SCIM
  parsing) and the RemoteStorage proxy are not exercised by this guard.
