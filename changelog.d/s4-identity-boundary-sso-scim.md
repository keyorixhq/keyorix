### Security
- **Verified the SSO/SCIM identity boundary against confusable account takeover.** Swept
  every place a SAML/OIDC/SCIM identifier becomes a principal, group key, or
  account-link and confirmed each folds or rejects confusables with the same NFC fold
  storage uses (keyorix#4335, fuzz-corpus#112). The account-linking-by-email path links
  an existing account only on an explicitly verified email (OIDC `email_verified`, or a
  SAML provider's `TrustAssertedEmail` opt-in), so an unverified or confusable
  (fullwidth/Cyrillic) email cannot take over a local account. No runtime change: a
  table-driven probe and an INVARIANTS entry pin the behaviour.

### Testing
- Added `internal/core/identity_boundary_sso_scim_sweep_test.go`, driving the full
  confusable corpus (fullwidth, ligature, roman numeral, circled digit, NBSP/ZWSP/ZWJ,
  Turkish dotted/dotless i, NFC-vs-NFD, Cyrillic homograph, case, email plus-tag/dot)
  through the real `GetUserByEmail`/`GetUserByUsername`/`resolveSSOUser` boundary.
