# Identity boundary sweep — SSO and SCIM (task S4)

Date: 2026-11-15. Scope: every call site where an EXTERNALLY supplied string becomes
(a) a user principal, (b) a group name / group-to-role mapping key, or (c) an
account-linking key (match by email or username to an existing local account), for
SAML, OIDC/SSO, SCIM, invitation accept, setup/consume, and CLI import. LDAP: none in
this codebase (confirmed by grep — only `internal/fuzzutil/hostile` references the
word). CLI user-import: none (no CLI command maps an external identity to a principal;
confirmed by grep).

## Why this sweep exists

`internal/identity` folds identity-bearing strings with **NFC, not NFKC** (decision
2026-11-15, keyorix#4335, fuzz-corpus#112; see the package header "Why NFC and not
NFKC"). Consequence: the fullwidth form of "admin" and ASCII "admin" are DIFFERENT
principals, and compatibility forms (ligatures, roman numerals, circled digits,
trailing space) are accepted by the permissive FoldedName profile as distinct. That
is only safe if every place that maps an external identifier to a principal folds or
rejects confusable forms at its own boundary *before* it calls `internal/identity`.

## The load-bearing fact

The fold is applied UNIFORMLY at the storage lookup boundary, so SSO/SCIM paths that
pass a raw external string to a storage lookup still get the same fold as write time:

- `LocalStorage.GetUserByEmail` (`internal/storage/store/local_users.go:163`) and
  `GetUserByUsername` (`:191`) BOTH run the lookup key through
  `identity.NewFoldedName` and compare against the stored `email_folded` /
  `username_folded` column — the same fold used at write time, on both backends (not a
  SQL-side `LOWER`, which diverges SQLite vs Postgres; #1642). An un-normalizable key
  (control/bidi) is treated as **not-found**, never surfaced as a lookup error.
- `GetUserByExternalID` (`:209`) is an exact string match on an opaque address, which
  is correct: a subject / externalId is an address, not a human-verified identity.

## Legend

- **Fold-before-lookup**: what normalizes/rejects the external string before the
  principal/group/link decision (function:line).
- **Same folding?**: whether the lookup and the stored key use the same fold.
- **Verdict**: ENFORCED / GAP / DOCUMENTED EXCEPTION.

## (a) External string → user principal

| # | Site | External field | Fold-before-lookup | Same folding? | Test | Verdict |
|---|------|----------------|--------------------|---------------|------|---------|
| a1 | `provisionSSOUser` JIT create (`internal/core/sso.go:742`) | OIDC/SAML email, derived username | `identity.NewFoldedName(username)` + `NewFoldedName(email)` (`sso.go:780,784`); username via `deriveSCIMUsername` (ASCII `[a-z0-9]`) | yes — folded cols written from same fold | `TestProvisionSSOUser_NonASCIIEmailProvisions` (existing); `TestIdentityBoundary_*` (new) | ENFORCED |
| a2 | `ProvisionSCIMUser` (`internal/core/scim.go:114`) | SCIM `userName`, `email`, `displayName` | `NewFoldedName(username)` + `NewFoldedName(email)` (`scim.go:167,171`); reserved `sso:` scheme refused (`:125`); domain allowlist (`:132`) | yes | `TestProvisionSCIMUser_NonASCIIUserNameProvisions` (existing) | ENFORCED |
| a3 | `scimUpdateUserTx` email change (`internal/core/scim.go:489`) | SCIM `email` | `NewFoldedName(*email)` keeps `EmailFolded` in lockstep (`scim.go:509`) | yes | existing SCIM update tests | ENFORCED |
| a4 | admin / CLI create `buildUserForCreate` (`internal/core/users.go:99`) | admin-supplied username/email | `NewFoldedName` → `UsernameFolded`/`EmailFolded` (`users.go:163,165`) + `validateUsernameCharset` | yes | `identity_name_validation_test.go` (existing) | ENFORCED |
| a5 | `deriveSCIMUsername` (`internal/core/scim.go:47`) | SCIM/SSO userName/email local-part | `strings.ToLower` + strip to `[a-z0-9]`; uniqueness via `GetUserByUsername` (folded) | n/a (ASCII derivation; dedup folds) | existing | ENFORCED |

## (b) External string → group name / group-to-role mapping key

| # | Site | External field | Matching | Verdict |
|---|------|----------------|----------|---------|
| b1 | SSO native group sync `applySSOGroupReconcile` (`internal/core/sso.go:1050`) | OIDC groups claim / SAML groups attr | RAW exact, case-sensitive: `assertedSet[g.Name]` against the native group **display** `Name` (NOT `NewFoldedName`, NOT `name_folded`) | DOCUMENTED EXCEPTION |
| b2 | SSO role mapping `buildSSORoleMaps` (`internal/core/sso.go:1273`) | OIDC/SAML asserted group strings | RAW exact: `assertedSet[group]` against admin-configured `GroupRoleMap` keys | DOCUMENTED EXCEPTION |
| b3 | SCIM group provision/rename `ProvisionSCIMGroup`/`Replace`/`Patch` (`scim_groups.go:176,238,335`) | SCIM `displayName` | `NewFoldedName(displayName)` → `NameFolded` (`scim_groups.go:194,252,346`) | ENFORCED |
| b4 | SCIM group membership (`scim_groups.go` add/remove) | SCIM member `value` (numeric id) | numeric id, filtered through `scimManagedMember` (scimOwned) — not an identity string | ENFORCED (N/A to fold) |

**b1/b2 assessment (DOCUMENTED EXCEPTION, not a vulnerability).** The match is exact
byte equality — the narrowest possible match — so a normalization mismatch can only
FAIL to add a membership/grant or CAUSE a removal; both are de-escalating. It can never
OVER-grant, because no confusable widens an exact match. The admin-conferring backstop
(`idpGroupConfersAdminVerdict` / `idpAutoGrantEscalationVerdict`,
`reconcileSSOGroupAdditions` `sso.go:1110`, `applySSOManagedRole` `sso.go:1307`,
`refuseAddToAdminGroup` `scim_groups.go:542`) is keyed on the RESOLVED group/role **ID**,
not on the asserted name, so no confusable name can slip past it. Removals route through
`RemoveUserFromGroupGlobal` with the last-admin guards (`sso.go:1165`). The correctness
cost of the exactness (an IdP asserting a case/width variant of a native group name
silently fails to sync that group) is an availability/footgun, not an escalation.

## (c) Account-linking key (email/username → existing local account) — HIGHEST RISK

| # | Site | External field | Gate before link | Same folding? | Verdict |
|---|------|----------------|------------------|---------------|---------|
| c1 | `resolveSSOUser` email fallback (`internal/core/sso.go:594`) | OIDC `email` + `email_verified`; SAML asserted email + `TrustAssertedEmail` | `email == "" \|\| !emailVerified → return nil` (`sso.go:602`); `GetUserByEmail` folds (`:605`); `ssoBoundToOtherProvider` cross-provider guard (`:612`) | yes (GetUserByEmail folds) | ENFORCED |
| c2 | `verifyIDToken` email_verified extraction (`sso.go:1407`) | OIDC `email_verified` claim | `emailVerified = claim present AND true` (`sso.go:1492`); email dropped if claim present-and-false (`:1486`) | n/a | ENFORCED |
| c3 | `CompleteSAML` (`sso.go:401`) | SAML asserted email | passes `p.TrustAssertedEmail` (OFF by default) as the "verified" flag, both to `resolveSSOUser` and to `provisionSSOUser`'s race re-check (`sso.go:431,446`) | yes | ENFORCED |
| c4 | `FindSCIMUser` (`internal/core/scim.go:93`) | SCIM `externalId`, `email` | externalId exact; email via `GetUserByEmail` (folds) | yes | ENFORCED |
| c5 | `checkSCIMEmailCollision` (`scim.go:469`) | SCIM `email` | `GetUserByEmail` (folds); `scimOwned` gate runs first (`scim.go:311`) | yes | ENFORCED |
| c6 | setup-token `SubjectEmail` (`internal/core/setup_token.go:133`) | email bound to a setup/invite token | `strings.TrimSpace(strings.ToLower(...))` — used only as the `(purpose,email)` SUPERSEDE/dedup key; the account linkage is by `SubjectUserID` (numeric), not by this string | n/a (not an identity-link key) | ENFORCED (not a link key) |
| c7 | `domainAllowed` (`internal/core/membership_lifecycle.go:105`) | email domain (install-wide allowlist, ADR-022) | `strings.Cut(email,"@")`, require exactly one `@`, `strings.ToLower` domain compare | fail-closed; not a principal-link | ENFORCED (see note) |

### c1/c2/c3 — the account-takeover-by-confusable question, stated plainly

- **Unverified email can never link to an existing local account.** OIDC
  `email_verified` is honoured: `resolveSSOUser` returns `(nil,nil)` for an
  unverified/absent-verified email, so the caller JIT-provisions a NEW account
  (nothing to take over) instead of claiming the existing one. SAML has no
  per-assertion `email_verified`; the substitute is the provider opt-in
  `TrustAssertedEmail` (OFF by default), closing the SAML-specific #89 takeover.
- **A verified confusable email still cannot take over.** NFC (not NFKC) folds a
  Cyrillic-homograph / fullwidth email to a DISTINCT key, so even a verified
  attacker-controlled confusable does not collide with the victim's folded email.
  NFKC would have merged them — this is precisely why NFC is safer here.
- **What `email_verified` does:** present-and-false drops the email entirely
  (`sso.go:1486`); present-and-true is the only state that lets the email claim an
  existing account; absent is treated as "trusted for JIT of a NEW account" but NOT
  for claiming an existing one (`emailVerified` stays false). Cross-provider claim of
  an already-federated account is additionally blocked by `ssoBoundToOtherProvider`.

### c7 note (`domainAllowed`)

Cuts on the FIRST ASCII `@`, rejects multi-`@` (#G46), and lowercases the domain with
`strings.ToLower` (not `NewFoldedName`). This is an allowlist check against
admin-configured ASCII domains, not a principal-link; it is fail-closed (a fullwidth
`＠`, an un-normalizable domain, or any confusable domain does not equal an ASCII
allowlist entry, so it is rejected). A confusable cannot BYPASS the allowlist because a
match requires byte-equality to an admin-configured ASCII entry after `ToLower`.

## Reachability (live caller vs admin vs malicious-IdP)

| Row | Reachable by | Notes |
|-----|--------------|-------|
| a1, c1, c2 | unauthenticated browser → `/auth/sso/{provider}/begin`+`/complete` | but requires a VALID, signature-verified id_token from the configured IdP; the attacker must control or coerce the trusted IdP |
| a1 (JIT), c3 | unauthenticated → `/auth/saml/{provider}/acs` | requires a signature-valid SAML assertion from the configured IdP; `TrustAssertedEmail`+`AutoProvision` must be on for an existing-account claim |
| a2, a3, b3, b4, c4, c5 | SCIM bearer token holder (the IdP's provisioning credential) | an already-trusted IdP integration credential, not an anonymous caller |
| b1, b2 | malicious / misconfigured IdP asserting group strings | fail-closed (see b1/b2 assessment) |
| a4, c7 | admin REST/gRPC; c7 also any onboarding path | admin-authenticated or install-config |
| c6 | invite/reset issuance (admin or self-service reset) | email is a dedup key, not a link |

No row is exploitable by an anonymous caller without either (i) control of a trusted
IdP's signing key / a valid SCIM token, or (ii) admin rights. The identity-fold
boundary itself is ENFORCED everywhere a principal or account-link is minted; b1/b2 are
a deliberate, fail-closed exactness that cannot escalate.

## What this sweep does NOT verify (honest limits)

- It is a code+storage-level sweep, verified by reading the exact fold call sites and by
  `internal/core/identity_boundary_sso_scim_sweep_test.go` which drives the confusable
  corpus through the real `GetUserByEmail`/`GetUserByUsername`/`resolveSSOUser` boundary
  on real SQLite. It does NOT exercise the full HTTP transport end to end (SAML XML
  parse, OIDC token parse, SCIM middleware), and covers LocalStorage, not the
  RemoteStorage proxy (out of scope; `/system` tier deleted, ADR-108).
- It does NOT re-verify the SAML/OIDC signature-validation stack (that is the subject of
  other findings, e.g. 2026-11-12 crewjam nil-deref) — only the identity MAPPING that
  runs AFTER a response is validated.
- The probe test could not be EXECUTED in the authoring session: `go.work` whole-graph
  resolution is blocked because `github.com/digitorus/pkcs7` (a repo dependency added
  2026-11-04) is absent from every reachable module cache with `GOPROXY=off` and no
  network. The test is gofmt-valid and self-contained; it runs once the module is
  cached. See the S4 report for the exact state.
