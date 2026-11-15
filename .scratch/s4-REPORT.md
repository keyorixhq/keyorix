# S4 — Identity boundary for SSO and SCIM

Task: verify that every place mapping an EXTERNAL identifier (SAML NameID/attributes,
OIDC claims, SCIM fields) to a Keyorix principal / group key / account-link folds or
rejects confusable forms at its own boundary, given that `internal/identity` folds with
**NFC, not NFKC** (keyorix#4335, fuzz-corpus#112). Fix any place it is not true.

Branch: `fuzz/s4-identity-boundary`. Date: 2026-11-15. Unattended session.

(Primary copy of this report is also at `/mnt/data/wave4/out/s4-REPORT.md`, which was
writable; this committed copy is identical.)

## Most-reasonable-reading note (nobody answers questions)

"The boundary is ENFORCED" = either the call site folds via `identity.NewFoldedName`,
or the storage lookup it calls folds consistently with how the stored `*_folded` column
was written (both count). "GAP" = an external string reaches a principal/group/link
decision through a DIFFERENT fold than storage used, enabling a confusable collision
(takeover) or a two-principals-for-one-human split.

## Headline: NEGATIVE result — the identity boundary is ENFORCED

I found **no security gap**. The identity fold is applied UNIFORMLY at the storage
lookup boundary, which is the load-bearing fact, so SSO/SCIM paths that pass a raw
external string to a lookup still get the same fold as write time:

- `LocalStorage.GetUserByEmail` (`internal/storage/store/local_users.go:163`) and
  `GetUserByUsername` (`:191`) both run the lookup key through `identity.NewFoldedName`
  and compare the stored `*_folded` column — the same fold as write time, on both
  backends; an un-normalizable key is treated as not-found.
- `GetUserByExternalID` (`:209`) is an exact match on an opaque address — correctly
  NOT folded (a subject/externalId is an address, not a human-verified identity).
- JIT/SCIM provisioning folds username+email+group-displayName explicitly at the insert
  (`provisionSSOUser`, `ProvisionSCIMUser`, `scimUpdateUserTx`, `ProvisionSCIMGroup`);
  the admin/CLI path folds via `buildUserForCreate`. No LDAP path, no CLI user-import.

Because there is no gap, there is no production fix and no red/green defect proof — the
right deliverable is the negative result, pinned by a probe test and an INVARIANTS entry.

### Highest-risk row — account linking by email — is ENFORCED

- **Unverified email can never link to an existing local account.** `resolveSSOUser`
  (`sso.go:602`) returns nil for an unverified/absent-verified email; the caller then
  JIT-provisions a NEW account (nothing to take over), it does not claim the existing
  one. `verifyIDToken` sets `emailVerified` true ONLY when `email_verified` is present
  AND true, and drops the email entirely when it is present-and-false (`sso.go:1486`).
- **SAML** has no per-assertion `email_verified`; the substitute is the provider opt-in
  `TrustAssertedEmail` (OFF by default), closing the SAML-specific #89 takeover.
  `CompleteSAML` passes it (not a hardcoded true) both to `resolveSSOUser` and to the
  provision race re-check (`sso.go:431,446`).
- **A verified confusable email still cannot take over**, because NFC (not NFKC) folds a
  Cyrillic-homograph / fullwidth email to a DISTINCT key that cannot collide with the
  victim's folded email. NFKC would have merged them — this is exactly why NFC is safer
  here, confirming the keyorix#4335 decision.
- Cross-provider claim of an already-federated account is additionally blocked by
  `ssoBoundToOtherProvider` (`sso.go:569`).

### Deliberate, fail-closed exception (DOCUMENTED EXCEPTION, not a vuln)

SSO native group-name matching (`applySSOGroupReconcile`, `sso.go:1050`) and
`GroupRoleMap` key matching (`buildSSORoleMaps`, `sso.go:1273`) use RAW exact,
case-sensitive string equality — NOT `NewFoldedName`. This is fail-closed for privilege:
an exact byte match is the narrowest possible, so a normalization mismatch can only
FAIL-to-add a membership/grant or CAUSE a removal (both de-escalating), never over-grant;
and the admin-conferring backstop (`idpGroupConfersAdminVerdict` /
`idpAutoGrantEscalationVerdict`) is keyed on the RESOLVED group/role ID, not the asserted
name, so no confusable name slips past it. The correctness cost (an IdP asserting a
case/width variant of a native group name silently fails to sync it) is an
availability footgun, not an escalation. Classified HARDENING, not fixed (task says fix
only confirmed gaps; "Do not refactor").

## Full sweep table

Committed at `docs/findings/2026-11-15-identity-boundary-sweep.md` — rows a1–a5 (principal),
b1–b4 (group), c1–c7 (account-link), each with external field, fold-before-lookup
(function:line), same-folding verdict, test, and a reachability trace.

## Deliverables committed on the branch

- `docs/findings/2026-11-15-identity-boundary-sweep.md` — the sweep table (the central artifact).
- `internal/core/identity_boundary_sso_scim_sweep_test.go` — table-driven probe over the
  full confusable corpus against the real `GetUserByEmail`/`GetUserByUsername`/
  `resolveSSOUser` boundary (real file-backed SQLite with the production folded indexes).
  Non-ASCII built from explicit code points via `cp()` (100% ASCII source) so no
  file-write layer can re-normalize a fixture.
- `internal/core/INVARIANTS.d/INV-CORE-sso-scim-external-identity-folded-at-boundary.md`
- `changelog.d/s4-identity-boundary-sso-scim.md` (### Security + ### Testing)
- This report (`.scratch/s4-REPORT.md`, force-added; also at `/mnt/data/wave4/out/`).

**Review-coverage ledger:** `internal/core` already has a fragment
(`docs/review-coverage.d/internal__core.tsv`). The ledger enforces one row per package
and FAILS on a duplicate key involving a fragment, so adding a second `internal/core`
row would break `scripts/check-review-coverage.sh`. I deliberately did NOT add one; the
sweep's evidence lives in the finding doc + the INVARIANTS entry + the probe test.

## Environment ARTIFACT — the probe could not be executed this session

`go test` cannot build ANY package in this worktree: `go.work` (`use .`) forces
whole-module-graph resolution, and `github.com/digitorus/pkcs7`
`v0.0.0-20261104125046` (a repo dependency added 2026-11-04, in go.sum) is **absent from
every reachable module cache** — the env's `GOMODCACHE=/mnt/data/wave4/gomod`, the
default `/root/go/pkg/mod`, nowhere — with `GOPROXY=off` and no network. Even
`internal/identity`'s own shipped tests fail to build for the same reason. I did not
change the global `go env` config (`GOPROXY`/`GOMODCACHE` live in the shared
`~/.config/go/env` and would affect sibling sessions — forbidden by the one-writer rule).
Classification: **ARTIFACT** (environment), not a code defect.

Consequence, stated honestly: I could NOT produce an executed PASS line for the probe.
The test is gofmt-clean (syntactically valid) and self-contained; it will run once
`pkcs7` is cached. The property it asserts is independently supported by the exact code
I read (uniform fold at `GetUserByEmail`/`GetUserByUsername`; the `email_verified` gate
in `resolveSSOUser`/`verifyIDToken`) and by the repo's already-shipped, already-green
`TestNewFoldedName_CompatibilityFormsAreDistinctPrincipals`
(`internal/identity/identity_test.go`), which pins that fullwidth/ligature/roman forms
fold distinctly under `NewFoldedName`. I hand-traced every corpus case through the real
code paths to confirm the test's expected outcomes (see the sweep doc).

## What each oracle does NOT verify

- `TestIdentityBoundary_UserLookupFold_NoConfusableMerge`: verifies the LocalStorage
  fold boundary (SQLite, production folded indexes). Does NOT cover the HTTP transport,
  the RemoteStorage proxy, or Postgres-specific collation.
- `TestIdentityBoundary_ResolveSSOUser_EmailLinkGate`: verifies `resolveSSOUser`'s
  email/verified link logic directly. Does NOT exercise `verifyIDToken` token parsing or
  the SAML assertion parse (asserted as upstream-validated inputs), and does NOT cover
  the JIT-provision write path end to end.
- The sweep is code+storage reading plus these probes; it does NOT re-verify the
  SAML/OIDC signature-validation stack (separate findings), only the identity MAPPING
  that runs after a response is validated.
- Neither oracle could be EXECUTED this session (see ARTIFACT above), so "ENFORCED" rests
  on code reading + the existing green identity_test.go, not a fresh PASS line.

## Talk material (5 sentences, honest about the negative result)

1. This was a negative result: the SSO/SCIM identity boundary is ENFORCED — I found no
   gap and made no production change, because the NFC fold is applied uniformly at the
   storage lookup layer, so even the paths that pass a raw IdP string get the same fold
   as write time. 2. The highest-risk row, account linking by email, is safe: an
   unverified email can never claim an existing account, and a verified Cyrillic/fullwidth
   confusable can't take one over either — NFC keeps it a distinct key where NFKC would
   have merged it, which is the whole point of the keyorix#4335 decision. 3. The one real
   divergence — SSO group-name and GroupRoleMap matching is raw exact-match, not folded —
   is fail-closed: an exact match is the narrowest possible, so a mismatch only drops
   privilege, never grants, and the admin backstop is keyed on the resolved ID, not the
   name. 4. I am being explicit that the probe test could not be executed this session: a
   just-added dependency (`digitorus/pkcs7`) is missing from every offline module cache,
   so `go.work` can't build any package in the repo — the test is valid and will pass once
   that's cached, and the property is independently backed by the already-green
   `internal/identity` tests. 5. The honest risk left on the table is availability, not
   security: an IdP that asserts a case/width variant of a native group name will silently
   fail to sync that group — worth a doc note for operators, but not a takeover.
