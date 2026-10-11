- **INV-CORE-pat-restriction-outside-authorize** Every read or decision whose visibility
  is decided OUTSIDE `Authorize`/`AuthorizePrincipal`/`AuthorizeSecret` applies the
  caller's PAT restriction (ADR-042) itself, at the row's own scope, failing closed:
  the personal secret set (`ListSecretsWithSharingInfo`, and defensively
  `ListSecretsInScopeWithSharingInfo`) keeps a secret only if the restriction allows
  `secrets.read` at its project/environment; `CheckSecretPermission` checks the mapped
  permission at the secret's scope before honouring ownership, shares or ACL rows (the
  `AuthorizeSecret` PAT-SCOPE-002 check); the notification feed shows a restricted
  token only notifications whose project it may `secrets.read`, none without a project,
  and its badge count and mark-read writes follow the same visibility; the secret
  access-request family checks `roles.assign` at the request's project before admin
  authority (`requireAccessRequestAuthorityAt`) and `secrets.read` there for the
  requester's own rows; and a restricted PAT cannot create a PAT
  (`ErrRestrictedPATCannotMintPAT`). Helpers: `pat_restriction_listing.go`. Why:
  PAT-GUARD-1, after SHARE-4 found #3018's `/shares/owned` listing by membership; the
  sweep then found `/secrets`, `/notifications`, `/secret-access-requests` and
  `POST /auth/tokens` doing the same on main. Guard: `server/http`
  `TestEveryGETRouteHonoursPATRestriction` (every GET route from `chi.Walk`, restricted
  PATs of a project-only owner and a global admin against a canary project, with
  unrestricted controls) and `server/grpc` `TestEveryGRPCReadHonoursPATRestriction`
  (every unary read RPC from the live server); targeted `TestPATRestriction_*` in
  `server/http`; `internal/core` `TestPATRestrictionListingFilters_Edges`.
