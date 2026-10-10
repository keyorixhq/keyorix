- **INV-CORE-share-elevates-member-on-one-secret** A member's effective permission on a
  secret is max(role permission, active share permission) (#2941, Andrei's 2026-10-10
  decision). The share term lives in exactly one function, `sharePermissionFor`
  (`share_authz.go`), and both per-secret decision functions call it: `AuthorizeSecret` (the
  gate behind every per-secret REST route via `RequireScopedSecretPermission` /
  `RequireScopedSecretRefPermission`, every per-secret gRPC RPC via `authorizeSecretScoped`,
  and the core helpers that call `AuthorizeSecretPrincipal`) and `CheckSecretPermission` (the
  core `*WithPermissionCheck` / `EnforceSecret*Permission` paths). Limits, each enforced in
  that one function: (1) a share applies only while the recipient is a LIVE member of the
  secret's project (`IsProjectMember`, at access time — `RemoveProjectMember` deletes role
  grants and ACLs but not share rows); (2) an expired share grants nothing; a revoked share is
  a deleted row; (3) a share satisfies only `secrets.read` (read|write share) and
  `secrets.write` (write share), never `secrets.delete`, `secrets.manage`, owner or the right
  to share; a stored level outside read|write grants nothing; (4) machine principals never
  take the share path. In `AuthorizeSecret` the share term runs only after ACL and role both
  denied, and a grant there writes `share_access_elevated` (with the share id) — so that audit
  row marks exactly the decisions a share made. Share mutations are owner-only through
  `requireShareAuthority`, whose typed refusals (`ErrShareOwnerNotMember`,
  `ErrShareRecipientNotMember`, ...) transports turn into the same user-facing reason via
  `ShareRefusalMessage` (#2976). Why: #2941 (a `write` share let nothing happen because the
  role-only route gates refused first, and the gRPC gate was role-only too), #2976 (bare 403).
  Guard: `share_authz_guard_test.go` (`TestShareTerm_DecisionFunctionsConsultIt`,
  structural; `TestShareTerm_AuthorizeSecret_MaxOfRoleAndShare`,
  `TestShareTerm_CheckSecretPermission_NonMemberShareGrantsNothing`, behavioural with real
  storage); transport halves `server/http/share_authz_route_guard_test.go`
  (`TestEveryPerSecretRoute_UsesShareAwareGate` over router.go's AST inventory,
  `TestSecretGates_CallShareAwareCheck`) and
  `server/grpc/services/share_authz_rpc_guard_test.go` (`TestEverySecretRPC_UsesShareAwareGate`
  over `pb.SecretService_ServiceDesc`, `TestAuthorizeSecretScoped_CallsShareAwareCheck`);
  end-to-end `server/http/share_elevation_2941_test.go`,
  `server/grpc/services/share_elevation_2941_test.go`. All default-ci.
  **Not covered**: a core function that authorizes one secret by calling the role-only
  `AuthorizePrincipal` at the secret's scope instead of `AuthorizeSecretPrincipal` would
  bypass the share term without tripping these guards (it would under-grant, never
  over-grant).
