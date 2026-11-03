- **INV-CORE-storage-read-fault-never-reported-as-not-found** On the revoke / suspend / unbind /
  withdraw / attest paths (machine identity and token, OIDC binding, project membership,
  invitation, access request, dynamic-secret lease, access-review attestation, bulk delete and
  bulk rename), on own-session and own-PAT revoke, and on the grant / create paths that read a
  parent (user create with a role or assignments, role-grant validation, environment create and
  copy, member invite, access-request approval, secret-access approval; STORAGE-ERR-CLASS-2) a storage READ that fails is classified by `classifyReadError`
  (`storage_read_class.go`): a positive no-such-row (`gorm.ErrRecordNotFound` or a typed
  not-found sentinel) keeps the caller's "not found" text, and anything else becomes
  `ErrStorageReadUnavailable` (matched with `errors.Is`, never by text). The row is untouched,
  the same call retried after the fault clears succeeds, and the transports answer 503 +
  `Retry-After` (REST) / `Unavailable` (gRPC). A true not-found and a cross-project mismatch stay
  one identical message, so there is no existence oracle. Why: a fault folded into "not found"
  tells the operator the principal is already gone while the revoke was never applied
  (STORAGE-ERR-CLASS-1; SQLITE-TIME-TAILS-1 hit it with a scan error). Guard:
  `TestStorageReadClass_MachineIdentityFamily`, `TestStorageReadClass_MembershipInvitationAccessRequest`,
  `TestStorageReadClass_RevokeLease`, `TestStorageReadClass_AccessReviewAndBulk` (injected read
  faults, SQLite and Postgres), `TestStorageUnavailable_RESTMapping` and
  `TestStorageUnavailable_RPCsAnswerUnavailable` (transport mapping), `TestStorageReadClass_OwnRevoke`,
  `TestStorageReadClass_GrantPaths`, `TestStorageReadClass_GrantPaths_InviteAndApprove`,
  `TestStorageReadClass_ApproveSecretAccessRequest` (STORAGE-ERR-CLASS-2, with REST
  `TestStorageUnavailable_OwnRevokeREST` / `TestStorageUnavailable_GrantPathsREST` and the
  router-level `TestDynamicSecretLeaseRoutes_ReadFaultIs503ForGlobalHolders`), and the repo-wide
  `TestNoStorageReadErrorFoldedIntoNotFound` (internal/core/guards; calibrated red on the old
  `machineInProject` shape). `isPositiveNotFound` must list every typed not-found sentinel a
  storage getter wraps (session, role, project, environment, ...), or a true absence is
  misreported as a fault. **Not covered**: the login / MFA / WebAuthn / impersonation lane, the
  setup-link accept path and the machine-token / dynamic-secret grant / create / renew paths,
  which fold a fault into a fail-closed refusal and are listed as exceptions in the guard with
  their reasons; the permission checks inside the authorization-checked secret fetches that bulk
  delete folds into its uniform denial (#G14: reporting a fault there only for an existing
  secret would let a caller without access probe existence during a partial outage); the gRPC
  lease lookup answers `PermissionDenied`, not `Unavailable`, to a caller without global
  permission (the lease scope is unknown when the read faults), and the same fold remains in the
  other REST scope resolvers (config, share, rotation policy, secret).
