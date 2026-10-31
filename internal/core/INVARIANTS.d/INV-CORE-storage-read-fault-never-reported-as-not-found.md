- **INV-CORE-storage-read-fault-never-reported-as-not-found** On the revoke / suspend / unbind /
  withdraw / attest paths (machine identity and token, OIDC binding, project membership,
  invitation, access request, dynamic-secret lease, access-review attestation, bulk delete and
  bulk rename) a storage READ that fails is classified by `classifyReadError`
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
  `TestStorageUnavailable_RPCsAnswerUnavailable` (transport mapping), and the repo-wide
  `TestNoStorageReadErrorFoldedIntoNotFound` (internal/core/guards; calibrated red on the old
  `machineInProject` shape). **Not covered**: the login / MFA / WebAuthn / impersonation lane and
  the grant / create / renew paths, which fold a fault into a fail-closed refusal and are listed
  as exceptions in the guard with their reasons; own-session and own-PAT revoke; the permission
  checks inside the authorization-checked secret fetches that bulk delete folds into its uniform
  denial (#G14); the gRPC lease lookup answers `PermissionDenied`, not `Unavailable`, to a caller
  without global permission (the lease scope is unknown when the read faults).
