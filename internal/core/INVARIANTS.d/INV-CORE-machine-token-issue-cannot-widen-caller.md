- **INV-CORE-machine-token-issue-cannot-widen-caller** A machine identity acting as itself
  (`WithSelfMachineGranter`, not a /system relay) can never use `IssueMachineToken` to
  obtain a credential broader than the one it called with. It cannot issue a token for
  itself. Its presented credential (`WithMachineCallerCredential`, set by the REST and gRPC
  handlers) must be a live opaque `kx_machine_` credential of that machine with no CIDR
  allowlist; a federated JWT or an unrecorded credential is refused. It is refused a target
  whose roles are admin-tier by the bypass flag, a canonical admin name or the permission
  bundle (`roleIsAdminTier`). All refusals wrap `ErrMachinePrivilegeCeilingDenied`. Why:
  REVIEW-3993-DEEP-1, a CIDR-restricted machine minted itself an unrestricted, non-expiring
  token (the machine counterpart of PAT-GUARD-1). Guard:
  `machine_token_caller_credential_test.go`, `machine_token_admin_tier_target_test.go`,
  server/http/handlers `machine_token_caller_credential_test.go`, server/grpc/services
  `TestGRPCIssueMachineToken_MachineCaller`.
  **Not covered**: a user caller authenticated by a CIDR-only restricted PAT, and the user
  path's non-admin branch, which requires only `roles.assign` and not that the actor holds
  what the target holds (INV-CORE-01 follow-up issue).
