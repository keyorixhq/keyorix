- **INV-CORE-bulk-delete-machine-per-secret-scope** `BulkDeleteSecrets` authorizes every item
  for the caller it serves, in core, not only at the route's `secrets.delete@project` gate. A user
  (actorID != 0) takes the singular delete's owner/share/role check. A machine token (actorID 0,
  ctx tagged `ActorTypeMachine`) takes the singular DELETE route's machine rule:
  `secrets.delete` at the secret's own project and environment for the ctx machine identity
  (`AuthorizeSecretPrincipalForSecret`, the decision `RequireScopedSecretPermission` makes), so a
  machine deletes in bulk only what it may delete one by one. A machine tag without a machine ID,
  a refusal and a failed role read all refuse the item ("secret not found", nothing deleted).
  Only actorID 0 with no machine tag, an in-process caller with no authenticated principal
  (embedded/local mode), keeps the bare delete with the project match alone. Why: #4546 (L3 of
  REVIEW-4522-DEEP-1): a machine token arrived with UserID 0 and took the local branch, so core
  deleted any secret of the project for it. Guard:
  `internal/core/bulk_delete_machine_4546_test.go` (`TestBulkDeleteSecrets_MachineRefusedPerSecretOutsideItsScope`,
  `...MachineWithProjectRoleDeletesAll`, `...MachineTagWithoutIdentityFailsClosed`,
  `...MachineAuthorizationFaultFailsClosed`, `...LocalCallerStillDeletes`). Not covered: a machine
  request that reaches core without the ctx machine tag would take the local branch; the tag is
  set by the auth middleware (`server/middleware/auth.go`) and the gRPC auth interceptor, and
  BulkDeleteSecrets has no gRPC RPC. The authzdiff `bulk.delete` core leg still answers
  `errNotAuthzLayer` for machines (L4 of the same review).
