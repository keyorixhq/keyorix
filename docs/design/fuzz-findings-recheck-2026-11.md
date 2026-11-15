# Fuzz findings re-check against main (2026-11, FUZZ-FINDINGS-RECHECK-NOV-1)

Five old open findings, re-checked on `origin/main` e550eb75e. Each verdict names the
fixing commit and the test that proves it; each proving test was run at that SHA and
passes.

## #3105 gRPC DeleteSecret reports an error after the delete committed

FIXED by a65c00ff2 (#3508). The post-commit purge-date read-back
(`DeletedSecretPurgeAt` -> `GetSecretIncludingDeleted`) now runs through
`besteffort.Run`, so a panic or error leaves `PurgeAt` unset and the RPC answers success.
Proof: `TestSecretService_DeleteSecret_PurgeAtReadbackFault_DoesNotUndoCompletedDelete`
(`server/grpc/services/secret_delete_readback_fault_test.go`), panic and error armed on
`GetSecretIncludingDeleted#1`, asserts success, soft-deleted row and the
`secret.deleted` audit row.

## #3225 POST /users/ creates the user, then returns an error

FIXED by 80a43afe5 (lost-ack read-back in `internal/core/users.go`), widened to the
sibling insert sites by 69c4e3fd9 and guarded by cf71fe49c. A commit whose
acknowledgement was lost is read back and answered as success; a rolled-back create stays
an error. This is the PARTIAL-COMMIT-NOV-2 family fix, so no new pattern was added.
Proof: `TestPartialCommit_UserCreateLostAckAnswersSuccess`,
`TestPartialCommit_UserCreateRolledBackStaysAnError` and
`TestPartialCommit_EveryUserCreateSiteHandlesLostAck`
(`server/faultops/partial_commit_user_create_test.go`). PARTIAL-COMMIT-TAILS-NOV-3 has
nothing left to own here.
