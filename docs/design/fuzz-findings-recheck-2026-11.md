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

## #2842 oracle (a) flags RotateSecret's non-transactional version write

FIXED by 68b81eea2 (AUDIT-MUTATION-TX-1). A rotation with no rotation backend, and every
rollback, now commits the version, the timestamp and the audit row in one transaction
(`internal/core/secrets.go`), and the last `#2842` fuzz tolerance was removed. No oracle
exemption was needed. A backend-bound rotation stays two writes by design: the new
version must survive an upstream credential change that already happened. Proof:
`TestSecretMutationAudit_RowExistsIffMutationCommitted` (`internal/core`) and
`TestSecretMutationAuditFailure_FailsClosedChangesNothing`
(`server/faultops/secret_mutation_audit_fail_closed_test.go`, which covers rollback).
Residual, not a defect: `docs/atomicity-exempt.tsv` has no write-count row for the
backend-bound path.

## #3377 FlushSecretReadDenials is never called on graceful shutdown

FIXED by 71efc1ebf, bounded to 10s by 636b9b5ce (#3602). `server/main.go` has one deferred
call, `flushSecretReadDenialsOnShutdown(coreService)`, with the logic in
`server/shutdown.go`. Defers run LIFO after the servers drained, so the denial rows reach
the audit log before the forwarder closes. Proof:
`TestShutdown_FlushesOpenSecretReadDenialSummary` and
`TestShutdown_SecretReadDenialFlushIsBoundedOnSlowDatabase` (`server/shutdown_flush_test.go`).
