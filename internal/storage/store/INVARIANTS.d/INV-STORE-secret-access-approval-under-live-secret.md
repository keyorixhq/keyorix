- **INV-STORE-secret-access-approval-under-live-secret** An approved secret-scoped
  `AccessRequest` never commits under a soft-deleted secret. `UpdateAccessRequest`, when
  it moves a request with a `secret_id` to `approved`, re-reads the secret with
  `lockLiveParent` (Postgres `FOR SHARE`; SQLite's single writer serializes) AFTER its
  conditional UPDATE, in the same transaction, and rolls back with `ErrSecretNotFound`
  when the secret is gone. Together with `closeApprovedSecretAccessRequests` (#2797),
  which `DeleteSecret` and the `DeleteProject` cascade run after their secret soft-delete
  has row-locked the secret, every interleaving ends with no approval surviving a delete:
  either the delete committed first and the approval rolls back, or the approval
  committed first and the sweep (a later statement, new snapshot) expires it.
  Why: CORE-ACTOR-RACE-1. `ApproveSecretAccessRequest` checks liveness with a GetSecret
  outside its write transaction and the sweep only closes rows already approved, so a
  delete landing between the two left an approval that came back live on restore.
  Guard: `internal/core/access_request_approve_delete_race_test.go`
  (`TestApproveSecretAccessRequest_DeleteInApprovalWindow_Postgres` / `_SQLite`, both
  deleters; `_DeleteSweep_AllOrderings_Postgres`, all six forced orderings per deleter;
  red without this check on both drivers).
  Not covered: an approval whose check and write both land between a delete and a restore
  of the same secret stands (it was decided and written against a live secret), pinned by
  `TestApproveSecretAccessRequest_DeleteAndRestoreInApprovalWindow`. Project/role requests
  (`secret_id IS NULL`) are not touched by this check.
