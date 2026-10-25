- **INV-HTTP-scim-failure-never-not-found** A SCIM Users request (GET, POST, PUT, PATCH,
  DELETE `/scim/v2/Users`) answers `404` only when the user positively does not exist or is
  not SCIM-managed (`storage.ErrUserNotFound`, `core.ErrNotSCIMManaged`). Every other failure
  is classified by `errors.Is` in `writeSCIMWriteError` (`scim_errors.go`), never by message
  text: email/`externalId` taken `409 uniqueness`, last-admin refusal `409`, invalid value
  `400 invalidValue`, SQLite write contention or a lost conditional state write `503` +
  `Retry-After`, anything else (transient, deadlock, rolled back, canceled) `500` with
  `clientSafe`'s generic detail and the real error logged with the request id. Why: an IdP
  that gets `404` for a deactivation or DELETE marks the user gone and never retries, so a
  rolled-back deprovision left the account active (#3494). Guard:
  `scim_storage_error_status_test.go` (`TestSCIM_UserWriteStorageError_Is500NotNotFound`
  faults every storage call of PUT/PATCH/DELETE and asserts 500 plus "account still active";
  the 503/404/409 classes alongside) and `scim_write_error_test.go`
  (`TestSCIMWriteErrorStatus_Classes`). Not covered: the SCIM Groups handlers (#3620).
