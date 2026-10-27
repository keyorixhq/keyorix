- **INV-HTTP-scim-failure-never-not-found** A SCIM Users or Groups request (GET, POST, PUT,
  PATCH, DELETE `/scim/v2/Users`, `/scim/v2/Groups`) answers `404` only when the user or
  group positively does not exist or the user is not SCIM-managed (`storage.ErrUserNotFound`,
  `storage.ErrGroupNotFound`, `core.ErrNotSCIMManaged`). Every other failure
  is classified by `errors.Is` in `writeSCIMWriteError` (`scim_errors.go`), never by message
  text: email/`externalId`/group name taken `409 uniqueness`, last-admin refusal `409`,
  invalid value or a group member SCIM does not manage `400 invalidValue`, adding to a group
  that grants an admin role `403`, SQLite write contention or a lost conditional state write `503` +
  `Retry-After`, anything else (transient, deadlock, rolled back, canceled) `500` with
  `clientSafe`'s generic detail and the real error logged with the request id. Why: an IdP
  that gets `404` for a deactivation or DELETE marks the user gone and never retries, so a
  rolled-back deprovision left the account active (#3494), and the same for a group change
  (#3620). Guard:
  `scim_storage_error_status_test.go` (`TestSCIM_UserWriteStorageError_Is500NotNotFound`
  faults every storage call of PUT/PATCH/DELETE and asserts 500 plus "account still active";
  the 503/404/409 classes alongside) and `scim_write_error_test.go`
  (`TestSCIMWriteErrorStatus_Classes`); for Groups `scim_group_storage_error_status_test.go`
  (`TestSCIM_GroupStorageError_Is500NotNotFound` faults every storage call of GET/PUT/PATCH/
  DELETE, `TestSCIM_CreateGroupStorageError_Is500` the POST) and `scim_group_not_found_test.go`.
  Not covered: a failure reading a group's members while rendering a successful write's
  response (the member list is rendered empty; `renderGroup` ignores that error).
