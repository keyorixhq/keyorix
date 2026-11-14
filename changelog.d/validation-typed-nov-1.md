### Fixed
- **Ordinary validation refusals in the users, versions, break-glass, account, env-clone and access-review families answer 400, not 500.** Deleting or restoring user id 0, listing the versions of secret id 0, activating break-glass with an install-wide-admin or role-assigning emergency role, deciding an access-review item that is already decided, an unknown access-review source and a machine caller deciding an item answered `500 InternalError` because core built these refusals as bare "Validation error: ..." errors that the handlers could only classify by text. They are typed now (`ErrValidation`, `ErrBreakGlassInvalidRequest`) and the handlers classify by `errors.Is`, so REST and gRPC agree and the status no longer depends on the language. The refusal text is unchanged.

### Changed
- **A failed read of the source or destination environment in an environment clone is a storage fault, not a validation refusal.** It used to be worded "Validation error: source environment: <driver text>" whatever the cause; a missing environment keeps its text and its 404 and now matches `storage.ErrEnvironmentNotFound`, any other failure is the retry class.
- **A refused new password also matches `ErrValidation`** (in addition to `ErrPasswordPolicy` / `ErrPasswordReused`), so a transport classifying by `ErrValidation` answers it 400 / InvalidArgument.

### Testing
- `TestEveryValidationRefusalIsTyped` now scans the users, versions, env_clone, account, break_glass and access_review files (still report-only through its `docs/guard-rollout.d` row); `TestValidationRefusalStatusCharacterization` pins the REST status and error code of every reachable refusal of these families, in English and under a translated locale.
