- **INV-CORE-validation-refusal-is-typed** In the groups, secrets, catalog, pat, sharing,
  users, versions, env-clone, account, break-glass and access-review families every refusal worded with the i18n `ErrorValidation` key ("Validation error: ...")
  matches a sentinel while keeping its text: the family's own (`storage.ErrInvalidGroupRequest`,
  `ErrSecretInvalidInput`, `storage.ErrInvalidSecretACLRequest`, `ErrBreakGlassInvalidRequest`) or `ErrValidation` where the
  family has none (catalog, pat, sharing, users, versions, env-clone, account, access review).
  A refused new password (`policyRefusal`) matches both `ErrPasswordPolicy` and `ErrValidation`; the
  independent-reviewer refusals of access review stay `ErrPermissionDenied` (authorization). A storage READ that failed is never worded as a validation
  refusal: it is `ErrStorageReadUnavailable` (secret copy's target-environment read, secret
  create's parent read and env clone's source/destination reads used to answer "Validation
  error: ..." for a fault). Why: a transport can
  classify the refusal by `errors.Is` only if it is typed; the text is translated and a driver
  error can contain "invalid" or "required" (CORE-ERR-FAMILY-7). Guard:
  `TestEveryValidationRefusalIsTyped` (report-only until its first green nightly, calibrated by
  `TestValidationRefusalScanCalibration`), `TestErrFamily7_ValidationRefusalsMatchTheirFamily`,
  `TestErrFamily7_CopySecretEnvironmentReadFaultIsNotValidation`,
  `TestErrFamily7_CreateSecretParentReadFaultIsUnavailable`, `TestValidationTyped_*` and the REST
  table `TestValidationRefusalStatusCharacterization` (server/http/handlers). Not covered: other
  files that spell the key (setup*.go, invitations.go, classification.go, reissue_otp.go's sibling
  setup_delivery.go, ...), and the handlers of these families that still classify by text
  (CloneEnvironment in catalog.go, RotateSecret in secrets_versions.go), which keep answering the
  same status because the text is unchanged.
