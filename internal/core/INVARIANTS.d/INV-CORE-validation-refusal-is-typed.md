- **INV-CORE-validation-refusal-is-typed** In the groups, secrets, catalog, pat and sharing
  families every refusal worded with the i18n `ErrorValidation` key ("Validation error: ...")
  matches a sentinel while keeping its text: the family's own (`storage.ErrInvalidGroupRequest`,
  `ErrSecretInvalidInput`, `storage.ErrInvalidSecretACLRequest`) or `ErrValidation` where the family
  has none (catalog, pat, sharing). A storage READ that failed is never worded as a validation
  refusal: it is `ErrStorageReadUnavailable` (secret copy's target-environment read and secret
  create's parent read used to answer "Validation error: ..." for a fault). Why: a transport can
  classify the refusal by `errors.Is` only if it is typed; the text is translated and a driver
  error can contain "invalid" or "required" (CORE-ERR-FAMILY-7). Guard:
  `TestEveryValidationRefusalIsTyped` (report-only until its first green nightly, calibrated by
  `TestValidationRefusalScanCalibration`), `TestErrFamily7_ValidationRefusalsMatchTheirFamily`,
  `TestErrFamily7_CopySecretEnvironmentReadFaultIsNotValidation`,
  `TestErrFamily7_CreateSecretParentReadFaultIsUnavailable`. Not covered: other files that spell the
  key (users.go, versions.go, break_glass.go, access_review*.go, setup*.go, account.go, ...), and the
  handlers of these families that still classify by text (`errtext` exceptions list), which keep
  answering the same status because the text is unchanged.
