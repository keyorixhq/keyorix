- **INV-CORE-not-found-is-typed-and-fault-is-not-a-verdict** A core read that answers "no such
  thing" does so with a typed error (`ErrSecretRefNotFound`, `ErrAccessReviewNotFound`,
  `ErrMembershipTargetNotFound`, `ErrAnomalyAlertNotFound`, the `storage.Err*NotFound` family)
  only for a positive not-found (`isPositiveNotFound`); a read that FAILED is
  `ErrStorageReadUnavailable` (`classifyReadError`, `SecretReadVerdictFault` for the
  uniform-denial probes), and no transport decides "not found" by matching "not found" in the
  message (it is translated, and a driver error can say it). Why: a database outage answered 404 /
  idle / "no such secret" on ref reads, secret access requests, anomaly acknowledge, access-review
  decide and revoke, folder create and membership transitions (ERR-FOLD-HANDLERS-1). Guard:
  `storage_read_class_fold_handlers_test.go`, `storage_read_class_access_review_test.go`, handler
  `TestFoldHandlers_*`, handler `TestAccessReviewMachinePrincipal_AbsentAnswersLikeCrossProject`
  (an absent machine id answers revoke/attest/decide exactly like one in another project, so the
  ARC-001 lookup is no existence oracle), middleware `TestScopeResolverRefReadFault`, and the existing
  `TestNoStorageReadErrorFoldedIntoNotFound`. Not covered: handlers still outside this family that
  match message text for other verdicts (`errtext` exceptions list, #3864).
