- **INV-CORE-refresh-storage-panic-takes-error-path** Every storage call `RefreshSession` and
  its reuse revocation (`handleSessionReuse`) make runs through `refreshStorageCall`, so a panic
  takes exactly its error's path: only the pre-verdict `GetSessionAny` is `ErrRefreshNotEvaluated`
  (the transport hands the per-IP login slot back); the owner read is `ErrStorageReadUnavailable`
  (503, slot kept); a write is the wrong-token refusal (slot kept); and a panicking hash listing
  still lets the family revocation run. The panic value is never wrapped, so its payload cannot
  read as a definitive not-found. Why: #3968 (a panic ended in the Recovery 500 and kept the slot
  for every call, including the pre-verdict lookup); a post-verdict panic that refunded the slot
  would make a valid token cheaper than a wrong one (#2880). Guard:
  `refresh_panic_test.go` (`TestRefreshSession_PostVerdictPanicIsNotEvaluatedOnlyBeforeTheVerdict`,
  `TestRefreshSession_ReuseHashListingPanicStillRevokesTheFamily`), handler
  `TestRefresh_StoragePanicSlotPolicy` (every storage call refresh makes, derived per scenario,
  panic kind, through `middleware.Recovery`), faultops
  `TestRefreshStoragePanicTakesTheErrorPath_3968`. Not covered: a storage call added to refresh
  outside `refreshStorageCall` is caught only if a handler scenario reaches it.
