- **INV-ENCRYPTION-premanifest-adoption-after-open** A key set with no key-set
  manifest is never recorded as generation 1 while a rotation staging file
  (`<key file>.pending`) is present until `Initialize` has opened it (an
  authenticated DEK unwrap under the on-disk KEK): `ReconcileKeySet` defers the
  adoption, and `Initialize` adopts after it succeeds (`keyfiles.AdoptProvenKeySet`,
  outside `Service.mu`, with the adoption audit event). Without a manifest an
  interrupted rotate-kek that left the old salt with the new DEK looks exactly like
  a harmless leftover; adopting it before opening would make the runbook's fix (the
  staged salt renamed into place) refuse at the next boot as a file from another
  generation. Why: #2424, #2900 criterion 4. Guard:
  `keyset_premanifest_staging_test.go`
  (`TestPreManifestInterruptedRotateKEK_HarmfulState_FixedSetBoots`,
  `TestPreManifestInterruptedRotateKEK_HarmlessState_AdoptedOnceOpened`),
  `internal/keyfiles/manifest_adopt_staging_test.go`.
