- **INV-LIBCONF-pkcs7-remove-auth-attrs-verify-fails-cleanly** When
  `(*SignedData).RemoveAuthenticatedAttributes()` is called between
  `AddSigner`/`AddSignerChain` and `Finish()`, the resulting token's
  `VerifyWithChain` MUST return a non-nil error — not panic — on every input.
  Rationale: `AddSigner` computes the signature over `marshalAttributes(finalAttrs)`
  (the authenticated attributes); after removal, `verifySignature` skips the
  `len(AuthenticatedAttributes)>0` branch and calls
  `ee.CheckSignature(sigalg, p7.Content, sig_over_attrs)` — a structural
  signature mismatch. The invariant pins the error-not-panic contract of the
  `len(AuthenticatedAttributes)==0` branch in verify.go. What this invariant does
  NOT verify: the specific error returned; behaviour with zero signerInfos.
  Why: LS5 COMPOSE decision for `(*SignedData).RemoveAuthenticatedAttributes`
  (docs/fuzz/library-surface/LS5-DECISION.md). Guard: `FuzzPKCS7Sign` and
  `FuzzPKCS7SignWithChain` with `removeAuthAttrs=true`
  (`internal/libconformance/sign_pkcs7_fuzz_test.go`).
