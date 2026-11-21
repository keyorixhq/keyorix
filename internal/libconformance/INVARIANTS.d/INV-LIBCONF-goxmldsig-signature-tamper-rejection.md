- **INV-LIBCONF-goxmldsig-signature-tamper-rejection** When `russellhaering/goxmldsig` has just
  produced an enveloped signature over an element that VERIFIES, modifying the signed content —
  adding an attribute to the signed root, which exclusive-C14N includes in the digest — must make
  `ValidationContext.Validate` FAIL. A document that still verifies after its signed bytes change
  is a tamper-accepted (signature-integrity) failure. Why: goxmldsig is the engine crewjam/saml's
  whole trust model rests on; the one property an XML-Signature library must never break is that a
  signature covers the exact bytes it claims and any change to them is detected (the class XML
  Signature Wrapping attacks target). The oracle is GATED: it asserts tamper-rejection only on a
  document that actually verified, so a benign reason to not verify (cert/clock/shape) is never a
  false finding; the "sign always verifies" and "equivalent re-serialisation keeps the verdict"
  directions are deliberately NOT asserted (both can fail benignly). The red-proof confirms the
  gate is non-vacuous (the benign seed verifies before tamper) and that a no-op tamper would fire
  the oracle. Full XSW family (sibling injection, ID-reference confusion) is a LEFTOVER better
  driven through the crewjam layer (SXS1). Guard: `FuzzGoxmldsigSignatureMetamorphic` with
  `TestGoxmldsigSignatureMetamorphicRedGreen` (`internal/libconformance`,
  `goxmldsig_signature_metamorphic_fuzz_test.go` + `_redproof_test.go`).
