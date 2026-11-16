- **INV-FUZZCLOUD-webauthn-cose-bounded** go-webauthn's
  `webauthncose.ParsePublicKey`, which `internal/cryptoinventory/webauthn.go`
  runs on a credential COSE/CBOR public key (attacker-supplied at WebAuthn
  registration, re-parsed from storage), is total and bounded: arbitrary bytes
  decode without panic and within a generous wall-clock bound, so a hostile CBOR
  length-header ("array of 2^53 elements") cannot turn the decode into an OOM or
  hang. Does NOT bound allocation volume directly (bounds TIME, not bytes), does
  NOT test the accept/reject policy, and relies on `go test`'s own fuzz timeout
  to catch a true infinite hang. Why: a direct library-level
  complement to `FuzzCOSEKeyBoundedWork`
  (`internal/libconformance/cose_key_boundedwork_fuzz_test.go`), which bounds
  time AND allocation; this one bounds only time. Guard:
  `FuzzWebAuthnParsePublicKey`
  (`fuzz/thirdparty/webauthn/webauthn_cose_fuzz_test.go`), red-proofed with a
  planted slow parse.
