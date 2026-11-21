- **INV-LIBCONF-pkcs7-sign-and-encrypt-bounded-work** The digitorus/pkcs7
  signing pipeline (`NewSignedData`, `(*SignedData).AddSigner`,
  `(*SignedData).AddSignerChain`, `(*SignedData).Finish`) and the two
  encryption entry points (`Encrypt`, `EncryptUsingPSK`) must never panic
  and never hang on ANY input accepted by their Go API (including empty,
  arbitrarily large, or structurally unusual plaintext / PSK bytes).
  Although these functions produce output rather than consume untrusted
  input, Keyorix code could call them with attacker-influenced plaintext or
  configuration; a panic or hang in the signing or encryption path would be
  a reachable defect.  `FuzzPKCS7SignWithChain` additionally exercises the
  intermediate-certificate code path in `AddSignerChain` that
  `FuzzPKCS7Sign` (empty-parents) does not reach.  Why: the signing/encrypt
  surface was unguarded by any fuzz harness prior to LS3; `NewSignedData`
  allocates from the input inside an ASN.1 marshal path that had no
  allocation or panic coverage.  `FuzzPKCS7Sign` and `FuzzPKCS7SignWithChain`
  additionally carry a sign-then-verify round-trip oracle (LS4): when
  `Finish()` succeeds the resulting token is parsed and verified against the
  signing PKI's own root pool via `VerifyWithChain`, asserting no sign/verify
  asymmetry in the library.  Guard: `FuzzPKCS7Sign`,
  `FuzzPKCS7SignWithChain`, `FuzzPKCS7Encrypt`, `FuzzPKCS7EncryptUsingPSK`
  (`internal/libconformance`).
