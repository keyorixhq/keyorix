- **INV-LIBCONF-pkcs7-mlkem-decrypt-bounded-work** The ML-KEM-768
  decapsulation path of `(*PKCS7).Decrypt` must never panic and never hang
  on ANY input that parses successfully via `pkcs7.Parse` when the caller
  holds an ML-KEM-768 decapsulation key.  This path (in `kem.go`:
  `decryptKEMRecipientKey` → `parseOtherRecipientInfo` →
  `kemRecipientInfo` → `decapsulate` → AES key-unwrap) is completely
  separate from the RSA key-transport path covered by LS2's
  `FuzzPKCS7Decrypt` harness.  Why: `(*PKCS7).Decrypt` with an ML-KEM
  key type is reachable from the same notary endpoint that calls
  `VerifyWithOpts`; a panic in the ML-KEM parsing path is directly
  reachable from pkcs7.Parse → p7.Decrypt.  Positive control: the seed
  envelope (ML-KEM-768 AES-256-CBC envelope) must decrypt successfully
  before fuzzing starts; a failing positive control aborts the harness,
  making the ML-KEM path visible.  Guard: `FuzzPKCS7DecryptMLKEM768`
  (`internal/libconformance`).
