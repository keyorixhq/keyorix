- **INV-LIBCONF-pkcs7-mlkem-decrypt-bounded-work** The ML-KEM decapsulation
  path of `(*PKCS7).Decrypt` must never panic and never hang on ANY input that
  parses successfully via `pkcs7.Parse`, for BOTH ML-KEM-768 and ML-KEM-1024
  decapsulation keys.  This path (in `kem.go`: `decryptKEMRecipientKey` →
  `parseOtherRecipientInfo` → `kemRecipientInfo` → `decapsulate` →
  AES key-unwrap) is completely separate from the RSA key-transport path
  covered by LS2's `FuzzPKCS7Decrypt` harness.  The 768 and 1024 paths share
  one implementation in `mlKEMDecapsulator` (a type-switch); only key size and
  ciphertext length differ.  Why: `(*PKCS7).Decrypt` with an ML-KEM key type
  is reachable from the same notary endpoint that calls `VerifyWithOpts`; a
  panic in the ML-KEM parsing path is directly reachable from pkcs7.Parse →
  p7.Decrypt.  Positive control: the seed envelope must decrypt successfully
  before fuzzing starts; a failing positive control aborts the harness, making
  the ML-KEM path visible.  Guards: `FuzzPKCS7DecryptMLKEM768` (LS3,
  ML-KEM-768 path) and `FuzzPKCS7DecryptMLKEM1024` (LS6, ML-KEM-1024 path),
  both in `internal/libconformance`.
