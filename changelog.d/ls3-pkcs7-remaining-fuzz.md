### Testing
- **pkcs7 full-surface fuzz coverage (LS3).** Added harnesses for all four remaining
  `github.com/digitorus/pkcs7` entry points: `DegenerateCertificate`,
  `(*PKCS7).Decrypt` via ML-KEM-768 key, `NewSignedData`/`AddSigner`/
  `AddSignerChain`/`Finish`, and `Encrypt`/`EncryptUsingPSK`. Added a
  TimeStamping-EKU leaf-cert seed to `FuzzPKCS7VerifyWithOpts` and fixed the
  reference oracle to pass `ExtKeyUsageAny` to match pkcs7's own default.
  Coverage of the digitorus/pkcs7 exported surface rises from 7/27 (LS2) to
  14/27 symbols reached by at least one harness. All six harnesses passed 120 s
  foreground fuzz runs with no panics or hangs.
