### Testing
- **pkcs7 verify/decrypt fuzz coverage (LS2).** Adds five new fuzz targets for the
  previously uncovered `digitorus/pkcs7` signature-verification and decryption surface:
  `FuzzPKCS7VerifyWithOpts` (Tier 1A — direct `internal/notary` caller on TSA bytes,
  with a one-directional differential oracle against `crypto/x509` chain verification),
  `FuzzPKCS7Verify`, `FuzzPKCS7VerifyWithChain`, `FuzzPKCS7VerifyWithChainAtTime`,
  and `FuzzPKCS7DecryptUsingPSK` (bounded allocation check for the GHSA-3xqc-rpq8-wgp9
  allocation class in the decrypt path), plus `FuzzPKCS7Decrypt` (RSA key-transport
  path). All harnesses confirmed clean over a 120 s foreground fuzz run on each target.
