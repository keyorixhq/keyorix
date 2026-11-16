### Testing
- **Transferred the digitorus/pkcs7 binary-parser bug classes (BER memory-exhaustion
  DoS, BER out-of-bounds panic, round-trip divergence) to the other binary-format
  parsers Keyorix reaches.** New bounded-work + round-trip fuzz targets in
  `internal/libconformance`: `FuzzCBORBoundedWork` and `FuzzCBORRoundTrip`
  (fxamacker/cbor/v2 — the attestation/COSE codec reached indirect-only via
  go-webauthn), `FuzzTPMUnmarshalBoundedWork` (google/go-tpm `tpm2.Unmarshal` of the
  TPM2B sealed-KEK / attestation structures reached from
  `internal/crypto/tpm_provider.go`), and `FuzzCOSEKeyBoundedWork`
  (go-webauthn `webauthncose.ParsePublicKey`). Each asserts decode time (Guard) and
  allocation (`64 MiB + 4 KiB·N` envelope) stay proportional to input; the round-trip
  target names every benign disagreement in a committed `EXPECTED-DIFFERENCE.md` table
  so only a NEW class fails. Pinned behaviour recorded in
  `internal/libconformance/INVARIANTS.md`. No production code changed.
