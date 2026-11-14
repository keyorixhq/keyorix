- **INV-LIBCONFORMANCE-binary-parsers-bounded-work** Every binary-format decoder
  Keyorix reaches — `pkcs7.Parse` (BER), `cbor.Unmarshal` (fxamacker/cbor/v2, the
  go-webauthn attestation/COSE codec), `tpm2.Unmarshal[TPM2B*/TPMT*/TPMS*]` (the TPM
  sealed-KEK / attestation reader) and `webauthncose.ParsePublicKey` (the COSE
  key seam) — does bounded work on ANY input: it never panics, never hangs, and its
  allocation stays within the envelope `64 MiB + 4 KiB·N` of the N-byte input. A
  declared length or element count far larger than the input (CBOR major-type-4/5
  heads up to 2^64-1, indefinite-length nesting, a TPM2B uint16/uint32 length prefix,
  a COSE coordinate byte-string length) MUST NOT drive an allocation proportional to
  the DECLARED size. Why: this is the digitorus/pkcs7 BER memory-exhaustion DoS + OOB
  panic class (High/Moderate advisories) transferred to the other binary parsers in
  Keyorix's dependency graph — a regression in a pinned dep that removed a bound would
  otherwise be a pre-auth (WebAuthn) or startup (TPM KEK-unseal) DoS. The oracle
  bounds WORK only: it verifies nothing about the parse RESULT (validity, signature,
  trust). Red/green proof: a planted length-prefix `make()` defect allocated 302 MB
  for a 4-byte input and tripped the alloc check, while the real cbor decoder of a
  count=2^32-1 head allocated 112 bytes (it does not preallocate from the declared
  count, even with the DecMode caps lifted). Guard: `FuzzCBORBoundedWork`,
  `FuzzTPMUnmarshalBoundedWork`, `FuzzCOSEKeyBoundedWork`,
  `FuzzDigitorusPKCS7BoundedWork`, `FuzzDERPKCS7BoundedWork`
  (`internal/libconformance`).
