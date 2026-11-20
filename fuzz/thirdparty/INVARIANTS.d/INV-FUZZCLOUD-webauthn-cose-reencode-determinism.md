- **INV-FUZZCLOUD-webauthn-cose-reencode-determinism** The COSE credential
  public key re-encoding in go-webauthn@v0.18.2's
  `unmarshalCredentialPublicKey` (protocol/authenticator.go:384-396) is
  byte-stable: for the same COSE key bytes, 20 consecutive calls to
  `protocol.AuthenticatorData.Unmarshal` must return identical
  `CredentialPublicKey` bytes, those bytes must re-decode under
  `DupMapKeyEnforcedAPF` without error, and their sha256 must be stable.
  Reachable pre-auth via
  `server/http/handlers/webauthn.go:68 →
  protocol.ParseCredentialCreationResponseBytes → AuthenticatorData.Unmarshal →
  unmarshalCredentialPublicKey` on attacker-controlled COSE key bytes; the
  re-encoded bytes are stored as `Credential.PublicKey` in the database and
  later decoded by `ParsePublicKey` for signature verification.  The specific
  KFZ-2026-153 non-determinism vector (tag-based key collision) is blocked by
  `webauthncbor`'s `TagsForbidden` decode option; the float32/float64 collision
  is blocked by `DupMapKeyEnforcedAPF` (all CBOR floats decode to `float64`
  in `any` context).  This invariant is a regression tripwire: if either guard
  is relaxed, the oracle would catch non-determinism.  Does NOT assert
  cryptographic validity of the key, acceptance by the ceremony, or the
  `bytes.Equal` path in `credential.Verify` (Keyorix does not call that
  method).  Why: KFZ-2026-153 (private disclosure), wa1-REPORT.md finding F1.
  Guard: `FuzzCOSEKeyReencodeIsDeterministic`
  (`server/http/handlers/webauthnparse/cose_reencode_determinism_fuzz_test.go`),
  red-proofed with `TestCOSEReencodeOracle_ByteStabilityRedProof` and
  `TestCOSEReencodeOracle_DupMapKeyRedProof`.
