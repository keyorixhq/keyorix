- **INV-FUZZCLOUD-webauthn-cose-reencode-determinism** Every COSE credential
  public key that Keyorix's WebAuthn registration would store re-encodes to
  the same bytes on every call. go-webauthn@v0.18.2's
  `unmarshalCredentialPublicKey` (protocol/authenticator.go:384-396) stores a
  CTAP2 re-encoding of the attacker-controlled key, not the bytes sent, reached
  pre-auth via `server/http/handlers/webauthn.go:68 →
  protocol.ParseCredentialCreationResponseBytes → AuthenticatorData.Unmarshal`,
  then stored by `core.FinishWebAuthnRegistration` after
  `webauthn.CreateCredential` accepts it. For the same key bytes, 20
  consecutive `AuthenticatorData.Unmarshal` calls must all succeed or all
  fail; if their `CredentialPublicKey` bytes differ, the real registration
  ceremony (`CreateCredential`, "none" attestation, 20 runs) must refuse the
  key every time; stable bytes must re-decode under `DupMapKeyEnforcedAPF`.
  The re-encoding is NOT byte-stable for every input: `TagsForbidden` blocks
  the KFZ-2026-153 tag vector, but some untagged inputs still re-encode
  differently from call to call (private KFZ-2026-153 notes). The ceremony
  refuses every such input found so far, and the oracle checks that refusal on
  each diverging input instead of assuming it. Detection is probabilistic: one
  divergence needs map iteration order to differ within 20 calls. Does NOT
  assert cryptographic validity of a stored key, acceptance by attestation
  formats other than "none", or the `bytes.Equal` path in `credential.Verify`
  (Keyorix does not call that method). Why: KFZ-2026-153 (private
  disclosure), wa1-REPORT.md finding F1, review of 2c481769. Guard:
  `FuzzCOSEKeyReencodeIsDeterministic`
  (`server/http/handlers/webauthnparse/cose_reencode_determinism_fuzz_test.go`),
  red-proofed through the same `checkCOSEReencode` with
  `TestCOSEReencodeOracle_DeterminismRedProof`,
  `TestCOSEReencodeOracle_AcceptanceRedProof` and
  `TestCOSEReencodeOracle_DupMapKeyRedProof`; the ceremony gate is checked in
  both directions by `TestCOSEReencodeOracle_LiveProbeGreenAndGate`.
