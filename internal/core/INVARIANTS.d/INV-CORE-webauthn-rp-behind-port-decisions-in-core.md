- **INV-CORE-webauthn-rp-behind-port-decisions-in-core** `internal/core` reaches the WebAuthn
  relying party only through `ports.WebAuthnRelyingParty` (implemented by `internal/webauthnrp`,
  wired in `server/wire_webauthn.go`); every decision about a ceremony's result stays in core and
  in its existing order: consume-first, account and lockout gates, `markLoginVerdict`, clone
  detection (`rejectIfCloned` refuses on `WebAuthnVerified.CloneWarning`, disables, audits,
  notifies), counter persistence (`persistUpdatedCredential` stores `json.Marshal` of the opaque
  credential), step-up grants and audit. The adapter owns only the ceremony options (user
  verification REQUIRED on every assertion, exclusions and resident key preferred on registration)
  and the library's JSON, which is byte-compatible with rows written before the port existed.
  A nil relying party means disabled (`ErrWebAuthnDisabled`); the adapter never returns a typed
  nil. Why: CORE-DECOUPLE-WEBAUTHN-1 (go-webauthn, go-tpm, cbor, msgp out of core's closure);
  ADR-036. Guard: `internal/core/webauthn_port_proofs_test.go`
  (`TestCloneDetection_ThroughAdapter_RedWhenFlagDropped`,
  `TestAssertionWithoutUV_RefusedThroughCore_RedWhenPreferred`, `TestWebAuthnDisabled_NilAndWrappedNil`,
  `TestPasskeyResolve_StorageFailureNotEvaluated_UnknownHandleFailedAttempt`, each with a mutant
  adapter that must change the outcome); `internal/webauthnrp/webauthnrp_test.go`
  (`TestAssertionWithoutUV_IsRejected_RedWhenPreferred`, `TestValidate_RegressedCounterSurfacesCloneWarning`,
  `TestGolden_MainRowsRoundTripByteIdentical` against rows written by main 277e33568);
  `internal/core/ports/heavy_deps_webauthn_test.go` (the library may not come back).
  Not covered: a relying-party implementation other than `internal/webauthnrp` (none exists), and
  library behaviour itself (go-webauthn's own suite; the spec vectors cover the paths core uses).
