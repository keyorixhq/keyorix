package handlers

import (
	"testing"

	"github.com/go-webauthn/webauthn/protocol"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// FuzzWebAuthnCredentialResponse fuzzes the two go-webauthn entry points that
// parse browser-supplied credential blobs: registration attestation (a CBOR
// attestationObject + clientDataJSON) and the login/passwordless assertion.
//
// These are reached on the UNAUTHENTICATED ceremony-finish endpoints
// (webauthn.go:67/194/250/305): after a JSON decode and a 64 KiB size cap, the
// raw credential bytes go straight into the library with no keyorix-side schema
// validation in front of them. keyorix has no filter to bypass here — the library
// IS the front line — so a panic / out-of-bounds / hang inside the parser is a
// pre-auth DoS. This is a "behind the wall" pour point in the sense that the rich
// attestation-format family (packed / tpm / android-key / android-safetynet /
// apple / fido-u2f, plus the CBOR/COSE key decode each carries) sits behind the
// outer JSON envelope; fuzzing the parser directly floods all of it.
//
// Invariants:
//   - never panics / hangs (Guard bounds the per-input wall clock, matching the
//     other keyorix targets);
//   - no partial success: a parser must not return a non-nil parsed value together
//     with a non-nil error.
func FuzzWebAuthnCredentialResponse(f *testing.F) {
	// Minimal well-formed envelopes so the fuzzer starts just inside the JSON
	// wall and mutates the CBOR/attestation payload, not only the outer JSON.
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"id":"x","rawId":"eA","type":"public-key","response":{"clientDataJSON":"eyJ0IjoxfQ","attestationObject":"oA"}}`))
	f.Add([]byte(`{"id":"x","rawId":"eA","type":"public-key","response":{"clientDataJSON":"eyJ0IjoxfQ","authenticatorData":"oA","signature":"oA"}}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Registration-finish parse path (attestation).
		var cErr error
		var cNonNil bool
		fuzzutil.Guard(t.Fatalf, "protocol.ParseCredentialCreationResponseBytes", func() {
			pcc, e := protocol.ParseCredentialCreationResponseBytes(data)
			cErr, cNonNil = e, pcc != nil
		})
		if cErr != nil && cNonNil {
			t.Fatalf("ParseCredentialCreationResponseBytes returned an error but a non-nil parsed value: %v", cErr)
		}

		// Login / passwordless / reauth parse path (assertion).
		var aErr error
		var aNonNil bool
		fuzzutil.Guard(t.Fatalf, "protocol.ParseCredentialRequestResponseBytes", func() {
			pcr, e := protocol.ParseCredentialRequestResponseBytes(data)
			aErr, aNonNil = e, pcr != nil
		})
		if aErr != nil && aNonNil {
			t.Fatalf("ParseCredentialRequestResponseBytes returned an error but a non-nil parsed value: %v", aErr)
		}
	})
}
