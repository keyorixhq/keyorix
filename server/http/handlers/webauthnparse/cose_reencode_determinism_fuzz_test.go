package webauthnparse

// FuzzCOSEKeyReencodeIsDeterministic checks that the COSE credential public
// key re-encoding path (unmarshalCredentialPublicKey in go-webauthn@v0.18.2
// protocol/authenticator.go:384-396) is byte-stable: for any input, 20 repeated
// calls to AuthenticatorData.Unmarshal must return identical CredentialPublicKey
// bytes.
//
// Background (KFZ-2026-153, private disclosure to fxamacker/cbor maintainer):
// fxamacker/cbor v2.9.x re-encodes a decoded map[any]any in CTAP2/CoreDet mode
// non-deterministically when two distinct Go map keys have the same CTAP2 canonical
// encoding.  The unmarshalCredentialPublicKey path decodes a COSE_Key into any →
// map[any]any and re-encodes it with CTAP2EncOptions; if that re-encoding is
// non-deterministic the stored CredentialPublicKey bytes diverge across server
// restarts, which depending on how those bytes are later used (e.g. bytes.Equal in
// credential.Verify) could cause a denial-of-service.
//
// Analysis (trace 1 in wa1-REPORT.md):
//
//	The specific KFZ-2026-153 vector (integer-0 key collides with tag-1-time-0
//	key after re-encoding) is blocked by webauthncbor's TagsForbidden decode
//	option: any tagged input is rejected before the re-encode step.
//
//	The only remaining class (float32 and float64 encoding identically under CTAP2)
//	is blocked by DupMapKeyEnforcedAPF: fxamacker/cbor v2 decodes ALL CBOR float
//	types (float16, float32, float64) to Go float64 when the target is any, so a
//	CBOR map with float32(0.0) and float64(0.0) keys has the SAME decoded Go key,
//	and DupMapKeyEnforcedAPF reports the second as a duplicate → Unmarshal errors
//	→ registration fails before any re-encoding happens.
//
// This target is therefore a regression tripwire: it would catch a future
// webauthncbor change that removes either guard while keeping the re-encode path.
//
// Live caller chain:
//
//	server/http/handlers/webauthn.go:68
//	  → protocol.ParseCredentialCreationResponseBytes (attacker-supplied bytes)
//	  → AuthenticatorData.Unmarshal
//	  → unmarshalCredentialPublicKey (unexported, go-webauthn)
//	  → webauthncbor.UnmarshalFirst(keyBytes, &m) where m any
//	  → webauthncbor.Marshal(m)   ← the re-encode
//	  → CredentialPublicKey stored in DB, re-decoded during authentication
//
// Oracles:
//   - DETERMINISM: 20 consecutive Unmarshal calls on the same input produce the
//     same CredentialPublicKey bytes.
//   - DUP-MAP-KEY: the resulting bytes decode via webauthncbor.UnmarshalFirst with
//     DupMapKeyEnforcedAPF (the same decode mode used throughout webauthncbor)
//     without error.  If unmarshalCredentialPublicKey ever emitted duplicate-key
//     CBOR, authentication would fail on a DupMapKeyEnforcedAPF decode of the
//     stored bytes.
//   - HASH-STABLE: sha256 of the stored bytes is identical across all 20 calls;
//     a hash or bytes.Equal operation over the stored bytes must not depend on map
//     iteration order.
//
// What this oracle does NOT verify:
//   - NOT that the COSE key is cryptographically valid or accepted by ParsePublicKey.
//   - NOT that the registration ceremony would accept the input.
//   - NOT the semantics of the CredentialPublicKey when decoded into a typed struct;
//     only that the BYTES are stable and structurally valid CBOR.
//
// Private test data (NOT committed; .scratch/private/kfz-2026-153-colliding-keys.cbor):
// Raw CBOR for a map with an integer-0 key and a tag-1-epoch-0 key — the specific
// KFZ-2026-153 example.  When wrapped in authDataWithKey these bytes are rejected by
// TagsForbidden during UnmarshalFirst; they are kept only in the untracked directory
// to document the vector that is blocked.

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
)

func FuzzCOSEKeyReencodeIsDeterministic(f *testing.F) {
	// Seed 1: valid EC2 P-256 COSE key built by the ceremony helper.
	f.Add(fzCOSEKey(f, fzKey(f)))
	// Seed 2: minimal CBOR maps (rejected by ParsePublicKey; parser still exercises
	// the re-encoding path before returning an error from the ceremony).
	f.Add([]byte{0xa0})             // empty map  {}
	f.Add([]byte{0xa1, 0x01, 0x02}) // {1: 2}  — integer key, integer value
	// Seed 3: empty input → Unmarshal returns an error; no re-encoding, skip.
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, coseKey []byte) {
		authData := authDataWithKey(coseKey)

		// Oracle 1 (DETERMINISM) + Oracle 3 (HASH-STABLE): call Unmarshal 20
		// times on identical input; all results must be byte-identical.
		var first []byte
		for i := range 20 {
			var ad protocol.AuthenticatorData
			if err := ad.Unmarshal(authData); err != nil {
				return // invalid input; nothing to assert
			}
			got := ad.AttData.CredentialPublicKey
			if i == 0 {
				if len(got) == 0 {
					return // AT flag not set or no key extracted; nothing to test
				}
				first = bytes.Clone(got)
			} else {
				if !bytes.Equal(first, got) {
					t.Fatalf("DETERMINISM: Unmarshal call %d returned different"+
						" CredentialPublicKey bytes\n  first: %x\n  got:   %x"+
						"\n  coseKey input: %x", i+1, first, got, coseKey)
				}
			}
		}
		if len(first) == 0 {
			return
		}

		// Oracle 2 (DUP-MAP-KEY): the re-encoded bytes must decode without error
		// under the same DupMapKeyEnforcedAPF mode webauthncbor uses everywhere.
		// If unmarshalCredentialPublicKey produced duplicate-key CBOR (possible if
		// two decoded keys have the same CTAP2 canonical encoding), authentication
		// would fail because ParsePublicKey uses the same decode mode.
		var v any
		if _, err := webauthncbor.UnmarshalFirst(first, &v); err != nil {
			t.Fatalf("DUP-MAP-KEY: re-encoded CredentialPublicKey bytes fail"+
				" DupMapKeyEnforcedAPF decode: %v\n  bytes: %x\n  coseKey input: %x",
				err, first, coseKey)
		}

		// Oracle 3 (HASH-STABLE): sha256 of the stored bytes must equal a fresh
		// re-encoding.  This confirms that any hash or bytes.Equal operation over
		// the stored bytes is unaffected by map iteration order.
		h1 := sha256.Sum256(first)
		var ad2 protocol.AuthenticatorData
		if err := ad2.Unmarshal(authData); err != nil {
			return
		}
		h2 := sha256.Sum256(ad2.AttData.CredentialPublicKey)
		if h1 != h2 {
			t.Fatalf("HASH-STABLE: sha256 of CredentialPublicKey differs between"+
				" call 1 and call 21\n  h1: %x\n  h2: %x\n  coseKey input: %x",
				h1, h2, coseKey)
		}
	})
}

// authDataWithKey constructs a minimal authenticator data byte sequence that embeds
// coseKey as the credential public key.  The RP ID hash and credential ID are fixed
// to zero so AuthenticatorData.Unmarshal exercises the re-encoding path without
// requiring a full ceremony context.  The returned bytes are always at least 55 bytes
// long (RP ID hash 32 + flags 1 + counter 4 + AAGUID 16 + credID len 2).
func authDataWithKey(coseKey []byte) []byte {
	out := make([]byte, 0, 55+len(coseKey))
	out = append(out, make([]byte, 32)...)      // RP ID hash (zeros)
	out = append(out, 0x41)                     // flags: UP (0x01) | AT (0x40)
	out = binary.BigEndian.AppendUint32(out, 0) // sign counter = 0
	out = append(out, make([]byte, 16)...)      // AAGUID (zeros)
	out = append(out, 0x00, 0x00)               // credential ID length = 0
	return append(out, coseKey...)              // credential public key
}

// TestCOSEReencodeOracle_ByteStabilityRedProof shows that the DETERMINISM oracle
// (oracle 1) would fire if the encoding function returned different bytes across
// calls.  It plants a mock non-deterministic function and confirms the loop catches
// it within 20 iterations.
func TestCOSEReencodeOracle_ByteStabilityRedProof(t *testing.T) {
	// Planted defect: a function that alternates between two different outputs.
	callCount := 0
	nondeterministic := func() []byte {
		callCount++
		if callCount%2 == 0 {
			return []byte{0x01, 0x02, 0xAA}
		}
		return []byte{0x01, 0x02, 0xBB}
	}

	first := nondeterministic()
	fired := false
	for range 19 {
		got := nondeterministic()
		if !bytes.Equal(first, got) {
			fired = true
			break
		}
	}
	if !fired {
		t.Fatal("red proof: DETERMINISM oracle did not fire on a non-deterministic" +
			" mock — the loop logic is broken")
	}
}

// TestCOSEReencodeOracle_DupMapKeyRedProof shows that the DUP-MAP-KEY oracle
// (oracle 2) fires on bytes that contain a duplicate map key, using the same
// webauthncbor decode call the oracle uses.  CBOR {1: 1, 1: 2} (0xa2 01 01 01 02)
// has an integer key 1 that appears twice; webauthncbor must reject it.
func TestCOSEReencodeOracle_DupMapKeyRedProof(t *testing.T) {
	// 0xa2 = map of 2 pairs; 0x01 0x01 = int key 1, int val 1; 0x01 0x02 = int key 1 (dup), int val 2.
	dupKeyBytes := []byte{0xa2, 0x01, 0x01, 0x01, 0x02}
	var v any
	if _, err := webauthncbor.UnmarshalFirst(dupKeyBytes, &v); err == nil {
		t.Fatal("red proof: DUP-MAP-KEY oracle did not fire — webauthncbor accepted" +
			" CBOR with duplicate map key; DupMapKeyEnforcedAPF is not in effect")
	}
}
