package webauthnparse

// FuzzCOSEKeyReencodeIsDeterministic checks that the COSE credential public
// key Keyorix would store is byte-stable. go-webauthn@v0.18.2 does not store the
// key bytes the authenticator sent: unmarshalCredentialPublicKey
// (protocol/authenticator.go:384-396) decodes them into any and re-encodes them
// with CTAP2 canonical options, and that re-encoding becomes
// Credential.PublicKey.
//
// Background (KFZ-2026-153, private disclosure to the fxamacker/cbor maintainer):
// fxamacker/cbor v2.9.x re-encodes a decoded map[any]any non-deterministically
// when two distinct Go map keys have the same CTAP2 canonical encoding. The
// specific KFZ-2026-153 vector (an integer-0 key and a tag-1-time-0 key) is
// refused by webauthncbor's TagsForbidden decode option before any re-encoding.
// That guard does not cover every input: some untagged inputs still re-encode
// differently from call to call (details in the private KFZ-2026-153 notes,
// follow-up to the review of 2c481769). The registration ceremony refuses
// all known inputs of this kind before it stores a credential, so the property
// Keyorix depends on, and the one this target asserts, is narrower: every key
// the ceremony would accept re-encodes to the same bytes every time.
//
// Live caller chain:
//
//	server/http/handlers/webauthn.go:68
//	  → protocol.ParseCredentialCreationResponseBytes (attacker-supplied bytes)
//	  → AuthenticatorData.Unmarshal → unmarshalCredentialPublicKey (re-encode)
//	  → core.FinishWebAuthnRegistration → webauthn.CreateCredential (ceremony)
//	  → CreateWebAuthnCredential (stored), re-decoded during authentication
//
// Oracles (checkCOSEReencode, shared with the red-proof tests below):
//   - ACCEPTANCE: the coseReencodeCalls calls of AuthenticatorData.Unmarshal on
//     the same input all succeed or all fail.
//   - DETERMINISM: if the calls return different CredentialPublicKey bytes, the
//     real registration ceremony (webauthn.CreateCredential, "none" attestation,
//     run coseReencodeCalls times) must refuse the key every time.
//   - DUP-MAP-KEY: stable bytes decode via webauthncbor.UnmarshalFirst, the
//     DupMapKeyEnforcedAPF mode used throughout webauthncbor, without error.
//
// What this target does NOT verify, and skips silently:
//   - inputs whose re-encoding differs between calls but which the ceremony
//     refuses: they never reach storage. The ceremony check is the condition this
//     skip rests on, and it runs on every such input rather than being assumed.
//   - that a stored key is cryptographically valid, or that attestation formats
//     other than "none" accept it (they run the same step-16 key decode first).
//   - credential.Verify's bytes.Equal path (Keyorix does not call that method).
//
// Private test data (NOT committed; .scratch/private/): the KFZ-2026-153 example
// and the untagged input found by the 2c481769 review. Both are refused by the
// ceremony; they are kept out of the tree because the upstream issue is open.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
)

// coseReencodeCalls is how often each oracle repeats a call; map iteration
// order varies per call, so one call cannot show non-determinism.
const coseReencodeCalls = 20

// coseReencodeProbe is the code under test: the live one in the fuzz target, a
// planted one in the red-proof tests, so both run the same checkCOSEReencode.
type coseReencodeProbe struct {
	// reencode returns the CredentialPublicKey that go-webauthn would keep for coseKey.
	reencode func(coseKey []byte) ([]byte, error)
	// stored reports whether the registration ceremony accepts a credential carrying coseKey.
	stored func(tb testing.TB, coseKey []byte) bool
}

var liveCOSEReencodeProbe = coseReencodeProbe{reencode: reencodeViaAuthData, stored: registrationStoresKey}

func FuzzCOSEKeyReencodeIsDeterministic(f *testing.F) {
	// Seed 1: valid EC2 P-256 COSE key built by the ceremony helper.
	f.Add(fzCOSEKey(f, fzKey(f)))
	// Seed 2: minimal CBOR maps (rejected by ParsePublicKey; parser still exercises
	// the re-encoding path before returning an error from the ceremony).
	f.Add([]byte{0xa0})             // empty map  {}
	f.Add([]byte{0xa1, 0x01, 0x02}) // {1: 2}  — integer key, integer value
	// Seed 3: empty input → Unmarshal returns an error; no re-encoding.
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, coseKey []byte) {
		if err := checkCOSEReencode(t, liveCOSEReencodeProbe, coseKey); err != nil {
			t.Fatalf("%v\n  coseKey input: %x", err, coseKey)
		}
	})
}

// checkCOSEReencode applies the three oracles to one input and returns the first
// violation, or nil.
func checkCOSEReencode(tb testing.TB, p coseReencodeProbe, coseKey []byte) error {
	tb.Helper()
	first, firstErr := p.reencode(coseKey)
	first = bytes.Clone(first)
	var diverged []byte
	divergedAt := 0
	for i := 2; i <= coseReencodeCalls; i++ {
		got, err := p.reencode(coseKey)
		if (err == nil) != (firstErr == nil) {
			return fmt.Errorf("ACCEPTANCE: Unmarshal call %d returned err=%v, call 1 returned err=%v", i, err, firstErr)
		}
		if err == nil && divergedAt == 0 && !bytes.Equal(first, got) {
			diverged, divergedAt = bytes.Clone(got), i
		}
	}
	if firstErr != nil {
		return nil // refused by every call; nothing is stored
	}
	if divergedAt != 0 {
		for range coseReencodeCalls {
			if p.stored(tb, coseKey) {
				return fmt.Errorf("DETERMINISM: Unmarshal call %d returned different CredentialPublicKey"+
					" bytes and the registration ceremony accepts this key\n  call 1: %x\n  call %d: %x",
					divergedAt, first, divergedAt, diverged)
			}
		}
		return nil // the ceremony refuses the key; it never reaches storage
	}
	if len(first) == 0 {
		return nil // AT flag not set or no key extracted
	}
	var v any
	if _, err := webauthncbor.UnmarshalFirst(first, &v); err != nil {
		return fmt.Errorf("DUP-MAP-KEY: re-encoded CredentialPublicKey bytes fail"+
			" DupMapKeyEnforcedAPF decode: %v\n  bytes: %x", err, first)
	}
	return nil
}

// reencodeViaAuthData runs the production parse, AuthenticatorData.Unmarshal,
// on authenticator data carrying coseKey and returns the key it keeps.
func reencodeViaAuthData(coseKey []byte) ([]byte, error) {
	var ad protocol.AuthenticatorData
	if err := ad.Unmarshal(authDataWithKey(coseKey)); err != nil {
		return nil, err
	}
	return ad.AttData.CredentialPublicKey, nil
}

// registrationStoresKey reports whether webauthn.CreateCredential, the call
// FinishWebAuthnRegistration makes before it stores a credential, accepts a
// "none" attestation whose attested credential data carries coseKey. Everything
// else in the response is valid for fzRP and fzSession.
func registrationStoresKey(tb testing.TB, coseKey []byte) bool {
	tb.Helper()
	attested := append(append(make([]byte, 16), byte(len(fzCredID)>>8), byte(len(fzCredID))), fzCredID...)
	authData := fzAuthData(tb, 0x45, append(attested, coseKey...)) // UP | UV | AT
	att, err := webauthncbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": authData})
	if err != nil {
		tb.Fatal(err)
	}
	pcc, err := protocol.ParseCredentialCreationResponseBytes(registrationWith(tb, att))
	if err != nil {
		return false
	}
	_, err = fzRP(tb).CreateCredential(fzUser{}, fzSession(), pcc)
	return err == nil
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

// otherP256Key is a second fixed P-256 key, distinct from fzKey.
func otherP256Key(tb testing.TB) *ecdsa.PrivateKey {
	tb.Helper()
	d := sha256.Sum256([]byte("keyorix webauthnparse cose re-encode second key"))
	k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d[:])
	if err != nil {
		tb.Fatal(err)
	}
	return k
}

// alternating returns a planted reencode that alternates between a and b.
func alternating(a, b []byte) func([]byte) ([]byte, error) {
	calls := 0
	return func([]byte) ([]byte, error) {
		calls++
		if calls%2 == 0 {
			return b, nil
		}
		return a, nil
	}
}

// TestCOSEReencodeOracle_LiveProbeGreenAndGate is the green direction: the live
// probe passes the valid seed key, and the ceremony gate accepts that key and
// refuses a key without the algorithm parameter, so the gate is neither
// always-true nor always-false.
func TestCOSEReencodeOracle_LiveProbeGreenAndGate(t *testing.T) {
	valid := fzCOSEKey(t, fzKey(t))
	if err := checkCOSEReencode(t, liveCOSEReencodeProbe, valid); err != nil {
		t.Fatalf("live probe fails on the valid seed key: %v", err)
	}
	if !registrationStoresKey(t, valid) {
		t.Fatal("gate: the registration ceremony refuses the valid seed key")
	}
	if registrationStoresKey(t, []byte{0xa1, 0x01, 0x02}) { // {1: 2}, no alg
		t.Fatal("gate: the registration ceremony accepts a key without an algorithm")
	}
}

// TestCOSEReencodeOracle_DeterminismRedProof plants a re-encoding that
// alternates between two keys the ceremony accepts: DETERMINISM must fire. The
// gate is the live ceremony, not a mock.
func TestCOSEReencodeOracle_DeterminismRedProof(t *testing.T) {
	k1, k2 := fzCOSEKey(t, fzKey(t)), fzCOSEKey(t, otherP256Key(t))
	p := coseReencodeProbe{reencode: alternating(k1, k2), stored: registrationStoresKey}
	if err := checkCOSEReencode(t, p, k1); err == nil || !strings.HasPrefix(err.Error(), "DETERMINISM") {
		t.Fatalf("DETERMINISM oracle did not fire on a non-deterministic re-encoding of an accepted key: %v", err)
	}
}

// TestCOSEReencodeOracle_DivergenceOnRefusedKeyIsSkipped is the skip, stated as
// a test: the same planted divergence on a key the ceremony refuses is not a
// violation, because that key is never stored.
func TestCOSEReencodeOracle_DivergenceOnRefusedKeyIsSkipped(t *testing.T) {
	refused := []byte{0xa1, 0x01, 0x02} // {1: 2}, no alg
	p := coseReencodeProbe{reencode: alternating([]byte{0xa0}, refused), stored: registrationStoresKey}
	if err := checkCOSEReencode(t, p, refused); err != nil {
		t.Fatalf("divergence on a refused key reported as a violation: %v", err)
	}
}

// TestCOSEReencodeOracle_AcceptanceRedProof plants a parse that succeeds once
// and then fails: ACCEPTANCE must fire instead of the input being skipped.
func TestCOSEReencodeOracle_AcceptanceRedProof(t *testing.T) {
	calls := 0
	p := coseReencodeProbe{
		reencode: func([]byte) ([]byte, error) {
			calls++
			if calls > 1 {
				return nil, fmt.Errorf("planted failure on call %d", calls)
			}
			return []byte{0xa0}, nil
		},
		stored: func(testing.TB, []byte) bool { return false },
	}
	if err := checkCOSEReencode(t, p, []byte{0xa0}); err == nil || !strings.HasPrefix(err.Error(), "ACCEPTANCE") {
		t.Fatalf("ACCEPTANCE oracle did not fire when a later call failed: %v", err)
	}
}

// TestCOSEReencodeOracle_DupMapKeyRedProof plants a stable re-encoding with a
// duplicate map key, CBOR {1: 1, 1: 2} (0xa2 01 01 01 02): DUP-MAP-KEY must fire.
func TestCOSEReencodeOracle_DupMapKeyRedProof(t *testing.T) {
	dupKeyBytes := []byte{0xa2, 0x01, 0x01, 0x01, 0x02}
	p := coseReencodeProbe{
		reencode: func([]byte) ([]byte, error) { return dupKeyBytes, nil },
		stored:   func(testing.TB, []byte) bool { return true },
	}
	if err := checkCOSEReencode(t, p, dupKeyBytes); err == nil || !strings.HasPrefix(err.Error(), "DUP-MAP-KEY") {
		t.Fatalf("DUP-MAP-KEY oracle did not fire on duplicate-key bytes: %v", err)
	}
}
