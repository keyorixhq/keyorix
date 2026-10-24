package webauthnrp

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/keyorixhq/keyorix/internal/core/ports"
)

// The W3C NoneES256 test vectors (RPID "example.org"), the same bytes
// internal/core/webauthn_spec_vectors_test.go and go-webauthn's own suite use.
// The login assertion's authenticatorData flags are 0x19: user present, backup
// eligible/state, NOT user verified. Its signature counter is 0.
const (
	specLoginAuthenticatorDataHex = "bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b51900000000"
	specLoginClientDataJSONHex    = "7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a224f63446e55685158756c5455506f334a5558543049393770767a7a59425039745a63685879617630314167222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73657d"
	specLoginSignatureHex         = "3046022100f50a4e2e4409249c4a853ba361282f09841df4dd4547a13a87780218deffcd380221008480ac0f0b93538174f575bf11a1dd5d78c6e486013f937295ea13653e331e87"
	specCredentialIDHex           = "f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4" //nolint:gosec
	specLoginChallengeHex         = "39c0e7521417ba54d43e8dc95174f423dee9bf3cd804ff6d65c857c9abf4d408"
	specCredentialPubKeyHex       = "a5010203262001215820afefa16f97ca9b2d23eb86ccb64098d20db90856062eb249c33a9b672f26df61225820930a56b87a2fca66334b03458abf879717c12cc68ed73290af2e2664796b9220"
)

func specHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// specRP is the adapter configured for the vectors' RP ID and origin.
func specRP(t *testing.T) ports.WebAuthnRelyingParty {
	t.Helper()
	rp, err := New(Config{RPID: "example.org", RPDisplayName: "Keyorix", RPOrigins: []string{"https://example.org"}})
	if err != nil {
		t.Fatal(err)
	}
	return rp
}

func specUserID(id uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, id)
	return b
}

// specStoredCredential is the vector's credential as a stored blob, with the
// given signature counter already on record.
func specStoredCredential(t *testing.T, rp ports.WebAuthnRelyingParty, signCount uint32) ports.WebAuthnCredential {
	t.Helper()
	blob, err := json.Marshal(webauthn.Credential{
		ID:            specHex(t, specCredentialIDHex),
		PublicKey:     specHex(t, specCredentialPubKeyHex),
		Flags:         webauthn.CredentialFlags{UserPresent: true, BackupEligible: true},
		Authenticator: webauthn.Authenticator{SignCount: signCount},
	})
	if err != nil {
		t.Fatal(err)
	}
	cred, err := rp.DecodeCredential(blob)
	if err != nil {
		t.Fatal(err)
	}
	return cred
}

func specUser(t *testing.T, rp ports.WebAuthnRelyingParty, signCount uint32) ports.WebAuthnUser {
	t.Helper()
	return ports.WebAuthnUser{ID: specUserID(1), Name: "alice", DisplayName: "alice",
		Credentials: []ports.WebAuthnCredential{specStoredCredential(t, rp, signCount)}}
}

// specAssertion parses the login vector; userHandle is set for the
// discoverable (passwordless) path.
func specAssertion(t *testing.T, userHandle []byte) *protocol.ParsedCredentialAssertionData {
	t.Helper()
	id := base64.RawURLEncoding.EncodeToString(specHex(t, specCredentialIDHex))
	resp := map[string]any{
		"authenticatorData": base64.RawURLEncoding.EncodeToString(specHex(t, specLoginAuthenticatorDataHex)),
		"clientDataJSON":    base64.RawURLEncoding.EncodeToString(specHex(t, specLoginClientDataJSONHex)),
		"signature":         base64.RawURLEncoding.EncodeToString(specHex(t, specLoginSignatureHex)),
	}
	if userHandle != nil {
		resp["userHandle"] = base64.RawURLEncoding.EncodeToString(userHandle)
	}
	data, err := json.Marshal(map[string]any{"id": id, "rawId": id, "type": "public-key", "response": resp})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

// withSpecChallenge points a session this adapter began at the vector's
// challenge (the vector is signed over that fixed challenge) and leaves every
// other field, user verification included, as the adapter set it.
func withSpecChallenge(t *testing.T, s ports.WebAuthnSession) ports.WebAuthnSession {
	t.Helper()
	sd, ok := s.(*webauthn.SessionData)
	if !ok {
		t.Fatalf("session is %T", s)
	}
	cp := *sd
	cp.Challenge = base64.RawURLEncoding.EncodeToString(specHex(t, specLoginChallengeHex))
	return &cp
}
