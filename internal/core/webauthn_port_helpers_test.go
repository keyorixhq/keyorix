package core

import (
	"encoding/json"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/keyorixhq/keyorix/internal/core/ports"
)

// Test-only bridges between the go-webauthn library types the existing tests
// build and the ports.WebAuthnRelyingParty values core now takes
// (CORE-DECOUPLE-WEBAUTHN-1). They only change the type a test passes or
// inspects; every assertion stays as it was.

// verifiedFrom is what internal/webauthnrp returns for a verified credential.
func verifiedFrom(cred *webauthn.Credential) ports.WebAuthnVerified {
	return ports.WebAuthnVerified{
		ID:           cred.ID,
		SignCount:    cred.Authenticator.SignCount,
		CloneWarning: cred.Authenticator.CloneWarning,
		Credential:   cred,
	}
}

// credOf is a decoded stored credential (loadWebAuthnUser's wu.creds entry).
func credOf(t *testing.T, c ports.WebAuthnCredential) *webauthn.Credential {
	t.Helper()
	cred, ok := c.(*webauthn.Credential)
	if !ok {
		t.Fatalf("stored credential decoded to %T, want *webauthn.Credential", c)
	}
	return cred
}

// creationOpts decodes BeginWebAuthnRegistration's options JSON.
func creationOpts(t *testing.T, raw json.RawMessage) protocol.PublicKeyCredentialCreationOptions {
	t.Helper()
	var o protocol.PublicKeyCredentialCreationOptions
	if err := json.Unmarshal(raw, &o); err != nil {
		t.Fatalf("decode creation options: %v", err)
	}
	return o
}

// assertionOpts decodes a Begin*Login/Reauth options JSON.
func assertionOpts(t *testing.T, raw json.RawMessage) protocol.PublicKeyCredentialRequestOptions {
	t.Helper()
	var o protocol.PublicKeyCredentialRequestOptions
	if err := json.Unmarshal(raw, &o); err != nil {
		t.Fatalf("decode assertion options: %v", err)
	}
	return o
}
