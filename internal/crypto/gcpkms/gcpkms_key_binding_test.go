package gcpkms

// KEYCOMMIT-2 item 3: which key a wrapped-KEK blob is decrypted under. The GCP
// ciphertext is opaque to Keyorix (no key id or version field is parsed, none is
// added), so the only key binding the client controls is the request: Name is the
// configured crypto key on every Encrypt and Decrypt. This pins that, with the stub
// client. It does NOT verify what Cloud KMS embeds in a real ciphertext (not
// exercisable without the cloud), or the CRC32C handling (other tests).

import (
	"context"
	"testing"
)

func TestGCPKMS_EncryptAndDecryptPinTheConfiguredKeyName(t *testing.T) {
	cap := &capturingKMS{}
	c := &client{kms: cap, keyName: "projects/p/locations/l/keyRings/r/cryptoKeys/configured", aad: encContextAAD(map[string]string{"install": "a"})}

	ct, err := c.Encrypt(context.Background(), []byte("kek-material-32-bytes-long......"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if got := cap.lastEncryptReq.GetName(); got != c.keyName {
		t.Fatalf("Encrypt sent Name %q, want the configured key %q", got, c.keyName)
	}
	if _, err := c.Decrypt(context.Background(), ct); err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if got := cap.lastDecryptReq.GetName(); got != c.keyName {
		t.Fatalf("Decrypt sent Name %q, want the configured key %q", got, c.keyName)
	}

	// The blob names nothing: a blob that embeds another key's name (here, as extra
	// JSON the stub ignores) cannot redirect the request.
	forged := append([]byte(nil), ct...)
	forged = append(forged[:len(forged)-1], []byte(`,"name":"projects/p/locations/l/keyRings/r/cryptoKeys/attacker"}`)...)
	_, _ = c.Decrypt(context.Background(), forged)
	if got := cap.lastDecryptReq.GetName(); got != c.keyName {
		t.Fatalf("a blob carrying a key name redirected Decrypt to %q", got)
	}
}
