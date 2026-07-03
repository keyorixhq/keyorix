package gcpkms

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
	gax "github.com/googleapis/gax-go/v2"
)

// fakeKMS models GCP KMS AAD semantics: a blob decrypts only with the exact
// AdditionalAuthenticatedData it was encrypted under. The AAD is embedded in the
// ciphertext so the fake is stateless.
type fakeKMS struct{}

type fakeBlob struct {
	Plaintext []byte `json:"p"`
	AAD       []byte `json:"a"`
}

func (fakeKMS) Encrypt(_ context.Context, req *kmspb.EncryptRequest, _ ...gax.CallOption) (*kmspb.EncryptResponse, error) {
	b, _ := json.Marshal(fakeBlob{Plaintext: req.Plaintext, AAD: req.AdditionalAuthenticatedData})
	return &kmspb.EncryptResponse{Ciphertext: b}, nil
}

func (fakeKMS) Decrypt(_ context.Context, req *kmspb.DecryptRequest, _ ...gax.CallOption) (*kmspb.DecryptResponse, error) {
	var b fakeBlob
	if err := json.Unmarshal(req.Ciphertext, &b); err != nil {
		return nil, err
	}
	if !bytes.Equal(b.AAD, req.AdditionalAuthenticatedData) {
		return nil, errors.New("decryption failed: AAD mismatch")
	}
	return &kmspb.DecryptResponse{Plaintext: b.Plaintext}, nil
}

func newTestClient(encCtx map[string]string, allowFallback bool) *client {
	return &client{kms: fakeKMS{}, keyName: "projects/p/locations/l/keyRings/r/cryptoKeys/k", aad: encContextAAD(encCtx), allowFallback: allowFallback}
}

func TestGCPKMS_RoundTripWithContext(t *testing.T) {
	c := newTestClient(map[string]string{"keyorix-install": "inst-1"}, false)
	ct, err := c.Encrypt(context.Background(), []byte("kek-material"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	pt, err := c.Decrypt(context.Background(), ct)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(pt) != "kek-material" {
		t.Fatalf("round-trip got %q", pt)
	}
}

// #123: with the fallback OFF (the default), an AAD-less blob — the exact shape an
// attacker with encrypt permission on a shared CMK (but not Keyorix's own data) would
// plant — must NOT decrypt against an AAD-bound client.
func TestGCPKMS_FallbackDisabledByDefault_PlantedNoAADBlobRejected(t *testing.T) {
	planted := newTestClient(nil, false)
	ct, _ := planted.Encrypt(context.Background(), []byte("malicious-kek"))
	bound := newTestClient(map[string]string{"keyorix-install": "inst-1"}, false)
	if _, err := bound.Decrypt(context.Background(), ct); err == nil {
		t.Fatal("a no-AAD blob must NOT decrypt against an AAD-bound client when kms_allow_context_fallback is off")
	}
}

// With kms_allow_context_fallback explicitly enabled, a legacy no-AAD blob DOES
// decrypt — preserving the documented migration path.
func TestGCPKMS_FallbackEnabled_LegacyBlobDecryptsAsMigrationAid(t *testing.T) {
	legacy := newTestClient(nil, false)
	ct, _ := legacy.Encrypt(context.Background(), []byte("kek"))
	bound := newTestClient(map[string]string{"keyorix-install": "inst-1"}, true)
	pt, err := bound.Decrypt(context.Background(), ct)
	if err != nil {
		t.Fatalf("legacy blob must decrypt via the explicitly-enabled fallback: %v", err)
	}
	if string(pt) != "kek" {
		t.Fatalf("got %q", pt)
	}
}

func TestGCPKMS_CrossInstallDenied(t *testing.T) {
	a := newTestClient(map[string]string{"keyorix-install": "inst-A"}, false)
	ct, _ := a.Encrypt(context.Background(), []byte("kek-A"))
	b := newTestClient(map[string]string{"keyorix-install": "inst-B"}, false)
	if _, err := b.Decrypt(context.Background(), ct); err == nil {
		t.Fatal("install B must not unwrap install A's AAD-bound KEK")
	}
}

// Cross-install isolation between two DIFFERENTLY-bound installs holds regardless of
// the fallback setting; only a no-AAD blob benefits from it.
func TestGCPKMS_CrossInstallDenied_EvenWithFallbackEnabled(t *testing.T) {
	a := newTestClient(map[string]string{"keyorix-install": "inst-A"}, false)
	ct, _ := a.Encrypt(context.Background(), []byte("kek-A"))
	b := newTestClient(map[string]string{"keyorix-install": "inst-B"}, true)
	if _, err := b.Decrypt(context.Background(), ct); err == nil {
		t.Fatal("install B must not unwrap install A's AAD-bound KEK even with its own fallback enabled")
	}
}

func TestEncContextAAD_DeterministicAndEmpty(t *testing.T) {
	if encContextAAD(nil) != nil || encContextAAD(map[string]string{}) != nil {
		t.Fatal("empty context must produce nil AAD (byte-identical to no binding)")
	}
	a := encContextAAD(map[string]string{"b": "2", "a": "1"})
	b := encContextAAD(map[string]string{"a": "1", "b": "2"})
	if !bytes.Equal(a, b) {
		t.Fatal("AAD must be deterministic regardless of map iteration order")
	}
}
