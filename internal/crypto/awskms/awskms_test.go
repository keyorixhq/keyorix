package awskms

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
)

// fakeKMS models AWS KMS EncryptionContext semantics: a blob decrypts only with the
// exact context it was encrypted under. The context is embedded in the blob so the
// fake is stateless.
type fakeKMS struct{}

type fakeBlob struct {
	Plaintext []byte            `json:"p"`
	Context   map[string]string `json:"c"`
}

func (fakeKMS) Encrypt(_ context.Context, in *kms.EncryptInput, _ ...func(*kms.Options)) (*kms.EncryptOutput, error) {
	b, _ := json.Marshal(fakeBlob{Plaintext: in.Plaintext, Context: in.EncryptionContext})
	return &kms.EncryptOutput{CiphertextBlob: b}, nil
}

func (fakeKMS) Decrypt(_ context.Context, in *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	var b fakeBlob
	if err := json.Unmarshal(in.CiphertextBlob, &b); err != nil {
		return nil, err
	}
	if !contextEqual(b.Context, in.EncryptionContext) {
		return nil, errors.New("InvalidCiphertextException: encryption context mismatch")
	}
	return &kms.DecryptOutput{Plaintext: b.Plaintext}, nil
}

func contextEqual(a, b map[string]string) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	return reflect.DeepEqual(a, b)
}

func newTestClient(encCtx map[string]string) *client {
	return &client{kms: fakeKMS{}, keyID: "test-key", encCtx: encCtx}
}

func TestAWSKMS_RoundTripWithContext(t *testing.T) {
	c := newTestClient(map[string]string{"keyorix-install": "inst-1"})
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

func TestAWSKMS_LegacyBlobDecryptsViaFallback(t *testing.T) {
	// A KEK wrapped before any context was configured (no EncryptionContext).
	legacy := newTestClient(nil)
	ct, _ := legacy.Encrypt(context.Background(), []byte("kek"))
	// Enabling the binding on a running install must not lock out that legacy blob.
	bound := newTestClient(map[string]string{"keyorix-install": "inst-1"})
	pt, err := bound.Decrypt(context.Background(), ct)
	if err != nil {
		t.Fatalf("legacy blob must decrypt via the no-context fallback: %v", err)
	}
	if string(pt) != "kek" {
		t.Fatalf("got %q", pt)
	}
}

func TestAWSKMS_CrossInstallDenied(t *testing.T) {
	a := newTestClient(map[string]string{"keyorix-install": "inst-A"})
	ct, _ := a.Encrypt(context.Background(), []byte("kek-A"))
	// A different install sharing the CMK must NOT be able to unwrap A's KEK — neither
	// with its own context nor via the no-context fallback.
	b := newTestClient(map[string]string{"keyorix-install": "inst-B"})
	if _, err := b.Decrypt(context.Background(), ct); err == nil {
		t.Fatal("install B must not unwrap install A's context-bound KEK")
	}
}
