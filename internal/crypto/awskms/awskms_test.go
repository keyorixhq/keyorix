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

func newTestClient(encCtx map[string]string, allowFallback bool) *client {
	return &client{kms: fakeKMS{}, keyID: "test-key", encCtx: encCtx, allowFallback: allowFallback}
}

func TestAWSKMS_RoundTripWithContext(t *testing.T) {
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

// #123: with the fallback OFF (the default), a blob with no encryption context — the
// exact shape an attacker with kms:Encrypt on a shared CMK (but not Keyorix's own
// data) would plant — must NOT decrypt against a context-bound client. This is the
// actual security property the backlog finding demands; before the fix, the
// unconditional fallback made it fail.
func TestAWSKMS_FallbackDisabledByDefault_PlantedNoContextBlobRejected(t *testing.T) {
	planted := newTestClient(nil, false) // simulates an attacker's own Encrypt call, no context
	ct, _ := planted.Encrypt(context.Background(), []byte("malicious-kek"))
	bound := newTestClient(map[string]string{"keyorix-install": "inst-1"}, false) // allowFallback OFF
	if _, err := bound.Decrypt(context.Background(), ct); err == nil {
		t.Fatal("a no-context blob must NOT decrypt against a context-bound client when kms_allow_context_fallback is off")
	}
}

// With kms_allow_context_fallback explicitly enabled (a deliberate, transient
// migration aid), a legacy no-context blob DOES decrypt — preserving the documented
// migration path for an install enabling the binding on an already-wrapped KEK.
func TestAWSKMS_FallbackEnabled_LegacyBlobDecryptsAsMigrationAid(t *testing.T) {
	legacy := newTestClient(nil, false)
	ct, _ := legacy.Encrypt(context.Background(), []byte("kek"))
	bound := newTestClient(map[string]string{"keyorix-install": "inst-1"}, true) // allowFallback ON
	pt, err := bound.Decrypt(context.Background(), ct)
	if err != nil {
		t.Fatalf("legacy blob must decrypt via the explicitly-enabled fallback: %v", err)
	}
	if string(pt) != "kek" {
		t.Fatalf("got %q", pt)
	}
}

func TestAWSKMS_CrossInstallDenied(t *testing.T) {
	a := newTestClient(map[string]string{"keyorix-install": "inst-A"}, false)
	ct, _ := a.Encrypt(context.Background(), []byte("kek-A"))
	// A different install sharing the CMK must NOT be able to unwrap A's KEK — neither
	// with its own context nor via the no-context fallback (fallback off here, the
	// default; TestAWSKMS_CrossInstallDenied_EvenWithFallbackEnabled covers the other case).
	b := newTestClient(map[string]string{"keyorix-install": "inst-B"}, false)
	if _, err := b.Decrypt(context.Background(), ct); err == nil {
		t.Fatal("install B must not unwrap install A's context-bound KEK")
	}
}

// Even with the fallback explicitly enabled, install B's OWN context still doesn't
// match install A's blob, and the fallback only drops B's context — it never tries A's.
// So cross-install isolation between two DIFFERENTLY-context-bound installs holds
// regardless of the fallback setting; only a no-context blob benefits from it.
func TestAWSKMS_CrossInstallDenied_EvenWithFallbackEnabled(t *testing.T) {
	a := newTestClient(map[string]string{"keyorix-install": "inst-A"}, false)
	ct, _ := a.Encrypt(context.Background(), []byte("kek-A"))
	b := newTestClient(map[string]string{"keyorix-install": "inst-B"}, true)
	if _, err := b.Decrypt(context.Background(), ct); err == nil {
		t.Fatal("install B must not unwrap install A's context-bound KEK even with its own fallback enabled")
	}
}
