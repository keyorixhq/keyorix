package awskms

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
)

// fakeKMSError always returns an error from Encrypt.
type fakeKMSEncryptError struct{}

func (fakeKMSEncryptError) Encrypt(_ context.Context, _ *kms.EncryptInput, _ ...func(*kms.Options)) (*kms.EncryptOutput, error) {
	return nil, errors.New("KMSAccessDeniedException: not authorized")
}

func (fakeKMSEncryptError) Decrypt(_ context.Context, _ *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	return nil, errors.New("KMSAccessDeniedException: not authorized")
}

// TestAWSKMS_EncryptError verifies Encrypt propagates KMS errors.
func TestAWSKMS_EncryptError(t *testing.T) {
	c := &client{kms: fakeKMSEncryptError{}, keyID: "test-key"}
	_, err := c.Encrypt(context.Background(), []byte("data"))
	if err == nil {
		t.Fatal("expected an error from a failing KMS Encrypt")
	}
}

// TestAWSKMS_RoundTripNoContext verifies round-trip when no encryption context is set.
func TestAWSKMS_RoundTripNoContext(t *testing.T) {
	c := newTestClient(nil, false)
	ct, err := c.Encrypt(context.Background(), []byte("no-context-kek"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	pt, err := c.Decrypt(context.Background(), ct)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(pt) != "no-context-kek" {
		t.Fatalf("round-trip got %q", pt)
	}
}

// TestAWSKMS_DecryptError verifies Decrypt propagates a KMS error (both with and
// without the context-fallback path) when the underlying client always fails.
func TestAWSKMS_DecryptError(t *testing.T) {
	// With no context and no fallback — simple error propagation.
	c := &client{kms: fakeKMSEncryptError{}, keyID: "test-key"}
	_, err := c.Decrypt(context.Background(), []byte("blob"))
	if err == nil {
		t.Fatal("expected an error from a failing KMS Decrypt (no context)")
	}

	// With a context set but fallback off — the context is used, and the error
	// from the failing KMS must propagate without a retry.
	c2 := &client{kms: fakeKMSEncryptError{}, keyID: "test-key", encCtx: map[string]string{"k": "v"}, allowFallback: false}
	_, err = c2.Decrypt(context.Background(), []byte("blob"))
	if err == nil {
		t.Fatal("expected an error from a failing KMS Decrypt (context, no fallback)")
	}

	// With a context set AND fallback on — the first attempt (with context) fails,
	// the second attempt (without context) also fails; the final error must be
	// non-nil.
	c3 := &client{kms: fakeKMSEncryptError{}, keyID: "test-key", encCtx: map[string]string{"k": "v"}, allowFallback: true}
	_, err = c3.Decrypt(context.Background(), []byte("blob"))
	if err == nil {
		t.Fatal("expected an error from a failing KMS Decrypt (context + fallback both fail)")
	}
}

// TestAWSKMS_New_EmptyKeyID verifies New returns an error for an empty key ID.
// (New itself cannot be tested without real AWS credentials, but the empty-key
// guard fires before any network call.)
func TestAWSKMS_New_EmptyKeyID(t *testing.T) {
	_, err := New(context.Background(), "", nil, false)
	if err == nil {
		t.Fatal("expected an error for an empty key ID")
	}
}
