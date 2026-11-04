package gcpkms

import (
	"bytes"
	"context"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
	gax "github.com/googleapis/gax-go/v2"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// heldPlaintextBadCRCKMS returns the slice it holds as the decrypt plaintext,
// with a checksum that does not match it, so the buffer Decrypt discards on
// the checksum-mismatch return is observable after the call.
type heldPlaintextBadCRCKMS struct {
	plaintext []byte
}

func (heldPlaintextBadCRCKMS) Encrypt(context.Context, *kmspb.EncryptRequest, ...gax.CallOption) (*kmspb.EncryptResponse, error) {
	panic("not used")
}

func (k heldPlaintextBadCRCKMS) Decrypt(context.Context, *kmspb.DecryptRequest, ...gax.CallOption) (*kmspb.DecryptResponse, error) {
	return &kmspb.DecryptResponse{
		Plaintext:       k.plaintext,
		PlaintextCrc32C: wrapperspb.Int64(int64(crc32cSum(k.plaintext)) + 1),
	}, nil
}

// REVIEW-3947 F1: on a PlaintextCrc32C mismatch DecryptReportingFallback
// dropped the response plaintext without clearing it. A corrupted checksum
// field with an intact payload leaves the real KEK in that buffer.
func TestDecrypt_CRCMismatchZeroesPlaintext(t *testing.T) {
	leaked := []byte("fedcba9876543210fedcba9876543210")
	if bytes.Equal(leaked, make([]byte, len(leaked))) {
		t.Fatal("fixture must start non-zero")
	}

	c := &client{kms: heldPlaintextBadCRCKMS{plaintext: leaked}, keyName: "k"}
	pt, err := c.Decrypt(context.Background(), []byte("ct"))
	if err == nil {
		t.Fatal("expected a checksum-mismatch error")
	}
	if pt != nil {
		t.Fatalf("no key material may be returned with the error, got %d bytes", len(pt))
	}
	if !bytes.Equal(leaked, make([]byte, len(leaked))) {
		t.Fatalf("the discarded plaintext must be zeroed, still %q", leaked)
	}
}
