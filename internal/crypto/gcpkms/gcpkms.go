// Package gcpkms implements crypto.KMSClient against Google Cloud KMS (ADR-041).
// Like the awskms package, it is the only place the GCP KMS SDK is imported, so
// internal/crypto stays cloud-SDK-free. Credentials come from Application Default
// Credentials (GOOGLE_APPLICATION_CREDENTIALS / workload identity), never from
// Keyorix config. GCP KMS decrypts with the named crypto key, so the key is
// inherently pinned (the ciphertext cannot select a different key).
package gcpkms

import (
	"context"
	"fmt"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	keyorixcrypto "github.com/keyorixhq/keyorix/internal/crypto"
)

type client struct {
	kms     *kms.KeyManagementClient
	keyName string // projects/P/locations/L/keyRings/R/cryptoKeys/K
}

// New builds a GCP-KMS-backed crypto.KMSClient for the given crypto-key resource
// name (projects/.../cryptoKeys/...).
func New(ctx context.Context, keyName string) (keyorixcrypto.KMSClient, error) {
	if keyName == "" {
		return nil, fmt.Errorf("gcp-kms: kms_key_id (crypto key resource name) is required")
	}
	c, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("gcp-kms: create client: %w", err)
	}
	return &client{kms: c, keyName: keyName}, nil
}

func (c *client) Encrypt(ctx context.Context, plaintext []byte) ([]byte, error) {
	resp, err := c.kms.Encrypt(ctx, &kmspb.EncryptRequest{Name: c.keyName, Plaintext: plaintext})
	if err != nil {
		return nil, err
	}
	return resp.GetCiphertext(), nil
}

func (c *client) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	resp, err := c.kms.Decrypt(ctx, &kmspb.DecryptRequest{Name: c.keyName, Ciphertext: ciphertext})
	if err != nil {
		return nil, err
	}
	return resp.GetPlaintext(), nil
}
