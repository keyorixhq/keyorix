// Package awskms implements crypto.KMSClient against AWS KMS (ADR-041). It is the
// only place the AWS KMS SDK is imported, keeping internal/crypto cloud-SDK-free.
// Region and credentials come from the standard AWS chain (env, instance profile,
// IRSA, …) — never from Keyorix config.
package awskms

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	keyorixcrypto "github.com/keyorixhq/keyorix/internal/crypto"
)

type client struct {
	kms   *kms.Client
	keyID string
}

// New builds an AWS-KMS-backed crypto.KMSClient for the given key (ID, ARN, or
// alias). It loads the default AWS config; the caller's environment supplies the
// region and credentials.
func New(ctx context.Context, keyID string) (keyorixcrypto.KMSClient, error) {
	if keyID == "" {
		return nil, fmt.Errorf("aws-kms: kms_key_id is required")
	}
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("aws-kms: load AWS config: %w", err)
	}
	return &client{kms: kms.NewFromConfig(cfg), keyID: keyID}, nil
}

func (c *client) Encrypt(ctx context.Context, plaintext []byte) ([]byte, error) {
	out, err := c.kms.Encrypt(ctx, &kms.EncryptInput{KeyId: &c.keyID, Plaintext: plaintext})
	if err != nil {
		return nil, err
	}
	return out.CiphertextBlob, nil
}

func (c *client) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	// Pin KeyId so the blob is only decryptable by the expected CMK.
	out, err := c.kms.Decrypt(ctx, &kms.DecryptInput{CiphertextBlob: ciphertext, KeyId: &c.keyID})
	if err != nil {
		return nil, err
	}
	return out.Plaintext, nil
}
