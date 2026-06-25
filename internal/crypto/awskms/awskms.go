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

// awsKMSAPI is the slice of the KMS client the provider uses — an interface seam so
// the SDK stays contained here and the encryption-context fallback is unit-testable.
type awsKMSAPI interface {
	Encrypt(ctx context.Context, in *kms.EncryptInput, optFns ...func(*kms.Options)) (*kms.EncryptOutput, error)
	Decrypt(ctx context.Context, in *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error)
}

type client struct {
	kms    awsKMSAPI
	keyID  string
	encCtx map[string]string // AWS EncryptionContext bound to the wrapped KEK (may be empty)
}

// New builds an AWS-KMS-backed crypto.KMSClient for the given key (ID, ARN, or
// alias). It loads the default AWS config; the caller's environment supplies the
// region and credentials. encContext, when non-empty, is bound to the wrapped KEK so
// a different install sharing the same CMK cannot unwrap it.
func New(ctx context.Context, keyID string, encContext map[string]string) (keyorixcrypto.KMSClient, error) {
	if keyID == "" {
		return nil, fmt.Errorf("aws-kms: kms_key_id is required")
	}
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("aws-kms: load AWS config: %w", err)
	}
	return &client{kms: kms.NewFromConfig(cfg), keyID: keyID, encCtx: encContext}, nil
}

func (c *client) Encrypt(ctx context.Context, plaintext []byte) ([]byte, error) {
	in := &kms.EncryptInput{KeyId: &c.keyID, Plaintext: plaintext}
	if len(c.encCtx) > 0 {
		in.EncryptionContext = c.encCtx
	}
	out, err := c.kms.Encrypt(ctx, in)
	if err != nil {
		return nil, err
	}
	return out.CiphertextBlob, nil
}

func (c *client) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	// Pin KeyId so the blob is only decryptable by the expected CMK.
	in := &kms.DecryptInput{CiphertextBlob: ciphertext, KeyId: &c.keyID}
	if len(c.encCtx) > 0 {
		in.EncryptionContext = c.encCtx
	}
	out, err := c.kms.Decrypt(ctx, in)
	if err != nil && len(c.encCtx) > 0 {
		// Legacy blob wrapped before the encryption context was configured: retry once
		// without it, so enabling the binding on a running install doesn't lock out the
		// already-wrapped KEK (it rebinds on the next KEK re-wrap). A blob bound to a
		// DIFFERENT install's context still fails both attempts — the security property
		// holds.
		out, err = c.kms.Decrypt(ctx, &kms.DecryptInput{CiphertextBlob: ciphertext, KeyId: &c.keyID})
	}
	if err != nil {
		return nil, err
	}
	return out.Plaintext, nil
}
