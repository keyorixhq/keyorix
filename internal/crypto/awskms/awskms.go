// Package awskms implements crypto.KMSClient against AWS KMS (ADR-041). It is the
// only place the AWS KMS SDK is imported, keeping internal/crypto cloud-SDK-free.
// Region and credentials come from the standard AWS chain (env, instance profile,
// IRSA, …) — never from Keyorix config.
package awskms

import (
	"context"
	"fmt"
	"log"

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
	kms           awsKMSAPI
	keyID         string
	encCtx        map[string]string // AWS EncryptionContext bound to the wrapped KEK (may be empty)
	allowFallback bool              // #123: opt-in, see KMSAllowContextFallback's doc comment
}

// New builds an AWS-KMS-backed crypto.KMSClient for the given key (ID, ARN, or
// alias). It loads the default AWS config; the caller's environment supplies the
// region and credentials. encContext, when non-empty, is bound to the wrapped KEK so
// a different install sharing the same CMK cannot unwrap it — UNLESS allowFallback is
// also set, in which case a context-bound Decrypt failure retries once without any
// context (see config.KeyProviderConfig.KMSAllowContextFallback for the full
// rationale; default false = the binding is strictly enforced).
func New(ctx context.Context, keyID string, encContext map[string]string, allowFallback bool) (keyorixcrypto.KMSClient, error) {
	if keyID == "" {
		return nil, fmt.Errorf("aws-kms: kms_key_id is required")
	}
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("aws-kms: load AWS config: %w", err)
	}
	return &client{kms: kms.NewFromConfig(cfg), keyID: keyID, encCtx: encContext, allowFallback: allowFallback}, nil
}

func (c *client) Encrypt(ctx context.Context, plaintext []byte) ([]byte, error) {
	in := &kms.EncryptInput{KeyId: &c.keyID, Plaintext: plaintext}
	if len(c.encCtx) > 0 {
		in.EncryptionContext = c.encCtx
	}
	out, err := c.kms.Encrypt(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("aws-kms: encrypt: %w", err)
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
	// #123: the no-context retry is now OPT-IN (allowFallback) rather than automatic on
	// any failure. With it off — the default — a context-bound Decrypt failure is
	// final: this is the actual enforcement of the "different install can't unwrap my
	// KEK" property. An unconditional fallback made that advisory, since a blob an
	// attacker (with kms:Encrypt on the shared CMK but not Keyorix's own data) planted
	// with NO context always succeeds on the fallback attempt regardless of what this
	// install's context is. When allowFallback IS set (a deliberate, transient
	// migration aid — see KMSAllowContextFallback), a successful fallback is logged
	// loudly: it means this decrypt just used the weaker, unbound path, which should
	// be closed by re-wrapping (`keyorix encryption migrate-provider
	// --to-kms-encryption-context=...`) and turning the flag back off.
	if err != nil && len(c.encCtx) > 0 && c.allowFallback {
		out, err = c.kms.Decrypt(ctx, &kms.DecryptInput{CiphertextBlob: ciphertext, KeyId: &c.keyID})
		if err == nil {
			log.Printf("aws-kms: decrypted a wrapped KEK WITHOUT its configured encryption context (kms_allow_context_fallback is on) — this blob is not bound to this install; re-wrap it under the context via 'keyorix encryption migrate-provider --to-kms-encryption-context=...' and disable kms_allow_context_fallback")
		}
	}
	if err != nil {
		return nil, fmt.Errorf("aws-kms: decrypt: %w", err)
	}
	return out.Plaintext, nil
}
