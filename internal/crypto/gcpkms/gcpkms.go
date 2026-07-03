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
	"log"
	"sort"
	"strings"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	gax "github.com/googleapis/gax-go/v2"
	keyorixcrypto "github.com/keyorixhq/keyorix/internal/crypto"
)

// gcpKMSAPI is the slice of the KMS client the provider uses — an interface seam so
// the SDK stays contained here and the AAD fallback is unit-testable.
type gcpKMSAPI interface {
	Encrypt(ctx context.Context, req *kmspb.EncryptRequest, opts ...gax.CallOption) (*kmspb.EncryptResponse, error)
	Decrypt(ctx context.Context, req *kmspb.DecryptRequest, opts ...gax.CallOption) (*kmspb.DecryptResponse, error)
}

type client struct {
	kms           gcpKMSAPI
	keyName       string // projects/P/locations/L/keyRings/R/cryptoKeys/K
	aad           []byte // AdditionalAuthenticatedData binding the wrapped KEK (nil = none)
	allowFallback bool   // #123: opt-in, see KMSAllowContextFallback's doc comment
}

// New builds a GCP-KMS-backed crypto.KMSClient for the given crypto-key resource
// name (projects/.../cryptoKeys/...). encContext, when non-empty, is bound to the
// wrapped KEK as AdditionalAuthenticatedData so a different install sharing the same
// key cannot unwrap it — UNLESS allowFallback is also set, in which case an
// AAD-bound Decrypt failure retries once without any AAD (see
// config.KeyProviderConfig.KMSAllowContextFallback for the full rationale; default
// false = the binding is strictly enforced).
func New(ctx context.Context, keyName string, encContext map[string]string, allowFallback bool) (keyorixcrypto.KMSClient, error) {
	if keyName == "" {
		return nil, fmt.Errorf("gcp-kms: kms_key_id (crypto key resource name) is required")
	}
	c, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("gcp-kms: create client: %w", err)
	}
	return &client{kms: c, keyName: keyName, aad: encContextAAD(encContext), allowFallback: allowFallback}, nil
}

// encContextAAD canonicalises an encryption-context map into deterministic bytes
// (sorted key=value lines) for use as GCP AdditionalAuthenticatedData. Returns nil for
// an empty map so the no-binding path is byte-identical to the prior behaviour.
func encContextAAD(m map[string]string) []byte {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(m[k])
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

func (c *client) Encrypt(ctx context.Context, plaintext []byte) ([]byte, error) {
	req := &kmspb.EncryptRequest{Name: c.keyName, Plaintext: plaintext}
	if len(c.aad) > 0 {
		req.AdditionalAuthenticatedData = c.aad
	}
	resp, err := c.kms.Encrypt(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp.GetCiphertext(), nil
}

func (c *client) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	req := &kmspb.DecryptRequest{Name: c.keyName, Ciphertext: ciphertext}
	if len(c.aad) > 0 {
		req.AdditionalAuthenticatedData = c.aad
	}
	resp, err := c.kms.Decrypt(ctx, req)
	// #123: the no-AAD retry is now OPT-IN (allowFallback) rather than automatic on any
	// failure — see awskms.Decrypt's comment for the full rationale (identical here: an
	// unconditional fallback makes the AAD binding advisory, since a blob an attacker
	// planted with no AAD at all always succeeds on the fallback attempt).
	if err != nil && len(c.aad) > 0 && c.allowFallback {
		resp, err = c.kms.Decrypt(ctx, &kmspb.DecryptRequest{Name: c.keyName, Ciphertext: ciphertext})
		if err == nil {
			log.Printf("gcp-kms: decrypted a wrapped KEK WITHOUT its configured AAD (kms_allow_context_fallback is on) — this blob is not bound to this install; re-wrap it under the context via 'keyorix encryption migrate-provider --to-kms-encryption-context=...' and disable kms_allow_context_fallback")
		}
	}
	if err != nil {
		return nil, err
	}
	return resp.GetPlaintext(), nil
}
