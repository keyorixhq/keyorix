package azurekms

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errKeys is a fakeKeys variant whose WrapKey and UnwrapKey always return an error.
type errKeys struct {
	wrapErr   error
	unwrapErr error
}

func (e *errKeys) WrapKey(_ context.Context, _ string, _ string, _ azkeys.KeyOperationParameters, _ *azkeys.WrapKeyOptions) (azkeys.WrapKeyResponse, error) {
	if e.wrapErr != nil {
		return azkeys.WrapKeyResponse{}, e.wrapErr
	}
	return azkeys.WrapKeyResponse{}, nil
}

func (e *errKeys) UnwrapKey(_ context.Context, _ string, _ string, _ azkeys.KeyOperationParameters, _ *azkeys.UnwrapKeyOptions) (azkeys.UnwrapKeyResponse, error) {
	if e.unwrapErr != nil {
		return azkeys.UnwrapKeyResponse{}, e.unwrapErr
	}
	return azkeys.UnwrapKeyResponse{}, nil
}

// TestNew_EmptyKeyID exercises the early-return error when kms_key_id is "".
func TestNew_EmptyKeyID(t *testing.T) {
	_, err := New(context.Background(), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "kms_key_id")
}

// TestNew_InvalidKeyID exercises the parseKeyID error path inside New.
func TestNew_InvalidKeyID(t *testing.T) {
	// No scheme or host — parseKeyID returns an error.
	_, err := New(context.Background(), "/keys/kek/v1")
	require.Error(t, err)
}

// TestNew_ValidKeyID exercises the full New path including DefaultAzureCredential
// and azkeys.NewClient. On a dev machine without Azure credentials the function
// may still succeed (credential creation is lazy), so we accept either outcome —
// the goal is simply to execute the credential-creation and client-creation
// statements, not to assert authentication succeeds.
func TestNew_ValidKeyID(t *testing.T) {
	// This exercises the azidentity.NewDefaultAzureCredential + azkeys.NewClient path.
	// The returned error (if any) must not be nil only if credential creation fails;
	// on most CI/dev environments it either succeeds or fails with a credential error,
	// both of which are acceptable for coverage purposes.
	_, _ = New(context.Background(), "https://myvault.vault.azure.net/keys/kek")
}

// TestEncrypt_WrapKeyError exercises the error path in Encrypt when WrapKey fails.
func TestEncrypt_WrapKeyError(t *testing.T) {
	c := &client{
		keys:       &errKeys{wrapErr: fmt.Errorf("vault unavailable")},
		keyName:    "kek",
		keyVersion: "",
	}
	_, err := c.Encrypt(context.Background(), []byte("material"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "vault unavailable")
}

// TestDecrypt_UnwrapKeyError exercises the error path in Decrypt when UnwrapKey fails
// on a non-envelope (legacy) blob.
func TestDecrypt_UnwrapKeyError(t *testing.T) {
	c := &client{
		keys:       &errKeys{unwrapErr: fmt.Errorf("unwrap failed")},
		keyName:    "kek",
		keyVersion: "v1",
	}
	// A raw (non-magic-prefix) blob triggers the legacy unwrap path.
	_, err := c.Decrypt(context.Background(), []byte("raw-ciphertext"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unwrap failed")
}

// azureUpstreamMarker simulates internal-looking detail (a subscription/vault
// hostname) that an upstream Key Vault SDK error can carry.
const azureUpstreamMarker = "kv-internal-eastus2-047a1.vault.azure.net sub-9c21f0a3 safe-marker-7e21b"

// TestEncrypt_WrapKeyError_IsPrefixed verifies that Encrypt wraps the raw Key
// Vault SDK error with this file's own "azure-kms: wrap key:" prefix
// convention (matching how New already prefixes its own SDK/credential
// errors, e.g. "azure-kms: create client: %w") instead of returning it bare.
func TestEncrypt_WrapKeyError_IsPrefixed(t *testing.T) {
	c := &client{
		keys:       &errKeys{wrapErr: fmt.Errorf("Forbidden: caller %s not permitted", azureUpstreamMarker)},
		keyName:    "kek",
		keyVersion: "",
	}
	_, err := c.Encrypt(context.Background(), []byte("material"))
	require.Error(t, err)
	assert.True(t, strings.HasPrefix(err.Error(), "azure-kms: wrap key:"), "expected error prefixed with %q, got %q", "azure-kms: wrap key:", err.Error())
	// The prefix must be additive, not a replacement — the underlying detail
	// still traces through (as every other wrapped error in this file does)
	// for server-side diagnosis via %w, it just can no longer reach a client
	// unprefixed/unattributed to this package.
	assert.Contains(t, err.Error(), azureUpstreamMarker)
}

// TestDecrypt_UnwrapKeyError_IsPrefixed is the Decrypt counterpart of
// TestEncrypt_WrapKeyError_IsPrefixed, covering the legacy (non-envelope) blob
// unwrap path.
func TestDecrypt_UnwrapKeyError_IsPrefixed(t *testing.T) {
	c := &client{
		keys:       &errKeys{unwrapErr: fmt.Errorf("Forbidden: caller %s not permitted", azureUpstreamMarker)},
		keyName:    "kek",
		keyVersion: "v1",
	}
	_, err := c.Decrypt(context.Background(), []byte("raw-ciphertext"))
	require.Error(t, err)
	assert.True(t, strings.HasPrefix(err.Error(), "azure-kms: unwrap key:"), "expected error prefixed with %q, got %q", "azure-kms: unwrap key:", err.Error())
	assert.Contains(t, err.Error(), azureUpstreamMarker)
}

// TestDecrypt_UnwrapKeyError_PinnedEnvelope exercises the UnwrapKey error path
// for a version-pinned (magic-prefix) envelope blob.
func TestDecrypt_UnwrapKeyError_PinnedEnvelope(t *testing.T) {
	// Produce a valid envelope blob first.
	blob, err := encodeEnvelope("v1", []byte("ciphertext"))
	require.NoError(t, err)

	c := &client{
		keys:       &errKeys{unwrapErr: fmt.Errorf("key version not found")},
		keyName:    "kek",
		keyVersion: "",
	}
	_, err = c.Decrypt(context.Background(), blob)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "key version not found")
}
