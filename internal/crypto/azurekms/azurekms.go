// Package azurekms implements crypto.KMSClient against Azure Key Vault (ADR-041).
// Like the awskms and gcpkms packages, it is the only place the Azure Key Vault
// SDK is imported, so internal/crypto stays cloud-SDK-free. Credentials come from
// DefaultAzureCredential (env vars, managed identity, workload identity), never
// from Keyorix config.
//
// Envelope encryption uses the vault key's wrapKey/unwrapKey operations
// (RSA-OAEP-256): the 32-byte KEK is wrapped by the vault key and only the wrapped
// blob is stored on disk. Like GCP KMS, the operation names the key (vault URL +
// key name + version), so the key is inherently pinned — the ciphertext cannot
// select a different key.
package azurekms

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	keyorixcrypto "github.com/keyorixhq/keyorix/internal/crypto"
)

// wrapAlgorithm is the asymmetric wrap algorithm used to envelope the KEK. RSA
// keys are the common Key Vault case; the same algorithm is used for unwrap.
var wrapAlgorithm = azkeys.EncryptionAlgorithmRSAOAEP256

type client struct {
	keys       *azkeys.Client
	keyName    string
	keyVersion string // "" = latest version
}

// New builds an Azure-Key-Vault-backed crypto.KMSClient. keyID is the full key
// identifier URL (https://{vault}.vault.azure.net/keys/{name}[/{version}]); an
// omitted version uses the key's current version.
func New(_ context.Context, keyID string) (keyorixcrypto.KMSClient, error) {
	if keyID == "" {
		return nil, fmt.Errorf("azure-kms: kms_key_id (key identifier URL) is required")
	}
	vaultURL, name, version, err := parseKeyID(keyID)
	if err != nil {
		return nil, err
	}
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("azure-kms: default credential: %w", err)
	}
	c, err := azkeys.NewClient(vaultURL, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("azure-kms: create client: %w", err)
	}
	return &client{keys: c, keyName: name, keyVersion: version}, nil
}

// parseKeyID splits an Azure Key Vault key identifier URL into the vault URL, key
// name, and (optional) key version. Accepts both versioned and unversioned forms.
func parseKeyID(keyID string) (vaultURL, name, version string, err error) {
	u, err := url.Parse(keyID)
	if err != nil {
		return "", "", "", fmt.Errorf("azure-kms: invalid kms_key_id %q: %w", keyID, err)
	}
	if u.Scheme == "" || u.Host == "" {
		return "", "", "", fmt.Errorf("azure-kms: kms_key_id must be a key identifier URL (https://{vault}.vault.azure.net/keys/{name}[/{version}]), got %q", keyID)
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 2 || parts[0] != "keys" || parts[1] == "" {
		return "", "", "", fmt.Errorf("azure-kms: kms_key_id path must be /keys/{name}[/{version}], got %q", u.Path)
	}
	vaultURL = u.Scheme + "://" + u.Host
	name = parts[1]
	if len(parts) >= 3 {
		version = parts[2]
	}
	return vaultURL, name, version, nil
}

func (c *client) Encrypt(ctx context.Context, plaintext []byte) ([]byte, error) {
	res, err := c.keys.WrapKey(ctx, c.keyName, c.keyVersion, azkeys.KeyOperationParameters{
		Algorithm: to.Ptr(wrapAlgorithm),
		Value:     plaintext,
	}, nil)
	if err != nil {
		return nil, err
	}
	return res.Result, nil
}

func (c *client) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	res, err := c.keys.UnwrapKey(ctx, c.keyName, c.keyVersion, azkeys.KeyOperationParameters{
		Algorithm: to.Ptr(wrapAlgorithm),
		Value:     ciphertext,
	}, nil)
	if err != nil {
		return nil, err
	}
	return res.Result, nil
}
