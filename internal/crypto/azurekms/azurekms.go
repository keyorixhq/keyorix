// Package azurekms implements crypto.KMSClient against Azure Key Vault (ADR-041).
// Like the awskms and gcpkms packages, it is the only place the Azure Key Vault
// SDK is imported, so internal/crypto stays cloud-SDK-free. Credentials come from
// DefaultAzureCredential (env vars, managed identity, workload identity), never
// from Keyorix config.
//
// Envelope encryption uses the vault key's wrapKey/unwrapKey operations
// (RSA-OAEP-256): the 32-byte KEK is wrapped by the vault key and only the wrapped
// blob is stored on disk.
//
// Unlike AWS/GCP KMS, an Azure Key Vault key wrap/unwrap operation targets a
// specific key VERSION, and an unversioned kms_key_id resolves to whatever
// version is "current" at call time (docs/adr-041-kms-key-provider.md). Routine
// key rotation therefore changes what "current" means between the Encrypt call
// (at first run) and a later Decrypt call (at every subsequent restart) — the new
// version cannot unwrap ciphertext produced by the old one. To make this immune
// to rotation, Encrypt captures the exact key version Azure actually used (from
// the response KID, which is always fully versioned) and embeds it in the
// returned blob behind a magic prefix; Decrypt recognizes that prefix and targets
// the pinned version instead of "current". Ciphertext wrapped before this change
// (no prefix) still decrypts via the old "current"/configured-version resolution
// — see decodeEnvelope.
package azurekms

import (
	"bytes"
	"context"
	"encoding/json"
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

// envelopeMagic prefixes a version-pinned wrapped blob (see package doc). Raw
// Key Vault wrap output is uniformly-random ciphertext bytes, so the chance a
// legacy (pre-fix) blob collides with this ASCII prefix is negligible — well
// below the chance of guessing the wrapping key itself.
const envelopeMagic = "keyorix-azkms-v1:"

// envelope carries the exact key version a KEK was wrapped under, alongside the
// wrap result, so Decrypt can always target that version rather than "current".
type envelope struct {
	Version    string `json:"version"`
	Ciphertext []byte `json:"ciphertext"`
}

// encodeEnvelope prepends the magic prefix to a JSON-encoded envelope.
func encodeEnvelope(version string, ciphertext []byte) ([]byte, error) {
	body, err := json.Marshal(envelope{Version: version, Ciphertext: ciphertext})
	if err != nil {
		return nil, fmt.Errorf("azure-kms: encode envelope: %w", err)
	}
	return append([]byte(envelopeMagic), body...), nil
}

// decodeEnvelope reports whether blob is a version-pinned envelope produced by
// encodeEnvelope. Blobs without the magic prefix are legacy (or explicitly
// versioned pre-fix) wrap output and must be decrypted with the client's
// configured/"current" version instead.
func decodeEnvelope(blob []byte) (env envelope, ok bool, err error) {
	if !bytes.HasPrefix(blob, []byte(envelopeMagic)) {
		return envelope{}, false, nil
	}
	if err := json.Unmarshal(blob[len(envelopeMagic):], &env); err != nil {
		return envelope{}, false, fmt.Errorf("azure-kms: corrupt version-pinned envelope: %w", err)
	}
	return env, true, nil
}

// azureKeysAPI is the slice of the Key Vault keys client this package uses — an
// interface seam so the SDK stays contained here and version-pinning behavior is
// unit-testable with a fake that models rotation (a wrap tied to version V fails
// to unwrap once "current" moves to a different version).
type azureKeysAPI interface {
	WrapKey(ctx context.Context, name string, version string, parameters azkeys.KeyOperationParameters, options *azkeys.WrapKeyOptions) (azkeys.WrapKeyResponse, error)
	UnwrapKey(ctx context.Context, name string, version string, parameters azkeys.KeyOperationParameters, options *azkeys.UnwrapKeyOptions) (azkeys.UnwrapKeyResponse, error)
}

type client struct {
	keys       azureKeysAPI
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
		return nil, fmt.Errorf("azure-kms: wrap key: %w", err)
	}
	// res.KID is the fully-versioned key identifier Azure actually used, even
	// when the request (c.keyVersion) was unversioned/"current". Pin it into the
	// returned blob so a later Decrypt targets this exact version and is immune
	// to the key being rotated to a new "current" version in the meantime.
	var version string
	if res.KID != nil {
		version = res.KID.Version()
	}
	if version == "" {
		// Unexpected (Key Vault always returns a versioned KID), but fail safe by
		// falling back to the legacy, unpinned blob rather than erroring out.
		return res.Result, nil
	}
	return encodeEnvelope(version, res.Result)
}

func (c *client) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	version := c.keyVersion
	wrapped := ciphertext
	env, pinned, err := decodeEnvelope(ciphertext)
	if err != nil {
		return nil, err
	}
	if pinned {
		version = env.Version
		wrapped = env.Ciphertext
	}
	res, err := c.keys.UnwrapKey(ctx, c.keyName, version, azkeys.KeyOperationParameters{
		Algorithm: to.Ptr(wrapAlgorithm),
		Value:     wrapped,
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("azure-kms: unwrap key: %w", err)
	}
	return res.Result, nil
}
