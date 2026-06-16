// azurekv.go — the Azure Key Vault read-through connector. GetSecret resolves a
// reference (the secret name, optionally "name/version") within the connector's vault
// to its current value via the Key Vault data-plane GetSecret. The vault URL is the
// connector's configured address; credentials come from the ambient Azure identity
// chain (managed identity / workload identity / env / CLI) via DefaultAzureCredential
// — never from Keyorix config — mirroring the Azure KMS integration.
package connect

import (
	"context"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
)

// azKVGetAPI is the slice of the Key Vault secrets client the connector uses — an
// interface seam so it is unit-tested with a fake and the SDK stays contained here.
type azKVGetAPI interface {
	GetSecret(ctx context.Context, name, version string, options *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error)
}

// AzureKeyVaultConnector reads secrets from an Azure Key Vault.
type AzureKeyVaultConnector struct {
	name        string
	vaultURL    string
	allowedRefs []string
	// newClient builds a Key Vault client for vaultURL; nil uses the real client with
	// DefaultAzureCredential. Tests inject a fake.
	newClient func(ctx context.Context) (azKVGetAPI, error)
}

// NewAzureKeyVaultConnector builds an Azure Key Vault connector. vaultURL is the vault
// base URL (e.g. https://myvault.vault.azure.net/). allowedRefs, when non-empty,
// restricts readable references to those with one of the given prefixes (a guardrail
// on top of the ambient identity's RBAC/access-policy scope).
func NewAzureKeyVaultConnector(name, vaultURL string, allowedRefs []string) *AzureKeyVaultConnector {
	return &AzureKeyVaultConnector{name: name, vaultURL: vaultURL, allowedRefs: allowedRefs}
}

func (c *AzureKeyVaultConnector) Name() string { return c.name }
func (c *AzureKeyVaultConnector) Type() string { return "azure-key-vault" }

func (c *AzureKeyVaultConnector) client(ctx context.Context) (azKVGetAPI, error) {
	if c.newClient != nil {
		return c.newClient(ctx)
	}
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("azure-key-vault: default credential: %w", err)
	}
	cl, err := azsecrets.NewClient(c.vaultURL, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("azure-key-vault: new client: %w", err)
	}
	return cl, nil
}

func (c *AzureKeyVaultConnector) GetSecret(ctx context.Context, ref string) (string, error) {
	if ref == "" {
		return "", fmt.Errorf("azure-key-vault: secret reference is required (the secret name, optionally name/version)")
	}
	if c.vaultURL == "" {
		return "", fmt.Errorf("azure-key-vault: connector %q has no vault address configured", c.name)
	}
	if !prefixAllowed(c.allowedRefs, ref) {
		return "", fmt.Errorf("azure-key-vault: ref %q is not permitted by this connector's allowed_refs", ref)
	}
	// ref is "name" (latest) or "name/version"; version "" means the current version.
	name, version, _ := strings.Cut(ref, "/")
	if name == "" {
		return "", fmt.Errorf("azure-key-vault: ref %q has an empty secret name", ref)
	}

	cl, err := c.client(ctx)
	if err != nil {
		return "", err
	}
	out, err := cl.GetSecret(ctx, name, version, nil)
	if err != nil {
		return "", fmt.Errorf("azure-key-vault: get %q: %w", ref, err)
	}
	if out.Value == nil {
		return "", fmt.Errorf("azure-key-vault: secret %q has no value", ref)
	}
	return *out.Value, nil
}
