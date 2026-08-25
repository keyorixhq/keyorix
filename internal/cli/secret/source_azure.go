// source_azure.go — live import from Azure Key Vault.
//
// Authenticates with DefaultAzureCredential (env vars, managed identity, Azure
// CLI, …); lists every secret in the vault and reads its value. A JSON-object
// value explodes into one Keyorix secret per field; a plain string becomes a
// single secret.
//
// The Key Vault SDK surface is wrapped behind azureSecretsAPI so the collection
// logic is testable with a fake and the SDK types stay in one thin adapter.
package secret

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
)

// azureSecretsAPI abstracts the two Key Vault operations this importer needs.
type azureSecretsAPI interface {
	listNames(ctx context.Context) ([]string, error)
	getValue(ctx context.Context, name string) (string, error)
}

// fetchFromAzure builds a real Key Vault client from DefaultAzureCredential and
// collects every secret into entries.
func fetchFromAzure(ctx context.Context) ([]secretEntry, error) {
	if azureVaultURL == "" {
		return nil, fmt.Errorf("azure vault URL not set (use --azure-vault-url, e.g. https://<vault>.vault.azure.net)")
	}
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("azure credential: %w", err)
	}
	client, err := azsecrets.NewClient(azureVaultURL, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("azure key vault client: %w", err)
	}
	return collectAzure(ctx, &azureClientAdapter{c: client})
}

// collectAzure lists and reads secrets from any azureSecretsAPI. A secret with
// no accessible value (disabled, or a certificate-only secret with nothing in
// resp.Value) is skipped rather than fatal — but every skip is printed by name
// as it happens and tallied in sourceSkipCount, mirroring collectGCP's
// reporting, so a dropped secret is never silent.
func collectAzure(ctx context.Context, api azureSecretsAPI) ([]secretEntry, error) {
	names, err := api.listNames(ctx)
	if err != nil {
		return nil, fmt.Errorf("list azure secrets: %w", err)
	}
	var entries []secretEntry
	for _, name := range names {
		val, err := api.getValue(ctx, name)
		if err != nil {
			return nil, fmt.Errorf("read azure secret %q: %w", name, err)
		}
		if val == "" {
			fmt.Printf("  ~ Skipped  %-30s (no accessible value)\n", name)
			sourceSkipCount++
			continue
		}
		entries = append(entries, explodeValue(name, val)...)
	}
	return entries, nil
}

// azureClientAdapter wraps the azsecrets SDK client to satisfy azureSecretsAPI.
type azureClientAdapter struct {
	c *azsecrets.Client
}

func (a *azureClientAdapter) listNames(ctx context.Context) ([]string, error) {
	pager := a.c.NewListSecretPropertiesPager(nil)
	var names []string
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, p := range page.Value {
			if p == nil || p.ID == nil {
				continue
			}
			names = append(names, p.ID.Name())
		}
	}
	return names, nil
}

func (a *azureClientAdapter) getValue(ctx context.Context, name string) (string, error) {
	resp, err := a.c.GetSecret(ctx, name, "", nil)
	if err != nil {
		return "", err
	}
	if resp.Value == nil {
		return "", nil
	}
	return *resp.Value, nil
}
