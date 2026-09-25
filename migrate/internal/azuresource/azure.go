// Package azuresource reads secrets from an Azure Key Vault. GetSecret-equivalent read logic
// (empty-value rejection, response hardening) is ported from internal/connect/azurekv.go —
// migrate cannot import internal/connect (module boundary, docs/design-keyorix-migrate.md) —
// but this package additionally LISTS every secret in the vault (paginated), which azurekv.go's
// single-ref GetSecret never needed to do.
package azuresource

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"

	"github.com/keyorixhq/keyorix/migrate/internal/cloudentry"
	"github.com/keyorixhq/keyorix/migrate/internal/httpsafe"
	"github.com/keyorixhq/keyorix/migrate/internal/splitjson"
)

// Config holds every Azure Key Vault setting a Client needs. Credentials always come from the
// ambient Azure identity chain (managed identity / workload identity / env / CLI) via
// DefaultAzureCredential — never a Keyorix config field or CLI flag, matching
// internal/connect/azurekv.go's precedent.
type Config struct {
	VaultURL   string // required; the vault base URL, e.g. https://myvault.vault.azure.net/.
	NamePrefix string // optional; only secret names with this prefix are imported.
	// SplitJSON imports each top-level key of a JSON-object secret value as its own Keyorix
	// secret (Name field <secret>-<key>) instead of the whole string as one secret.
	SplitJSON bool
}

// azAPI is the slice of the Key Vault secrets client this package uses — an interface seam so
// it is unit-tested with a fake, matching internal/connect/azurekv.go's azSecretGetter
// precedent (extended here with the list pager, which that single-ref connector never needed).
type azAPI interface {
	NewListSecretPropertiesPager(options *azsecrets.ListSecretPropertiesOptions) *runtime.Pager[azsecrets.ListSecretPropertiesResponse]
	GetSecret(ctx context.Context, name, version string, options *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error)
}

// Client lists and reads secrets from an Azure Key Vault.
type Client struct {
	cfg Config
	// newClient builds an azAPI; nil uses the real Key Vault client with DefaultAzureCredential.
	// Tests inject a fake.
	newClient func(ctx context.Context) (azAPI, error)
}

// New builds a Client. It performs no network call — credential/vault-URL problems surface
// clearly at the first real call instead.
func New(cfg Config) *Client {
	return &Client{cfg: cfg}
}

func (c *Client) client(ctx context.Context) (azAPI, error) {
	if c.newClient != nil {
		return c.newClient(ctx)
	}
	if c.cfg.VaultURL == "" {
		return nil, fmt.Errorf("azure-key-vault: vault URL is required")
	}
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("azure-key-vault: default credential: %w", err)
	}
	cl, err := azsecrets.NewClient(c.cfg.VaultURL, cred, &azsecrets.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			Transport: httpsafe.Client(),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("azure-key-vault: new client: %w", err)
	}
	return cl, nil
}

// List lists every secret in the vault (optionally restricted to names with cfg.NamePrefix),
// reads each enabled one's current value, and returns it as a cloudentry.Entry — or, when a
// secret can't or shouldn't be imported (disabled, no value, or a read error), as a
// cloudentry.Skipped with a reason. Matches awssource.Client.List's "report, don't drop"
// convention.
func (c *Client) List(ctx context.Context) ([]cloudentry.Entry, []cloudentry.Skipped, error) {
	cl, err := c.client(ctx)
	if err != nil {
		return nil, nil, err
	}

	var entries []cloudentry.Entry
	var skipped []cloudentry.Skipped
	pager := cl.NewListSecretPropertiesPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("azure-key-vault: list secrets: %w", err)
		}
		for _, p := range page.Value {
			if p == nil || p.ID == nil {
				continue
			}
			name := p.ID.Name()
			if name == "" {
				continue
			}
			if c.cfg.NamePrefix != "" && !strings.HasPrefix(name, c.cfg.NamePrefix) {
				continue
			}
			locator := c.locator(name)
			// The "disabled secret" case: a secret whose current version has been explicitly
			// disabled must be reported as skipped, not silently imported nor silently dropped
			// — GetSecret would still happily return an disabled secret's value (Key Vault's
			// enabled flag only gates the DATA-PLANE default-version resolution used by other
			// consumers, not this direct-by-name-and-version read), so this check has to
			// happen here, from the listed properties, not be inferred from a read failure.
			if p.Attributes != nil && p.Attributes.Enabled != nil && !*p.Attributes.Enabled {
				skipped = append(skipped, cloudentry.Skipped{Locator: locator, Reason: "secret is disabled"})
				continue
			}
			es, skip, err := c.readSecret(ctx, cl, name, locator)
			if err != nil {
				return nil, nil, err
			}
			if skip != nil {
				skipped = append(skipped, *skip)
				continue
			}
			entries = append(entries, es...)
		}
	}
	return entries, skipped, nil
}

func (c *Client) locator(name string) string {
	return fmt.Sprintf("azure-key-vault:%s/%s", strings.TrimSuffix(c.cfg.VaultURL, "/"), name)
}

// readSecret fetches one secret's current (latest) value and turns it into one or more
// cloudentry.Entry (more than one only when SplitJSON explodes a JSON object), or a Skipped
// with a reason.
func (c *Client) readSecret(ctx context.Context, cl azAPI, name, locator string) ([]cloudentry.Entry, *cloudentry.Skipped, error) {
	out, err := cl.GetSecret(ctx, name, "", nil)
	if err != nil {
		return nil, nil, fmt.Errorf("azure-key-vault: get %q: %w", name, err)
	}

	// Value != nil alone is not "has a value" -- the same class of bug
	// internal/connect/azurekv.go's GetSecret was fixed for: a response body like
	// {"value":""} decodes to a non-nil pointer to "", which must not be treated as a real
	// secret.
	if out.Value == nil || *out.Value == "" {
		return nil, &cloudentry.Skipped{Locator: locator, Reason: "secret has no value"}, nil
	}

	value := *out.Value
	version := ""
	if out.ID != nil {
		version = out.ID.Version()
	}
	createdAt := ""
	if out.Attributes != nil && out.Attributes.Created != nil {
		createdAt = out.Attributes.Created.UTC().Format(time.RFC3339)
	}

	if c.cfg.SplitJSON {
		if fields, ok := splitjson.Object(value); ok {
			entries := make([]cloudentry.Entry, 0, len(fields))
			for _, f := range fields {
				entries = append(entries, cloudentry.Entry{
					RawName:   name,
					Field:     f.Key,
					Value:     f.Value,
					Version:   version,
					CreatedAt: createdAt,
					Locator:   locator + "#" + f.Key,
				})
			}
			if len(entries) > 0 {
				return entries, nil, nil
			}
		}
	}
	return []cloudentry.Entry{{RawName: name, Value: value, Version: version, CreatedAt: createdAt, Locator: locator}}, nil, nil
}
