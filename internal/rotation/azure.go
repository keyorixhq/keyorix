// azure.go — the Azure AD application rotation executor (ADR-047), a GENERATE-upstream
// backend: it rotates an app registration's client secret by minting a fresh secret via
// Microsoft Graph (addPassword) and removing the app's prior secrets, then returns the
// new client secret for Keyorix to store. Credentials come from the ambient Azure
// identity chain (DefaultAzureCredential), never from Keyorix config. The Graph calls go
// over net/http (no Graph SDK dependency), authenticated with an azidentity token.
package rotation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

const (
	azureGraphBase   = "https://graph.microsoft.com/v1.0"
	azureGraphScope  = "https://graph.microsoft.com/.default"
	azureHTTPTimeout = 30 * time.Second
)

// azureGraphAPI is the high-level slice of Microsoft Graph the executor uses — an
// interface seam so the HTTP/SDK details stay contained and tests inject a fake. appID
// is the application's object id.
type azureGraphAPI interface {
	ListPasswordKeyIDs(ctx context.Context, appID string) ([]string, error)
	AddPassword(ctx context.Context, appID string) (secretText string, err error)
	RemovePassword(ctx context.Context, appID, keyID string) error
}

// AzureAppSecretExecutor rotates an Azure AD application's client secret. The stored
// value is the new secret text.
type AzureAppSecretExecutor struct {
	name        string
	allowedRefs []string
	newClient   func(ctx context.Context) (azureGraphAPI, error)
}

// NewAzureAppSecretExecutor builds an Azure app-secret rotation executor. allowedRefs
// restricts which application object ids it may rotate (prefix allowlist) — required
// (fail-closed).
func NewAzureAppSecretExecutor(name string, allowedRefs []string) *AzureAppSecretExecutor {
	return &AzureAppSecretExecutor{name: name, allowedRefs: allowedRefs}
}

func (e *AzureAppSecretExecutor) Name() string { return e.name }
func (e *AzureAppSecretExecutor) Type() string { return "azure-app" }

// Rotate is not the path for a generate-upstream backend: the secret is minted by Azure.
func (e *AzureAppSecretExecutor) Rotate(_ context.Context, _, _ string) error {
	return fmt.Errorf("azure-app: backend mints the new secret upstream; use GenerateUpstream")
}

func (e *AzureAppSecretExecutor) client(ctx context.Context) (azureGraphAPI, error) {
	if e.newClient != nil {
		return e.newClient(ctx)
	}
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("azure-app: default credential: %w", err)
	}
	return &azureGraphClient{cred: cred, http: &http.Client{Timeout: azureHTTPTimeout}}, nil
}

// GenerateUpstream rotates application `ref` (its object id): mint a fresh client secret
// and delete the app's prior secrets, returning the new secret text.
func (e *AzureAppSecretExecutor) GenerateUpstream(ctx context.Context, ref string) (string, error) {
	if ref == "" {
		return "", fmt.Errorf("azure-app: application object id (ref) is required")
	}
	if len(e.allowedRefs) == 0 {
		return "", fmt.Errorf("azure-app: backend %q has no allowed_refs configured — refusing to rotate (fail-closed)", e.name)
	}
	if !prefixAllowed(e.allowedRefs, ref) {
		return "", fmt.Errorf("azure-app: application %q is not permitted by this backend's allowed_refs", ref)
	}
	cl, err := e.client(ctx)
	if err != nil {
		return "", err
	}

	prior, err := cl.ListPasswordKeyIDs(ctx, ref)
	if err != nil {
		return "", fmt.Errorf("azure-app: list secrets for %q: %w", ref, err)
	}
	secret, err := cl.AddPassword(ctx, ref)
	if err != nil {
		return "", fmt.Errorf("azure-app: add secret for %q: %w", ref, err)
	}
	if secret == "" {
		return "", fmt.Errorf("azure-app: add secret for %q returned no secret text", ref)
	}
	// Remove the prior secrets so only the freshly-minted one remains. Best-effort: a
	// delete failure is not fatal (the new secret is live and will be stored).
	for _, kid := range prior {
		_ = cl.RemovePassword(ctx, ref, kid)
	}
	return secret, nil
}

// azureGraphClient calls Microsoft Graph over net/http with an azidentity bearer token.
type azureGraphClient struct {
	cred azcore.TokenCredential
	http *http.Client
}

func (c *azureGraphClient) token(ctx context.Context) (string, error) {
	tok, err := c.cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{azureGraphScope}})
	if err != nil {
		return "", fmt.Errorf("acquire graph token: %w", err)
	}
	return tok.Token, nil
}

// do issues an authenticated Graph request and decodes a JSON response into out (out may
// be nil for no-content responses).
func (c *azureGraphClient) do(ctx context.Context, method, url string, body, out any) error {
	tok, err := c.token(ctx)
	if err != nil {
		return err
	}
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("graph %s returned %d: %s", method, resp.StatusCode, bytes.TrimSpace(msg))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func (c *azureGraphClient) ListPasswordKeyIDs(ctx context.Context, appID string) ([]string, error) {
	var out struct {
		PasswordCredentials []struct {
			KeyID string `json:"keyId"`
		} `json:"passwordCredentials"`
	}
	url := fmt.Sprintf("%s/applications/%s?$select=passwordCredentials", azureGraphBase, appID)
	if err := c.do(ctx, http.MethodGet, url, nil, &out); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(out.PasswordCredentials))
	for _, p := range out.PasswordCredentials {
		if p.KeyID != "" {
			ids = append(ids, p.KeyID)
		}
	}
	return ids, nil
}

func (c *azureGraphClient) AddPassword(ctx context.Context, appID string) (string, error) {
	body := map[string]any{"passwordCredential": map[string]any{"displayName": "keyorix-rotated"}}
	var out struct {
		SecretText string `json:"secretText"`
	}
	url := fmt.Sprintf("%s/applications/%s/addPassword", azureGraphBase, appID)
	if err := c.do(ctx, http.MethodPost, url, body, &out); err != nil {
		return "", err
	}
	return out.SecretText, nil
}

func (c *azureGraphClient) RemovePassword(ctx context.Context, appID, keyID string) error {
	url := fmt.Sprintf("%s/applications/%s/removePassword", azureGraphBase, appID)
	return c.do(ctx, http.MethodPost, url, map[string]any{"keyId": keyID}, nil)
}
