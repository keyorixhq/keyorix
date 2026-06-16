// vault.go — the HashiCorp Vault read-through connector. GetSecret reads a path via
// Vault's HTTP API (GET {address}/v1/{ref}) with a token, and returns the secret's
// data as JSON. KV v2 is detected and unwrapped (the value lives under data.data).
//
// Implemented directly over net/http (no Vault SDK dependency): a KV read is a
// single authenticated GET. The token comes from an environment variable (trusted,
// like the other backends' ambient credentials), never from the request.
package connect

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// vaultMaxResponseBytes caps the read body (a KV secret is small); guards a hostile/
// misbehaving endpoint.
const vaultMaxResponseBytes = 1 << 20 // 1 MiB

// VaultConnector reads secrets from HashiCorp Vault over its HTTP API.
type VaultConnector struct {
	name        string
	address     string // e.g. https://vault.example.com:8200
	token       string
	allowedRefs []string
	client      *http.Client
}

// NewVaultConnector builds a Vault connector. address is the Vault base URL; token
// is the Vault token (sourced from the environment by the caller). allowedRefs, when
// non-empty, restricts readable paths to those with one of the given prefixes.
func NewVaultConnector(name, address, token string, allowedRefs []string) *VaultConnector {
	return &VaultConnector{
		name:        name,
		address:     strings.TrimRight(address, "/"),
		token:       token,
		allowedRefs: allowedRefs,
		client:      &http.Client{Timeout: 15 * time.Second},
	}
}

func (c *VaultConnector) Name() string { return c.name }
func (c *VaultConnector) Type() string { return "vault" }

func (c *VaultConnector) GetSecret(ctx context.Context, ref string) (string, error) {
	if ref == "" {
		return "", fmt.Errorf("vault: secret reference (path) is required, e.g. secret/data/myapp")
	}
	if !prefixAllowed(c.allowedRefs, ref) {
		return "", fmt.Errorf("vault: ref %q is not permitted by this connector's allowed_refs", ref)
	}
	if c.address == "" {
		return "", fmt.Errorf("vault: connector address is not configured")
	}
	if c.token == "" {
		return "", fmt.Errorf("vault: no token configured (set the connector's token_env)")
	}

	url := c.address + "/v1/" + strings.TrimLeft(ref, "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("vault: new request: %w", err)
	}
	req.Header.Set("X-Vault-Token", c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("vault: get %q: %w", ref, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("vault: %s returned HTTP %d for %q", c.address, resp.StatusCode, ref)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, vaultMaxResponseBytes))
	if err != nil {
		return "", fmt.Errorf("vault: read response: %w", err)
	}

	// Vault wraps the secret under "data". KV v2 nests it again under data.data
	// (alongside data.metadata); KV v1 puts the secret map directly under data.
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil || len(env.Data) == 0 {
		return "", fmt.Errorf("vault: secret %q has no data", ref)
	}
	var kv2 struct {
		Data     json.RawMessage `json:"data"`
		Metadata json.RawMessage `json:"metadata"`
	}
	if err := json.Unmarshal(env.Data, &kv2); err == nil && len(kv2.Data) > 0 && len(kv2.Metadata) > 0 {
		return string(kv2.Data), nil // KV v2: return the inner data map
	}
	return string(env.Data), nil // KV v1: the data map itself
}
