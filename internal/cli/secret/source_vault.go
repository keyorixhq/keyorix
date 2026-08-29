// source_vault.go — live import from a running HashiCorp Vault KV engine.
//
// Uses Vault's HTTP API directly (no SDK dependency): recursively LISTs the KV
// tree under --vault-path and reads each leaf, mapping every field to a Keyorix
// secret. Supports KV v2 (default) and v1, which differ only in URL layout.
package secret

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// vaultClientTimeout bounds every request this client makes to a configured Vault
// server. Matches common.RemoteClient's old flat 30s timeout value (#G71 sibling
// fix) — deliberately NOT the connect/idle split #1521 gave common.RemoteClient,
// since that fix's own scope was the Keyorix-server client specifically. The
// caller's ctx (fetchFromVault ← cmd.Context(), which carries no
// deadline anywhere in this CLI) previously left this client's requests with NO
// bound at all — a hung/misconfigured/malicious VAULT_ADDR could stall 'secret
// import --source vault' forever.
const vaultClientTimeout = 30 * time.Second

// maxVaultResponseBytes caps how much of a Vault HTTP response body this
// client will read into memory before decoding. Vault responses read here are
// either a single KV secret's fields or a LIST of child key names under a
// path — both normally small, but a generous cap is used to accommodate large
// KV trees/secrets without tuning per call site, while still bounding a
// malicious or misbehaving Vault response from exhausting client memory via
// an unbounded json.Decode of resp.Body.
const maxVaultResponseBytes = 10 << 20 // 10MB

// vaultClient talks to a Vault KV engine over HTTP.
type vaultClient struct {
	addr      string
	token     string
	mount     string
	kvVersion int
	hc        *http.Client
}

// newVaultClient resolves connection settings from flags then VAULT_ADDR/
// VAULT_TOKEN, and validates the KV version.
func newVaultClient() (*vaultClient, error) {
	addr := vaultAddr
	if addr == "" {
		addr = os.Getenv("VAULT_ADDR")
	}
	token := vaultToken
	if token == "" {
		token = os.Getenv("VAULT_TOKEN")
	}
	if addr == "" {
		return nil, fmt.Errorf("vault address not set (use --vault-addr or $VAULT_ADDR)")
	}
	if token == "" {
		return nil, fmt.Errorf("vault token not set (use --vault-token or $VAULT_TOKEN)")
	}
	if vaultKVVersion != 1 && vaultKVVersion != 2 {
		return nil, fmt.Errorf("unsupported --vault-kv-version %d (want 1 or 2)", vaultKVVersion)
	}
	return &vaultClient{
		addr:      strings.TrimRight(addr, "/"),
		token:     token,
		mount:     strings.Trim(vaultMount, "/"),
		kvVersion: vaultKVVersion,
		// No redirect is legitimate for a fixed, operator-supplied Vault address — the
		// default client would otherwise follow a 30x carrying the live X-Vault-Token
		// header wherever a compromised/misconfigured Vault (or a MITM) points it (#114,
		// twin of #98's server-side connector).
		hc: &http.Client{Timeout: vaultClientTimeout, CheckRedirect: refuseVaultRedirect},
	}, nil
}

// refuseVaultRedirect makes the client return the first (redirect) response as-is
// instead of following it — see newVaultClient.
func refuseVaultRedirect(_ *http.Request, _ []*http.Request) error {
	return http.ErrUseLastResponse
}

// fetchFromVault walks the KV tree under --vault-path and returns every field as
// a secretEntry. A leaf with a single "value" field becomes one secret named
// after its path (mirroring the Keyorix export shape parseVault handles);
// multi-field leaves explode into "<path>-<field>".
func fetchFromVault(ctx context.Context) ([]secretEntry, error) {
	c, err := newVaultClient()
	if err != nil {
		return nil, err
	}

	var entries []secretEntry
	root := strings.Trim(vaultPath, "/")
	if err := c.walk(ctx, root, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

// walk recursively lists prefix; sub-paths (keys ending in "/") recurse, leaves
// are read and appended to out.
func (c *vaultClient) walk(ctx context.Context, prefix string, out *[]secretEntry) error {
	keys, err := c.list(ctx, prefix)
	if err != nil {
		return err
	}
	// A path with no LIST result is itself a leaf (or empty); try reading it.
	if len(keys) == 0 {
		return c.readLeaf(ctx, prefix, out)
	}
	for _, k := range keys {
		var child string
		if prefix != "" {
			child = prefix + "/" + strings.TrimSuffix(k, "/")
		} else {
			child = strings.TrimSuffix(k, "/")
		}
		if strings.HasSuffix(k, "/") {
			if err := c.walk(ctx, child, out); err != nil {
				return err
			}
			continue
		}
		if err := c.readLeaf(ctx, child, out); err != nil {
			return err
		}
	}
	return nil
}

// readLeaf reads a single KV path and appends its field(s) to out.
func (c *vaultClient) readLeaf(ctx context.Context, path string, out *[]secretEntry) error {
	fields, err := c.read(ctx, path)
	if err != nil {
		return err
	}
	if len(fields) == 0 {
		return nil
	}
	name := path
	if name == "" {
		name = c.mount
	}
	// Single "value" field → one secret named after the path.
	if len(fields) == 1 {
		if v, ok := fields["value"]; ok {
			if val := fmt.Sprintf("%v", v); val != "" {
				*out = append(*out, secretEntry{Name: sanitizeSecretName(name), Value: val})
			}
			return nil
		}
	}
	for k, v := range fields {
		val := fmt.Sprintf("%v", v)
		if k == "" || val == "" {
			continue
		}
		*out = append(*out, secretEntry{Name: sanitizeSecretName(name + "-" + k), Value: val})
	}
	return nil
}

// list returns the child keys at path (sub-paths end in "/"). A 404 means the
// path is not a listable folder and yields no keys.
func (c *vaultClient) list(ctx context.Context, path string) ([]string, error) {
	url := c.metadataURL(path) + "?list=true"
	var body struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	status, err := c.do(ctx, url, &body)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, nil
	}
	return body.Data.Keys, nil
}

// read returns the field map stored at a KV leaf path. A 404 yields nil.
func (c *vaultClient) read(ctx context.Context, path string) (map[string]interface{}, error) {
	var raw json.RawMessage
	status, err := c.do(ctx, c.dataURL(path), &raw)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, nil
	}
	// KV v2 nests the secret under data.data; v1 stores it directly under data.
	if c.kvVersion == 2 {
		var body struct {
			Data struct {
				Data map[string]interface{} `json:"data"`
			} `json:"data"`
		}
		if err := json.Unmarshal(raw, &body); err != nil {
			return nil, fmt.Errorf("decode vault read %q: %w", path, err)
		}
		return body.Data.Data, nil
	}
	var body struct {
		Data map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, fmt.Errorf("decode vault read %q: %w", path, err)
	}
	return body.Data, nil
}

// do issues an authenticated GET and decodes a non-404 success body into out.
// It returns the HTTP status so callers can treat 404 as "absent".
func (c *vaultClient) do(ctx context.Context, url string, out interface{}) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", c.token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.hc.Do(req)
	if err != nil {
		return 0, fmt.Errorf("vault request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode == http.StatusNotFound {
		return resp.StatusCode, nil
	}
	if resp.StatusCode == http.StatusForbidden {
		return resp.StatusCode, fmt.Errorf("vault denied access (HTTP 403) for %s — check token permissions", url)
	}
	if resp.StatusCode >= 400 {
		return resp.StatusCode, fmt.Errorf("vault returned HTTP %d for %s", resp.StatusCode, url)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxVaultResponseBytes)).Decode(out); err != nil {
		return resp.StatusCode, fmt.Errorf("decode vault response: %w", err)
	}
	return resp.StatusCode, nil
}

// metadataURL builds the LIST URL for a path (KV v2 uses /metadata/, v1 is flat).
func (c *vaultClient) metadataURL(path string) string {
	if c.kvVersion == 2 {
		return c.join("metadata", path)
	}
	return c.join("", path)
}

// dataURL builds the READ URL for a path (KV v2 uses /data/, v1 is flat).
func (c *vaultClient) dataURL(path string) string {
	if c.kvVersion == 2 {
		return c.join("data", path)
	}
	return c.join("", path)
}

// join assembles {addr}/v1/{mount}[/{segment}]/{path}, omitting empty parts.
// The mount and path components are path-escaped per segment so that secret/key
// names containing URL-significant characters (spaces, '#', '%', '?', …) — which
// Vault permits — produce a valid URL and reach the right path instead of being
// silently mangled into a query/fragment or a malformed request. {addr} is left
// untouched (it carries the scheme + host from trusted config).
func (c *vaultClient) join(segment, path string) string {
	parts := []string{c.addr, "v1", escapePath(c.mount)}
	if segment != "" {
		parts = append(parts, segment)
	}
	if p := escapePath(path); p != "" {
		parts = append(parts, p)
	}
	return strings.Join(parts, "/")
}

// escapePath path-escapes each '/'-separated component of p, preserving the
// separators. An empty (or all-slash) input yields "".
func escapePath(p string) string {
	segs := strings.Split(strings.Trim(p, "/"), "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return strings.Join(segs, "/")
}
