// Package vaultsource reads a HashiCorp Vault (or OpenBao) KV tree over Vault's HTTP API —
// no Vault SDK dependency, matching cli/cmd/secret/source_vault.go and
// internal/connect/vault.go's precedent of a small hand-rolled client for a KV read/list.
// This tool needs more than either existing client: recursive-tree KV v1/v2 walk (ported from
// source_vault.go), mount-version resolution via Vault's own mounts API rather than
// response-shape sniffing (ported from internal/connect/vault.go, see resolveKVMountVersion's
// doc comment), plus AppRole auth and Vault Enterprise/OpenBao namespace support (new — neither
// existing client has either). See docs/design-keyorix-migrate.md's "Vault client" section for
// which parts are ported vs. new.
package vaultsource

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// clientTimeout bounds every request this client makes to a configured Vault server, matching
// source_vault.go's vaultClientTimeout precedent (#G71 sibling).
const clientTimeout = 30 * time.Second

// maxResponseBytes caps how much of a Vault HTTP response body this client reads into memory,
// matching source_vault.go's maxVaultResponseBytes precedent -- generous enough for large KV
// trees/secrets, still bounded against a malicious or misbehaving Vault response.
const maxResponseBytes = 10 << 20 // 10MB

// Config holds every connection/auth setting a Client needs. Exactly one of Token or
// (RoleID, SecretID) must be set; namespace and KV version are optional (KV version is
// auto-detected per mount when zero, via resolveKVMountVersion).
type Config struct {
	Addr      string
	Namespace string // Vault Enterprise / OpenBao; sent as X-Vault-Namespace on every request.
	Mount     string // KV mount path, e.g. "secret".

	Token string // direct token auth.

	RoleID   string // AppRole auth (used when Token == "").
	SecretID string
}

// Client talks to a Vault KV engine over HTTP.
type Client struct {
	addr      string
	namespace string
	mount     string
	token     string
	hc        *http.Client

	// mountVersionsMu guards mountVersions: a per-client cache of KV mount version (1 or 2),
	// keyed by the mount path Vault itself reports (e.g. "secret/") — ported from
	// internal/connect/vault.go's resolveKVMountVersion, see its doc comment there for why
	// querying the mount directly (not sniffing response shape) is required for correctness,
	// not just a performance nicety.
	mountVersionsMu sync.Mutex
	mountVersions   map[string]int
}

// New builds a Client, performing AppRole login immediately if configured (so a bad
// role-id/secret-id fails fast at startup, not on the first KV read).
func New(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.Addr == "" {
		return nil, fmt.Errorf("vault address is required (--vault-addr or $VAULT_ADDR)")
	}
	if cfg.Token == "" && (cfg.RoleID == "" || cfg.SecretID == "") {
		return nil, fmt.Errorf("vault auth is required: --vault-token/$VAULT_TOKEN, or both --vault-role-id and --vault-secret-id")
	}

	c := &Client{
		addr:      strings.TrimRight(cfg.Addr, "/"),
		namespace: cfg.Namespace,
		mount:     strings.Trim(cfg.Mount, "/"),
		hc: &http.Client{
			Timeout: clientTimeout,
			// No redirect is legitimate for a fixed, operator-supplied Vault address — see
			// source_vault.go's refuseVaultRedirect / internal/connect/vault.go's
			// refuseRedirect for the shared rationale (a compromised/misconfigured Vault
			// must never receive the live token via a followed 3xx to another host).
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}

	if cfg.Token != "" {
		c.token = cfg.Token
		return c, nil
	}
	token, err := c.appRoleLogin(ctx, cfg.RoleID, cfg.SecretID)
	if err != nil {
		return nil, fmt.Errorf("vault AppRole login: %w", err)
	}
	c.token = token
	return c, nil
}

// appRoleLogin exchanges an AppRole role-id/secret-id pair for a client token via
// POST {addr}/v1/auth/approle/login. New code — neither source_vault.go nor
// internal/connect/vault.go supports AppRole; both are token-only.
func (c *Client) appRoleLogin(ctx context.Context, roleID, secretID string) (string, error) {
	body, err := json.Marshal(struct {
		RoleID   string `json:"role_id"`
		SecretID string `json:"secret_id"`
	}{RoleID: roleID, SecretID: secretID})
	if err != nil {
		return "", fmt.Errorf("build AppRole login body: %w", err)
	}

	reqURL := c.addr + "/v1/auth/approle/login"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, strings.NewReader(string(body)))
	if err != nil {
		return "", fmt.Errorf("build AppRole login request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	c.setCommonHeaders(req, "")

	resp, err := c.hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("AppRole login request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("AppRole login returned HTTP %d", resp.StatusCode)
	}
	var result struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&result); err != nil {
		return "", fmt.Errorf("decode AppRole login response: %w", err)
	}
	if result.Auth.ClientToken == "" {
		return "", fmt.Errorf("AppRole login response carried no client_token")
	}
	return result.Auth.ClientToken, nil
}

// setCommonHeaders sets the token (when non-empty) and namespace headers every request needs.
// token is passed explicitly rather than always using c.token so appRoleLogin (which runs
// before c.token is set) can share this helper.
func (c *Client) setCommonHeaders(req *http.Request, token string) {
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	if c.namespace != "" {
		req.Header.Set("X-Vault-Namespace", c.namespace)
	}
	req.Header.Set("Accept", "application/json")
}

// Entry is one Vault KV field, ready to become a Keyorix secret. Path is the KV path (without
// mount) the value was read from; Field is the KV field name ("value" for a single-field
// leaf's own sentinel field, mirroring source_vault.go's readLeaf convention). Metadata carries
// Vault's own custom_metadata (KV v2 only) for mapping into Keyorix's metadata.
type Entry struct {
	Path     string
	Field    string
	Value    string
	Metadata map[string]string
}

// SourceID is a stable identifier for this entry within this Vault, used as
// docs/design-keyorix-migrate.md's idempotency key. It intentionally excludes the token/
// credentials — only the address, mount, KV version and path/field identify "where this data
// came from," which is what must stay stable across runs with different auth.
func (e Entry) SourceID(addr, mount string, kvVersion int) string {
	field := e.Field
	if field == "" {
		field = "value"
	}
	return fmt.Sprintf("%s|%s|kv%d|%s|%s", strings.TrimRight(addr, "/"), strings.Trim(mount, "/"), kvVersion, e.Path, field)
}

// Walk recursively lists the KV tree under root and returns every field as an Entry.
// allVersions=false (the default) reads only the current version of each leaf; allVersions=true
// is not yet supported (see docs/design-keyorix-migrate.md's "Open questions" — Keyorix's
// secret-versioning API isn't in this tool's scope yet) and returns an error rather than
// silently behaving like allVersions=false.
func (c *Client) Walk(ctx context.Context, root string, allVersions bool) ([]Entry, error) {
	if allVersions {
		return nil, fmt.Errorf("--all-versions is not yet supported (see docs/design-keyorix-migrate.md's Open questions — Keyorix's secret-version-create API isn't wired into this tool yet); omit the flag to import the latest version of each secret")
	}
	var entries []Entry
	if err := c.walk(ctx, strings.Trim(root, "/"), &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

func (c *Client) walk(ctx context.Context, prefix string, out *[]Entry) error {
	keys, err := c.list(ctx, prefix)
	if err != nil {
		return err
	}
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

func (c *Client) readLeaf(ctx context.Context, path string, out *[]Entry) error {
	fields, meta, err := c.read(ctx, path)
	if err != nil {
		return err
	}
	if len(fields) == 0 {
		return nil
	}
	if len(fields) == 1 {
		if v, ok := fields["value"]; ok {
			if val := fmt.Sprintf("%v", v); val != "" {
				*out = append(*out, Entry{Path: path, Field: "", Value: val, Metadata: meta})
			}
			return nil
		}
	}
	for k, v := range fields {
		val := fmt.Sprintf("%v", v)
		if k == "" || val == "" {
			continue
		}
		*out = append(*out, Entry{Path: path, Field: k, Value: val, Metadata: meta})
	}
	return nil
}

// list returns the child keys at path (sub-paths end in "/"); a 404 means path is not a
// listable folder and yields no keys.
func (c *Client) list(ctx context.Context, path string) ([]string, error) {
	kvVersion, err := c.resolveKVMountVersion(ctx, path)
	if err != nil {
		return nil, err
	}
	reqURL := c.metadataURL(path, kvVersion) + "?list=true"
	var body struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	status, err := c.do(ctx, http.MethodGet, reqURL, &body)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, nil
	}
	return body.Data.Keys, nil
}

// read returns the field map and custom_metadata (KV v2 only) at a KV leaf path. A 404 yields
// (nil, nil, nil).
func (c *Client) read(ctx context.Context, path string) (map[string]interface{}, map[string]string, error) {
	kvVersion, err := c.resolveKVMountVersion(ctx, path)
	if err != nil {
		return nil, nil, err
	}
	var raw json.RawMessage
	status, err := c.do(ctx, http.MethodGet, c.dataURL(path, kvVersion), &raw)
	if err != nil {
		return nil, nil, err
	}
	if status == http.StatusNotFound {
		return nil, nil, nil
	}

	if kvVersion == 1 {
		var v1 struct {
			Data map[string]interface{} `json:"data"`
		}
		if err := json.Unmarshal(raw, &v1); err != nil {
			return nil, nil, fmt.Errorf("decode vault read %q: %w", path, err)
		}
		return v1.Data, nil, nil
	}

	// KV v2: the secret lives at data.data; data.metadata.custom_metadata carries operator
	// tags. A soft-deleted version reads back as `{"data": null, "metadata": {...}}` -- a
	// 200 OK, not a 404 -- so it must be treated as absent explicitly, matching
	// internal/connect/vault.go's GetSecret doc comment on this exact footgun.
	var v2 struct {
		Data struct {
			Data     json.RawMessage `json:"data"`
			Metadata struct {
				CustomMetadata map[string]string `json:"custom_metadata"`
			} `json:"metadata"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &v2); err != nil {
		return nil, nil, fmt.Errorf("decode vault read %q: %w", path, err)
	}
	if len(v2.Data.Data) == 0 || string(v2.Data.Data) == "null" {
		return nil, nil, nil // soft-deleted or destroyed version: absent, not an empty secret.
	}
	var fields map[string]interface{}
	if err := json.Unmarshal(v2.Data.Data, &fields); err != nil {
		return nil, nil, fmt.Errorf("decode vault KV v2 fields %q: %w", path, err)
	}
	return fields, v2.Data.Metadata.CustomMetadata, nil
}

// resolveKVMountVersion determines whether the mount serving path is KV v1 or v2 by querying
// Vault's sys/internal/ui/mounts/<path> API directly, exactly as internal/connect/vault.go
// does (ported unchanged — see that file's doc comment for the two response-shape-sniffing
// bugs this avoids: a v1 secret whose own fields are literally named "data"/"metadata", and a
// soft-deleted v2 version's null-data envelope). Cached per mount path for this Client's
// lifetime.
func (c *Client) resolveKVMountVersion(ctx context.Context, path string) (int, error) {
	c.mountVersionsMu.Lock()
	for mountPath, version := range c.mountVersions {
		if strings.HasPrefix(path, mountPath) || path == strings.TrimSuffix(mountPath, "/") {
			c.mountVersionsMu.Unlock()
			return version, nil
		}
	}
	c.mountVersionsMu.Unlock()

	full := c.mount
	if path != "" {
		full = c.mount + "/" + path
	}
	reqURL := c.addr + "/v1/sys/internal/ui/mounts/" + escapePath(full)
	var mountResp struct {
		Data struct {
			Path    string `json:"path"`
			Options struct {
				Version string `json:"version"`
			} `json:"options"`
		} `json:"data"`
	}
	if _, err := c.do(ctx, http.MethodGet, reqURL, &mountResp); err != nil {
		return 0, fmt.Errorf("resolve KV mount version for %q: %w", path, err)
	}

	version := 1
	if mountResp.Data.Options.Version == "2" {
		version = 2
	}
	mountPath := mountResp.Data.Path
	if mountPath == "" {
		mountPath = c.mount + "/"
	}
	c.mountVersionsMu.Lock()
	if c.mountVersions == nil {
		c.mountVersions = make(map[string]int)
	}
	c.mountVersions[mountPath] = version
	c.mountVersionsMu.Unlock()
	return version, nil
}

// do issues an authenticated request and decodes a non-404 success body into out (when out is
// non-nil), returning the HTTP status so callers can treat 404 as "absent."
func (c *Client) do(ctx context.Context, method, url string, out interface{}) (int, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return 0, fmt.Errorf("build request: %w", err)
	}
	c.setCommonHeaders(req, c.token)

	resp, err := c.hc.Do(req)
	if err != nil {
		return 0, fmt.Errorf("vault request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode == http.StatusNotFound {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
		return resp.StatusCode, nil
	}
	if resp.StatusCode == http.StatusForbidden {
		return resp.StatusCode, fmt.Errorf("vault denied access (HTTP 403) for %s — check token/AppRole permissions", url)
	}
	if resp.StatusCode >= 400 {
		return resp.StatusCode, fmt.Errorf("vault returned HTTP %d for %s", resp.StatusCode, url)
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
		return resp.StatusCode, nil
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(out); err != nil {
		return resp.StatusCode, fmt.Errorf("decode vault response: %w", err)
	}
	return resp.StatusCode, nil
}

func (c *Client) metadataURL(path string, kvVersion int) string {
	if kvVersion == 2 {
		return c.join("metadata", path)
	}
	return c.join("", path)
}

func (c *Client) dataURL(path string, kvVersion int) string {
	if kvVersion == 2 {
		return c.join("data", path)
	}
	return c.join("", path)
}

// join assembles {addr}/v1/{mount}[/{segment}]/{path}, path-escaping the mount and path
// components per segment — ported from source_vault.go's join/escapePath, same rationale
// (Vault permits URL-significant characters in secret/key names; escaping keeps them literal
// instead of mangling the request).
func (c *Client) join(segment, path string) string {
	parts := []string{c.addr, "v1", escapePath(c.mount)}
	if segment != "" {
		parts = append(parts, segment)
	}
	if p := escapePath(path); p != "" {
		parts = append(parts, p)
	}
	return strings.Join(parts, "/")
}

func escapePath(p string) string {
	segs := strings.Split(strings.Trim(p, "/"), "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return strings.Join(segs, "/")
}
