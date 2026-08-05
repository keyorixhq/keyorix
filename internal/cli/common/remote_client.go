package common

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	cliconfig "github.com/keyorixhq/keyorix/internal/cli/config"
	"github.com/keyorixhq/keyorix/internal/config"
)

const (
	bearerPrefix   = "Bearer "
	hdrContentType = "Content-Type"
	mimeJSON       = "application/json"
)

// maxRemoteResponseBytes caps how much of a Keyorix server response body this
// client will read into memory before decoding. RemoteClient backs every CLI
// command's remote mode (projects, secrets, environments, users, audit
// listings…), so a generous cap is used — matching the same 10MB idiom used
// for the equivalent MCP client response decode (internal/mcp/keyorix.go) —
// rather than a tight one tuned to any single endpoint's typical payload. This
// bounds a malicious or misbehaving server response from exhausting client
// memory via an unbounded json.Decode of resp.Body.
const maxRemoteResponseBytes = 10 << 20 // 10MB

// ResolveRemote returns the server endpoint and Bearer token from all config sources.
//
// Priority: env vars > ~/.keyorix/cli.yaml (written by 'keyorix connect')
//
//	> keyorix.yaml (written by 'keyorix auth login --server')
//
// Returns ok=false when no usable remote configuration exists, meaning the
// caller should fall back to embedded (direct-DB) mode.
func ResolveRemote() (endpoint, token string, ok bool) { // NOSONAR -- cognitive complexity 25, suppress go:S3776
	token = os.Getenv("KEYORIX_TOKEN")
	endpoint = os.Getenv("KEYORIX_SERVER")

	// CLI config (~/.keyorix/cli.yaml — written by 'keyorix connect')
	if cliCfg, err := cliconfig.LoadCLIConfig(""); err == nil && cliCfg.IsClientMode() {
		if endpoint == "" {
			endpoint = cliCfg.Client.Endpoint
		}
		if token == "" {
			token = cliCfg.Client.Auth.GetAPIKey()
		}
	}

	// Main config (keyorix.yaml — written by 'keyorix auth login --server'). config.Load
	// resolves a CWD-relative ./keyorix.yaml, so a type:remote config planted in the
	// working directory could silently redirect the CLI to an attacker server. Warn when
	// the remote endpoint/token is sourced from it (env and ~/.keyorix/cli.yaml above are
	// the trusted sources).
	if endpoint == "" || token == "" {
		if mainCfg, err := config.Load(""); err == nil &&
			mainCfg.Storage.Type == "remote" && mainCfg.Storage.Remote != nil {
			fromMain := false
			if endpoint == "" && mainCfg.Storage.Remote.BaseURL != "" {
				endpoint = mainCfg.Storage.Remote.BaseURL
				fromMain = true
			}
			if token == "" && mainCfg.Storage.Remote.GetAPIKey() != "" {
				token = mainCfg.Storage.Remote.GetAPIKey()
				fromMain = true
			}
			if fromMain {
				fmt.Fprintf(os.Stderr, "⚠️  Using a remote server config from ./keyorix.yaml in the current directory. If you did not place it here, a malicious file could be redirecting the CLI — prefer KEYORIX_SERVER/KEYORIX_TOKEN or 'keyorix connect'.\n")
			}
		}
	}

	// A non-HTTPS endpoint sends the bearer token in cleartext — warn loudly (a loopback
	// target for local testing is fine).
	if endpoint != "" && !endpointIsSecure(endpoint) {
		fmt.Fprintf(os.Stderr, "⚠️  Remote endpoint %q is not HTTPS — the access token is sent in cleartext and is MITM-capturable.\n", endpoint)
	}

	ok = endpoint != "" && token != ""
	return
}

// endpointIsSecure reports whether the endpoint is https or a loopback target.
func endpointIsSecure(endpoint string) bool {
	u, err := url.Parse(endpoint)
	if err != nil {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	host := u.Hostname()
	if host == "localhost" || strings.HasPrefix(host, "127.") || host == "::1" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// RemoteClient makes authenticated requests to the Keyorix HTTP API.
// Every response is unwrapped from the server's {"data": …} envelope before
// it is decoded into the caller-supplied target.
type RemoteClient struct {
	Endpoint string
	Token    string
	hc       *http.Client
}

// NewRemoteClient constructs a RemoteClient from the current configuration.
// Returns (nil, false) when no remote configuration is found so callers can
// fall back to embedded mode.
func NewRemoteClient() (*RemoteClient, bool) {
	endpoint, token, ok := ResolveRemote()
	if !ok {
		return nil, false
	}
	return &RemoteClient{
		Endpoint: endpoint,
		Token:    token,
		// #315: the zero-value http.Client has an infinite Timeout. Only 3 CLI
		// commands (status/connect/offline) wrap their own calls in
		// context.WithTimeout; the 100+ other call sites across secret/rbac/
		// machine/rotation/project/dynamic etc. use undecorated contexts — a hung
		// or misconfigured KEYORIX_SERVER would otherwise hang the CLI forever
		// with no way out. Mirrors the storage-layer remote client's default.
		hc: &http.Client{Timeout: defaultRemoteClientTimeout},
	}, true
}

// defaultRemoteClientTimeout matches internal/storage/remote's default
// (Config.GetTimeout's 30s fallback when TimeoutSeconds is unset).
const defaultRemoteClientTimeout = 30 * time.Second

// Get performs a GET to path, strips the {"data":…} envelope, and decodes into out.
func (c *RemoteClient) Get(ctx context.Context, path string, out interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Endpoint+path, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", bearerPrefix+c.Token)
	req.Header.Set("Accept", mimeJSON)

	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode >= 400 {
		return fmt.Errorf("server returned HTTP %d for %s", resp.StatusCode, path)
	}
	return decodeEnvelope(resp, out, path)
}

// GetRaw performs a GET and returns the raw, un-enveloped response body. Used for
// endpoints that serve a non-JSON artifact directly (e.g. the text/csv compliance and
// inventory exports), where the dashboard downloads the same bytes.
func (c *RemoteClient) GetRaw(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Endpoint+path, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", bearerPrefix+c.Token)
	req.Header.Set("Accept", "text/csv, */*")

	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("server returned HTTP %d for %s", resp.StatusCode, path)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response from %s: %w", path, err)
	}
	return body, nil
}

// Post serialises body as JSON, POSTs to path, strips the envelope, and decodes
// into out (out may be nil, matching Put/Patch, when the caller doesn't need the
// response body).
func (c *RemoteClient) Post(ctx context.Context, path string, body interface{}, out interface{}) error {
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal request body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint+path, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", bearerPrefix+c.Token)
	req.Header.Set(hdrContentType, mimeJSON)
	req.Header.Set("Accept", mimeJSON)

	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode >= 400 {
		return fmt.Errorf("server returned HTTP %d for %s", resp.StatusCode, path)
	}
	if out != nil {
		return decodeEnvelope(resp, out, path)
	}
	return nil
}

// decodeEnvelope strips {"data":…} and unmarshals the inner payload into out.
func decodeEnvelope(resp *http.Response, out interface{}, path string) error {
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxRemoteResponseBytes)).Decode(&env); err != nil {
		return fmt.Errorf("decode response from %s: %w", path, err)
	}
	if env.Data == nil {
		return fmt.Errorf("empty data in response from %s", path)
	}
	return json.Unmarshal(env.Data, out)
}

// Put serialises body as JSON, PUTs to path, strips the envelope, and decodes into out.
func (c *RemoteClient) Put(ctx context.Context, path string, body interface{}, out interface{}) error {
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal request body: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.Endpoint+path, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", bearerPrefix+c.Token)
	req.Header.Set(hdrContentType, mimeJSON)
	req.Header.Set("Accept", mimeJSON)

	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode >= 400 {
		return fmt.Errorf("server returned HTTP %d for %s", resp.StatusCode, path)
	}
	if out != nil {
		return decodeEnvelope(resp, out, path)
	}
	return nil
}

// Patch sends a PATCH to path with a JSON body and decodes the response envelope
// into out (out may be nil).
func (c *RemoteClient) Patch(ctx context.Context, path string, body interface{}, out interface{}) error {
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal request body: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, c.Endpoint+path, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", bearerPrefix+c.Token)
	req.Header.Set(hdrContentType, mimeJSON)
	req.Header.Set("Accept", mimeJSON)

	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode >= 400 {
		return fmt.Errorf("server returned HTTP %d for %s", resp.StatusCode, path)
	}
	if out != nil {
		return decodeEnvelope(resp, out, path)
	}
	return nil
}

// DeleteWithBody sends a DELETE to path carrying a JSON body (some endpoints —
// e.g. DELETE /user-roles — identify the target in the body rather than the URL).
// No response body is expected.
func (c *RemoteClient) DeleteWithBody(ctx context.Context, path string, body interface{}) error {
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal request body: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.Endpoint+path, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", bearerPrefix+c.Token)
	req.Header.Set(hdrContentType, mimeJSON)

	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode >= 400 {
		return fmt.Errorf("server returned HTTP %d for %s", resp.StatusCode, path)
	}
	return nil
}

// Delete sends a DELETE to path. No response body is expected.
func (c *RemoteClient) Delete(ctx context.Context, path string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.Endpoint+path, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", bearerPrefix+c.Token)

	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode >= 400 {
		return fmt.Errorf("server returned HTTP %d for %s", resp.StatusCode, path)
	}
	return nil
}
