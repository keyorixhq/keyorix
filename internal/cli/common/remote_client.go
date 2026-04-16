package common

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	cliconfig "github.com/keyorixhq/keyorix/internal/cli/config"
	"github.com/keyorixhq/keyorix/internal/config"
)

// ResolveRemote returns the server endpoint and Bearer token from all config sources.
//
// Priority: env vars > ~/.keyorix/cli.yaml (written by 'keyorix connect')
//
//	> keyorix.yaml (written by 'keyorix auth login --server')
//
// Returns ok=false when no usable remote configuration exists, meaning the
// caller should fall back to embedded (direct-DB) mode.
func ResolveRemote() (endpoint, token string, ok bool) {
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

	// Main config (keyorix.yaml — written by 'keyorix auth login --server')
	if endpoint == "" || token == "" {
		if mainCfg, err := config.Load(""); err == nil &&
			mainCfg.Storage.Type == "remote" && mainCfg.Storage.Remote != nil {
			if endpoint == "" {
				endpoint = mainCfg.Storage.Remote.BaseURL
			}
			if token == "" {
				token = mainCfg.Storage.Remote.GetAPIKey()
			}
		}
	}

	ok = endpoint != "" && token != ""
	return
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
		hc:       &http.Client{},
	}, true
}

// Get performs a GET to path, strips the {"data":…} envelope, and decodes into out.
func (c *RemoteClient) Get(ctx context.Context, path string, out interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Endpoint+path, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("server returned HTTP %d for %s", resp.StatusCode, path)
	}
	return decodeEnvelope(resp, out, path)
}

// Post serialises body as JSON, POSTs to path, strips the envelope, and decodes into out.
func (c *RemoteClient) Post(ctx context.Context, path string, body interface{}, out interface{}) error {
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal request body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint+path, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("server returned HTTP %d for %s", resp.StatusCode, path)
	}
	return decodeEnvelope(resp, out, path)
}

// decodeEnvelope strips {"data":…} and unmarshals the inner payload into out.
func decodeEnvelope(resp *http.Response, out interface{}, path string) error {
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return fmt.Errorf("decode response from %s: %w", path, err)
	}
	if env.Data == nil {
		return fmt.Errorf("empty data in response from %s", path)
	}
	return json.Unmarshal(env.Data, out)
}
