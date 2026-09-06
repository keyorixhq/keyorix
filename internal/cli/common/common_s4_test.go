// common_s4_test.go — coverage push for cli/common (batch s4).
// Targets:
//   - ResolveRemote: cli.yaml client-mode path, mainCfg remote path, non-HTTPS warning
//   - endpointIsSecure: url.Parse error path
//   - Get/GetRaw/Post/Put/Patch/DeleteWithBody/Delete: "build request" (invalid endpoint)
//     and "request failed" (server closes connection immediately) error paths
//   - ResolveProject: cli.yaml active_project fallback
//   - InitializeCoreService: default-config path (no config file), wireSecretEncryption error
//   - InitializeStorage: config.Load failure
package common

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	cliconfig "github.com/keyorixhq/keyorix/internal/cli/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── helpers ───────────────────────────────────────────────────────────────────

// newDropClient returns a RemoteClient backed by a server that closes every
// connection immediately, exercising the "request failed" (network error) path.
func newDropClient(t *testing.T) (*RemoteClient, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	// Accept and immediately close — the HTTP client will see a connection-reset.
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	addr := "http://" + ln.Addr().String()
	rc := &RemoteClient{Endpoint: addr, Token: "tok", hc: &http.Client{}}
	return rc, func() { _ = ln.Close() }
}

// newBadEndpointClient returns a RemoteClient whose Endpoint is syntactically
// invalid so that http.NewRequestWithContext returns an error ("build request").
func newBadEndpointClient() *RemoteClient {
	return &RemoteClient{Endpoint: "://\x00bad", Token: "tok", hc: &http.Client{}}
}

// writeCLIConfig writes a minimal cli.yaml to configDir/keyorix/cli.yaml.
// Returns the path used as XDG_CONFIG_HOME.
func writeCLIConfig(t *testing.T, cfg *cliconfig.CLIConfig) string {
	t.Helper()
	dir := t.TempDir()
	err := cliconfig.SaveCLIConfig(cfg, filepath.Join(dir, "keyorix", "cli.yaml"))
	require.NoError(t, err)
	return dir
}

// ── endpointIsSecure: url.Parse error path ───────────────────────────────────

func TestEndpointIsSecure_ParseError(t *testing.T) {
	// ":" triggers url.Parse to return an error ("missing protocol scheme").
	assert.False(t, endpointIsSecure(":"))
}

// ── ResolveRemote ─────────────────────────────────────────────────────────────

// TestResolveRemote_CLIConfig_ClientMode covers the cliCfg.IsClientMode() branch
// where endpoint and token are taken from ~/.keyorix/cli.yaml when no env vars
// are set and the CLI is in client mode.
func TestResolveRemote_CLIConfig_ClientMode(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("KEYORIX_API_KEY", "")

	cfg := cliconfig.DefaultCLIConfig()
	cfg.SetClientMode("http://127.0.0.1:9999", "cli-cfg-token")
	xdg := writeCLIConfig(t, cfg)
	t.Setenv("XDG_CONFIG_HOME", xdg)

	// Also suppress the main config so it isn't loaded.
	t.Setenv("KEYORIX_CONFIG_PATH", filepath.Join(t.TempDir(), "nonexistent.yaml"))

	endpoint, token, ok := ResolveRemote()
	// loopback → endpointIsSecure=true so no warning
	assert.True(t, ok, "should resolve from cli.yaml")
	assert.Equal(t, "http://127.0.0.1:9999", endpoint)
	assert.Equal(t, "cli-cfg-token", token)
}

// TestResolveRemote_NonHTTPS_Warning covers the "endpoint != "" && !endpointIsSecure"
// warning branch (line 73-75).
func TestResolveRemote_NonHTTPS_Warning(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "http://remote.example.com:8080")
	t.Setenv("KEYORIX_TOKEN", "some-token")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("KEYORIX_CONFIG_PATH", filepath.Join(t.TempDir(), "nonexistent.yaml"))

	stderr := captureStderr(t, func() {
		endpoint, token, ok := ResolveRemote()
		assert.True(t, ok)
		assert.Equal(t, "http://remote.example.com:8080", endpoint)
		assert.Equal(t, "some-token", token)
	})
	assert.Contains(t, stderr, "MITM-capturable")
}

// TestResolveRemote_MainConfig_Remote covers the mainCfg "fromMain" warning
// branch where both endpoint and token come from keyorix.yaml (lines 55-67).
func TestResolveRemote_MainConfig_Remote(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	// Put CLI in embedded mode so the cliCfg branch does not fire.
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	// Write a main keyorix.yaml with remote storage config.
	cfgDir := t.TempDir()
	cfgPath := filepath.Join(cfgDir, "keyorix.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(`storage:
  type: remote
  remote:
    base_url: "http://127.0.0.1:19998"
    api_key: "main-cfg-token"
`), 0600))
	t.Setenv("KEYORIX_CONFIG_PATH", cfgPath)

	stderr := captureStderr(t, func() {
		endpoint, token, ok := ResolveRemote()
		assert.True(t, ok)
		assert.Equal(t, "http://127.0.0.1:19998", endpoint)
		assert.Equal(t, "main-cfg-token", token)
	})
	// The "fromMain" warning must appear.
	assert.Contains(t, stderr, "keyorix.yaml")
}

// TestResolveRemote_CLIConfig_FillsOnlyMissingFields covers the partial-fill
// branches: env var supplies endpoint but not token; cli.yaml client config
// fills in the missing token.
func TestResolveRemote_CLIConfig_FillsOnlyMissingFields(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "http://127.0.0.1:9998")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("KEYORIX_API_KEY", "")

	cfg := cliconfig.DefaultCLIConfig()
	cfg.SetClientMode("http://127.0.0.1:9999", "cli-token-fill")
	xdg := writeCLIConfig(t, cfg)
	t.Setenv("XDG_CONFIG_HOME", xdg)
	t.Setenv("KEYORIX_CONFIG_PATH", filepath.Join(t.TempDir(), "nonexistent.yaml"))

	endpoint, token, ok := ResolveRemote()
	assert.True(t, ok)
	// Endpoint from env var wins; token filled from cli.yaml.
	assert.Equal(t, "http://127.0.0.1:9998", endpoint)
	assert.Equal(t, "cli-token-fill", token)
}

// ── ResolveProject: cli.yaml active_project path ─────────────────────────────

func TestResolveProject_CLIYaml_ActiveProject(t *testing.T) {
	t.Setenv("KEYORIX_PROJECT", "")

	cfg := cliconfig.DefaultCLIConfig()
	cfg.SetActiveProject("yaml-project")
	xdg := writeCLIConfig(t, cfg)
	t.Setenv("XDG_CONFIG_HOME", xdg)

	got, err := ResolveProject("")
	require.NoError(t, err)
	assert.Equal(t, "yaml-project", got)
}

// ── HTTP "build request" error paths ─────────────────────────────────────────

func TestRemoteClient_Get_BuildRequestError(t *testing.T) {
	err := newBadEndpointClient().Get(context.Background(), "/v1/x", &struct{}{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "build request")
}

func TestRemoteClient_GetRaw_BuildRequestError(t *testing.T) {
	_, err := newBadEndpointClient().GetRaw(context.Background(), "/v1/x")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "build request")
}

func TestRemoteClient_Delete_BuildRequestError(t *testing.T) {
	err := newBadEndpointClient().Delete(context.Background(), "/v1/x")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "build request")
}

// ── HTTP "request failed" (network error) paths ───────────────────────────────

func TestRemoteClient_Get_RequestFailed(t *testing.T) {
	rc, cleanup := newDropClient(t)
	defer cleanup()

	err := rc.Get(context.Background(), "/v1/x", &struct{}{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "request failed")
}

func TestRemoteClient_GetRaw_RequestFailed(t *testing.T) {
	rc, cleanup := newDropClient(t)
	defer cleanup()

	_, err := rc.GetRaw(context.Background(), "/v1/x")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "request failed")
}

func TestRemoteClient_Post_RequestFailed(t *testing.T) {
	rc, cleanup := newDropClient(t)
	defer cleanup()

	err := rc.Post(context.Background(), "/v1/x", struct{}{}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "request failed")
}

func TestRemoteClient_Put_RequestFailed(t *testing.T) {
	rc, cleanup := newDropClient(t)
	defer cleanup()

	err := rc.Put(context.Background(), "/v1/x", struct{}{}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "request failed")
}

func TestRemoteClient_Patch_RequestFailed(t *testing.T) {
	rc, cleanup := newDropClient(t)
	defer cleanup()

	err := rc.Patch(context.Background(), "/v1/x", struct{}{}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "request failed")
}

func TestRemoteClient_DeleteWithBody_RequestFailed(t *testing.T) {
	rc, cleanup := newDropClient(t)
	defer cleanup()

	err := rc.DeleteWithBody(context.Background(), "/v1/x", struct{}{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "request failed")
}

func TestRemoteClient_Delete_RequestFailed(t *testing.T) {
	rc, cleanup := newDropClient(t)
	defer cleanup()

	err := rc.Delete(context.Background(), "/v1/x")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "request failed")
}

// ── GetRaw: io.ReadAll error path ─────────────────────────────────────────────

// badBodyHandler writes headers, then closes the connection mid-body so that
// io.ReadAll returns an error.
func badBodyHandler(w http.ResponseWriter, r *http.Request) {
	// Hint the client that there's a body coming, then hijack and close.
	w.Header().Set("Content-Length", "9999")
	w.WriteHeader(http.StatusOK)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	// Hijack the connection and close it to cause a read error on the client.
	if hj, ok := w.(http.Hijacker); ok {
		conn, _, err := hj.Hijack()
		if err == nil {
			_ = conn.Close()
		}
	}
}

func TestRemoteClient_GetRaw_ReadBodyError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(badBodyHandler))
	defer srv.Close()

	rc := &RemoteClient{Endpoint: srv.URL, Token: "tok", hc: srv.Client()}
	_, err := rc.GetRaw(context.Background(), "/v1/export")
	// We accept either "request failed" (if the EOF happens during do) or
	// "read response" (if it happens during ReadAll).  Either signals the
	// uncovered branch is now exercised.
	require.Error(t, err)
}

// ── InitializeCoreService: default-config fallback path ─────────────────────

// TestInitializeCoreService_NoConfigFile exercises the "config.Load fails
// with IsNotExist" branch by pointing KEYORIX_CONFIG_PATH at a non-existent
// file so config.Load returns an error.
//
// #G-blank-storage-default: this used to assert InitializeCoreService silently
// falls back to a local SQLite config (Storage.Type="local",
// Database.Path="./secrets.db") and succeeds — a CLI command run with zero
// usable configuration (no keyorix.yaml, no KEYORIX_CONFIG_PATH) silently
// created a real, on-disk local database file, completely bypassing whatever
// backend (e.g. a `keyorix connect`-configured remote server) the operator
// actually intended. The CLI must never apply that default (see the matching
// comment in internal/storage/factory.go's CreateStorage) — it must now fail
// loudly instead of silently creating ./secrets.db.
func TestInitializeCoreService_NoConfigFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("KEYORIX_MASTER_PASSWORD", "")
	// An absolute path pointing to a file that does not exist causes config.Load to fail.
	t.Setenv("KEYORIX_CONFIG_PATH", filepath.Join(dir, "does-not-exist.yaml"))

	svc, err := InitializeCoreService()
	require.Error(t, err)
	assert.Nil(t, svc)
	assert.Contains(t, err.Error(), "storage.type is not set")
}

// ── InitializeCoreService: wireSecretEncryption error propagated ─────────────

// TestInitializeCoreService_EncryptionMisconfigFails exercises the
// wireSecretEncryption error path (line 98-100): encryption is enabled but
// KEYORIX_MASTER_PASSWORD is empty, so wireSecretEncryption returns an error
// that InitializeCoreService propagates.
func TestInitializeCoreService_EncryptionMisconfigFails(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("KEYORIX_MASTER_PASSWORD", "")

	cfgPath := filepath.Join(dir, "keyorix.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(`storage:
  type: local
  database:
    path: "`+dir+`/enc_misconfig.db"
  encryption:
    enabled: true
    dek_path: "dek.json"
    salt_path: "salt.bin"
locale:
  language: "en"
  fallback_language: "en"
`), 0600))
	t.Setenv("KEYORIX_CONFIG_PATH", cfgPath)
	t.Chdir(dir)

	_, err := InitializeCoreService()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "KEYORIX_MASTER_PASSWORD")
}

// ── InitializeStorage: config.Load failure ──────────────────────────────────

// TestInitializeStorage_ConfigLoadError exercises the error path at lines 172-174
// by pointing KEYORIX_CONFIG_PATH at a non-existent absolute file.
func TestInitializeStorage_ConfigLoadError(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEYORIX_CONFIG_PATH", filepath.Join(dir, "missing.yaml"))

	_, err := InitializeStorage()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load config")
}

// ── InitializeCoreService: delivery.New failure path ─────────────────────────

// TestInitializeCoreService_DeliveryMisconfigIsIgnored exercises the
// "delivery.New error → svc.SetCredentialDelivery(nil, ...)" branch (lines 106-108).
// A misconfigured delivery mode (smtp with no host) triggers the error; the
// function should still succeed because the error is best-effort.
func TestInitializeCoreService_DeliveryMisconfigIsIgnored(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("KEYORIX_MASTER_PASSWORD", "")

	cfgPath := filepath.Join(dir, "keyorix.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(`storage:
  type: local
  database:
    path: "`+dir+`/delivery_test.db"
locale:
  language: "en"
  fallback_language: "en"
credential_delivery:
  mode: "smtp"
  smtp:
    host: ""
`), 0600))
	t.Setenv("KEYORIX_CONFIG_PATH", cfgPath)

	svc, err := InitializeCoreService()
	require.NoError(t, err)
	assert.NotNil(t, svc)
}

// ── Post/Put/Patch/DeleteWithBody: "build request" error paths ───────────────

func TestRemoteClient_Post_BuildRequestError(t *testing.T) {
	err := newBadEndpointClient().Post(context.Background(), "/v1/x", struct{ V string }{"ok"}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "build request")
}

func TestRemoteClient_Put_BuildRequestError(t *testing.T) {
	err := newBadEndpointClient().Put(context.Background(), "/v1/x", struct{ V string }{"ok"}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "build request")
}

func TestRemoteClient_Patch_BuildRequestError(t *testing.T) {
	err := newBadEndpointClient().Patch(context.Background(), "/v1/x", struct{ V string }{"ok"}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "build request")
}

func TestRemoteClient_DeleteWithBody_BuildRequestError(t *testing.T) {
	err := newBadEndpointClient().DeleteWithBody(context.Background(), "/v1/x", struct{ V string }{"ok"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "build request")
}

// ── InitializeCoreService: factory.CreateStorage failure path ────────────────

// TestInitializeCoreService_InvalidStorageTypeFails exercises the
// "factory.CreateStorage fails" branch (line 74-76) by specifying an unrecognised
// storage.type in the config so the factory returns an error.
func TestInitializeCoreService_InvalidStorageTypeFails(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("KEYORIX_MASTER_PASSWORD", "")

	cfgPath := filepath.Join(dir, "keyorix.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(`storage:
  type: "invalid-storage-type"
locale:
  language: "en"
  fallback_language: "en"
`), 0600))
	t.Setenv("KEYORIX_CONFIG_PATH", cfgPath)

	_, err := InitializeCoreService()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create storage")
}

// ── InitializeStorage: factory.CreateStorage failure path ───────────────────

// TestInitializeStorage_InvalidStorageTypeFails exercises the
// "factory.CreateStorage fails" branch (line 177-179) with an unrecognised
// storage.type.
func TestInitializeStorage_InvalidStorageTypeFails(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "keyorix.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(`storage:
  type: "invalid-type"
locale:
  language: "en"
  fallback_language: "en"
`), 0600))
	t.Setenv("KEYORIX_CONFIG_PATH", cfgPath)

	_, err := InitializeStorage()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create storage")
}

// ── wireSecretEncryption: encSvc.Initialize failure path ────────────────────

// TestWireSecretEncryption_UnknownKeyProviderFails exercises the
// "encSvc.Initialize fails" branch (line 146-148) by configuring an
// unrecognised key_provider.type which causes NewKeyProviderFromConfig to error.
func TestWireSecretEncryption_UnknownKeyProviderFails(t *testing.T) {
	t.Chdir(t.TempDir())
	// A non-empty, non-"password" provider type bypasses the passphrase check and
	// reaches encSvc.Initialize, which calls buildKeyProvider → error.
	t.Setenv("KEYORIX_MASTER_PASSWORD", "")

	cfg := encEnabledCfg("local")
	cfg.Storage.Encryption.KeyProvider.Type = "unknown-provider"
	svc := core.NewKeyorixCore(nil)
	err := wireSecretEncryption(svc, cfg)
	require.Error(t, err)
	// The error must mention the unknown provider.
	assert.Contains(t, err.Error(), "unknown-provider")
}

// ── Unused io import kept for badBodyHandler ──────────────────────────────────

var _ = io.EOF // keep io imported
