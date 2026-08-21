// common_s5_test.go — coverage push for cli/common (batch s5).
// Targets:
//   - ValidateRemoteEndpointURL: parse-error, non-http(s)-scheme, missing-host,
//     and valid branches (directly, not just indirectly via NewRemoteClient).
//   - NewRemoteClientWithCredentials: success and validation-failure paths.
//   - newHardenedRemoteClient: the ValidateRemoteEndpointURL failure branch.
//   - refuseRemoteClientRedirect: the CheckRedirect callback, both as a direct
//     unit test and wired end-to-end through an http.Client via Get().
//   - ResolveAPIKey: the prompt=true / interactive-read branch.
//   - wireSecretEncryption: the AcquireSharedKeyLock failure branch (a live
//     "server" already holds the exclusive key lock on the same key directory).
package common

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	cliconfig "github.com/keyorixhq/keyorix/internal/cli/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── ValidateRemoteEndpointURL ─────────────────────────────────────────────────

func TestValidateRemoteEndpointURL(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		wantErr string // substring expected in the error, "" means no error
	}{
		{"parse error", "://\x00bad", "invalid remote endpoint"},
		{"non-http(s) scheme", "ftp://example.com", "must use http or https"},
		{"missing host", "http://", "missing a host"},
		{"valid http", "http://keyorix.example.com", ""},
		{"valid https", "https://keyorix.example.com:8443", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidateRemoteEndpointURL(c.raw)
			if c.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), c.wantErr)
			if c.name != "parse error" {
				// The parse-error case re-quotes the raw string via url.Parse's own
				// %q-wrapped error, which double-escapes the NUL byte — skip the
				// literal substring check there and rely on wantErr instead.
				assert.Contains(t, err.Error(), c.raw)
			}
		})
	}
}

// ── NewRemoteClientWithCredentials ────────────────────────────────────────────

func TestNewRemoteClientWithCredentials_Success(t *testing.T) {
	rc, ok := NewRemoteClientWithCredentials("https://keyorix.example.com", "explicit-token")
	require.True(t, ok)
	require.NotNil(t, rc)
	assert.Equal(t, "https://keyorix.example.com", rc.Endpoint)
	assert.Equal(t, "explicit-token", rc.Token)
}

// TestNewRemoteClientWithCredentials_InvalidEndpoint covers both
// NewRemoteClientWithCredentials's failure return and, underneath it,
// newHardenedRemoteClient's ValidateRemoteEndpointURL rejection branch.
func TestNewRemoteClientWithCredentials_InvalidEndpoint(t *testing.T) {
	rc, ok := NewRemoteClientWithCredentials("ftp://example.com", "tok")
	assert.False(t, ok)
	assert.Nil(t, rc)
}

// ── refuseRemoteClientRedirect ────────────────────────────────────────────────

func TestRefuseRemoteClientRedirect(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "http://internal.example.com/secret", nil)
	require.NoError(t, err)

	err = refuseRemoteClientRedirect(req, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refusing to follow redirect")
	assert.Contains(t, err.Error(), "internal.example.com/secret")
}

// TestRemoteClient_RefusesToFollowRedirect proves the hardening is actually wired
// into the http.Client used by RemoteClient.Get (CWE-918): a server response that
// tries to 302 the request elsewhere (e.g. to an internal host) must not be
// followed transparently with the bearer token attached.
func TestRemoteClient_RefusesToFollowRedirect(t *testing.T) {
	var redirectTargetHit bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectTargetHit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/internal", http.StatusFound)
	}))
	defer srv.Close()

	rc, ok := newHardenedRemoteClient(srv.URL, "tok")
	require.True(t, ok)

	var out struct{}
	err := rc.Get(context.Background(), "/v1/x", &out)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "request failed")
	assert.False(t, redirectTargetHit, "the client must never actually reach the redirect target")
}

// ── ResolveRemote: invalid-stored-endpoint warning branches ──────────────────

// TestResolveRemote_CLIConfig_InvalidEndpointIsIgnored covers the
// ValidateRemoteEndpointURL failure branch inside the ~/.keyorix/cli.yaml
// resolution: a malformed endpoint persisted by a prior 'keyorix connect' (or
// hand-edited) must be ignored (not returned to the caller) rather than handed
// to an HTTP client, and a warning naming the source file must be printed.
func TestResolveRemote_CLIConfig_InvalidEndpointIsIgnored(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("KEYORIX_API_KEY", "")

	cfg := cliconfig.DefaultCLIConfig()
	cfg.SetClientMode("ftp://not-http-or-https.example.com", "cli-cfg-token")
	xdg := writeCLIConfig(t, cfg)
	t.Setenv("XDG_CONFIG_HOME", xdg)
	t.Setenv("KEYORIX_CONFIG_PATH", filepath.Join(t.TempDir(), "nonexistent.yaml"))

	stderr := captureStderr(t, func() {
		endpoint, _, ok := ResolveRemote()
		assert.False(t, ok, "an invalid persisted endpoint must not be surfaced as usable")
		assert.Empty(t, endpoint)
	})
	assert.Contains(t, stderr, "Ignoring remote endpoint from ~/.keyorix/cli.yaml")
	assert.Contains(t, stderr, "must use http or https")
}

// TestResolveRemote_MainConfig_InvalidEndpointIsIgnored is the ./keyorix.yaml
// counterpart: an invalid storage.remote.base_url must be ignored with a
// warning, not silently handed to an HTTP client.
func TestResolveRemote_MainConfig_InvalidEndpointIsIgnored(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	cfgDir := t.TempDir()
	cfgPath := filepath.Join(cfgDir, "keyorix.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(`storage:
  type: remote
  remote:
    base_url: "ftp://not-http-or-https.example.com"
    api_key: "main-cfg-token"
`), 0600))
	t.Setenv("KEYORIX_CONFIG_PATH", cfgPath)

	stderr := captureStderr(t, func() {
		endpoint, token, ok := ResolveRemote()
		assert.False(t, ok, "an invalid persisted endpoint must not be surfaced as usable")
		assert.Empty(t, endpoint)
		// Token still comes through independently of the endpoint validity.
		assert.Equal(t, "main-cfg-token", token)
	})
	assert.Contains(t, stderr, "Ignoring remote endpoint from ./keyorix.yaml")
	assert.Contains(t, stderr, "must use http or https")
}

// ── ResolveAPIKey: interactive prompt path ────────────────────────────────────

// TestResolveAPIKey_PromptWithNeitherFlagNorEnv exercises the prompt=true branch
// (--api-key unset, KEYORIX_API_KEY unset). In the non-tty environment `go test`
// runs under, term.ReadPassword always fails immediately (the same established
// pattern as internal/cli/dynamic's TestReadAdminDSN_S23_ErrorMentionsEnvVar), so
// this deterministically exercises the "failed to read API key" wrapping without
// blocking on real terminal input.
func TestResolveAPIKey_PromptWithNeitherFlagNorEnv(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("api-key", "", "")
	t.Setenv(APIKeyEnvVar, "")

	got, err := ResolveAPIKey(cmd, true)
	require.Error(t, err)
	assert.Empty(t, got)
	assert.Contains(t, err.Error(), "failed to read API key")
}

// ── wireSecretEncryption: AcquireSharedKeyLock failure ────────────────────────

// TestWireSecretEncryption_RefusedWhileServerHoldsExclusiveLock exercises the
// AcquireSharedKeyLock error branch: a "live server" (simulated exactly as
// internal/encryption's own exclusive_lock_test.go does, by a Service that has
// taken the exclusive key lock) holds the same key directory, so a CLI command's
// wireSecretEncryption must be refused rather than reading/writing secret values
// against a DEK that might be mid-rotation.
func TestWireSecretEncryption_RefusedWhileServerHoldsExclusiveLock(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	const passphrase = "shared-dir-passphrase"
	t.Setenv("KEYORIX_MASTER_PASSWORD", passphrase)

	cfg := encEnabledCfg("local")

	// Simulate a live server that already holds the exclusive key lock on this
	// same key directory (same DEKPath/SaltPath, same passphrase so Initialize
	// can derive the same KEK).
	serverSvc := encryption.NewService(&cfg.Storage.Encryption, dir)
	require.NoError(t, serverSvc.Initialize(passphrase))
	require.NoError(t, serverSvc.AcquireExclusiveKeyLock())
	defer serverSvc.Shutdown()

	svc := core.NewKeyorixCore(nil)
	err := wireSecretEncryption(svc, cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exclusively")
	assert.False(t, svc.SecretValueEncryptionActive())
}
