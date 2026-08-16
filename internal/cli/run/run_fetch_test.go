package run

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestToEnvKey(t *testing.T) {
	cases := map[string]string{
		"db-password": "DB_PASSWORD",
		"api.key!":    "API_KEY_",
		"already_ok":  "ALREADY_OK",
		"MixedCase":   "MIXEDCASE",
		"1two":        "1TWO",
		"":            "",
		"a b/c":       "A_B_C",
	}
	for in, want := range cases {
		assert.Equal(t, want, toEnvKey(in), "toEnvKey(%q)", in)
	}
}

// TestFetchSecretsRemote drives the remote secret-injection path against the real
// sendSuccess envelope: resolve project → env → list secrets → fetch each value,
// keyed by toEnvKey(name).
func TestFetchSecretsRemote(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/projects":
			_, _ = w.Write([]byte(`{"success":true,"data":{"projects":[{"id":1,"name":"web"}]}}`))
		case "/api/v1/projects/1/environments":
			_, _ = w.Write([]byte(`{"success":true,"data":{"environments":[{"id":2,"name":"dev"}]}}`))
		case "/api/v1/secrets":
			_, _ = w.Write([]byte(`{"success":true,"data":{"secrets":[{"id":9,"name":"db-password"}]}}`))
		case "/api/v1/secrets/9":
			_, _ = w.Write([]byte(`{"success":true,"data":{"value":"s3cr3t"}}`))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	got, err := fetchSecretsRemote(context.Background(), srv.URL, "tok", "web", "dev")
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"DB_PASSWORD": "s3cr3t"}, got)
}

func TestFetchSecretsRemote_ProjectNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":{"projects":[]}}`))
	}))
	defer srv.Close()

	_, err := fetchSecretsRemote(context.Background(), srv.URL, "tok", "ghost", "dev")
	require.Error(t, err)
	assert.Contains(t, err.Error(), `project "ghost" not found on server`)
}

// TestFetchSecretsRemote_HungServerTimesOut is the #G71 detection-idea regression
// test: point fetchSecretsRemote at a server that accepts the TCP connection but
// never writes a response, and assert the call fails with a bounded timeout error
// rather than hanging indefinitely — matching common.RemoteClient's own
// defaultRemoteClientTimeout (30s), since fetchSecretsRemote now goes through
// common.NewRemoteClientWithCredentials instead of a homegrown *http.Client.
func TestFetchSecretsRemote_HungServerTimesOut(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close() //nolint:errcheck

	// Accept connections but never read/write/close them — simulates a hung or
	// malicious KEYORIX_SERVER that completes the TCP handshake and then stalls.
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			_ = c // deliberately leaked for the test's duration; never responded to
		}
	}()
	endpoint := "http://" + ln.Addr().String()

	type result struct {
		err error
	}
	done := make(chan result, 1)
	start := time.Now()
	go func() {
		_, ferr := fetchSecretsRemote(context.Background(), endpoint, "tok", "web", "dev")
		done <- result{err: ferr}
	}()

	// Generous outer bound well above the 30s client timeout so this isn't flaky,
	// but still bounded so a regression to an unbounded hang fails the test instead
	// of hanging the suite forever.
	const outerBound = 55 * time.Second
	select {
	case r := <-done:
		elapsed := time.Since(start)
		require.Error(t, r.err, "a hung server must surface a timeout error, not succeed or hang")
		assert.Less(t, elapsed, outerBound, "fetchSecretsRemote must return close to the client's own request timeout, not hang indefinitely")
	case <-time.After(outerBound):
		t.Fatal("fetchSecretsRemote hung indefinitely against an unresponsive server (#G71): the CLI HTTP client is missing its request timeout")
	}
}

func TestFetchSecretsEmbedded(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "keyorix.yaml")
	require.NoError(t, config.Save(cfgPath, &config.Config{
		Locale:  config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
		Storage: config.StorageConfig{Type: "local", Database: config.DatabaseConfig{Path: filepath.Join(dir, "s.db")}},
	}))
	t.Setenv("KEYORIX_CONFIG_PATH", cfgPath)
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	ctx := context.Background()
	svc, err := common.InitializeCoreService()
	require.NoError(t, err)
	project, err := svc.CreateProjectWithEnvs(ctx, "web", "", []string{"dev"})
	require.NoError(t, err)
	envs, err := svc.ListEnvironmentsByProject(ctx, project.ID)
	require.NoError(t, err)
	require.NotEmpty(t, envs)
	_, err = svc.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "db-password", Value: []byte("s3cr3t"), ProjectID: project.ID,
		EnvironmentID: envs[0].ID, Type: "password", CreatedBy: "test",
	})
	require.NoError(t, err)

	got, err := fetchSecretsEmbedded(ctx, "web", "dev")
	require.NoError(t, err)
	assert.Equal(t, "s3cr3t", got["DB_PASSWORD"])

	_, err = fetchSecretsEmbedded(ctx, "ghost", "dev")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}
