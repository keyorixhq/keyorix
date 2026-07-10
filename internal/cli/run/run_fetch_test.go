package run

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

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
		case "/api/v1/environments":
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
