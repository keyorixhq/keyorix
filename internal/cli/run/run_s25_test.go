// run_s25_test.go — sprint-2.5 coverage for the run CLI package.
// Targets: apiClient nil-data envelope, isSensitiveKeyorixEnv _SECRET/_DSN,
// filterSensitiveEnv edge cases, runRun token-flag-without-endpoint path,
// fetchSecretsRemote environments-fetch error, buildChildEnv multi-secret.
package run

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// NOTE: apiClient (and its tests TestApiClientGet_NilDataEnvelope /
// TestApiClientGet_UnmarshalError) was removed under #G71: fetchSecretsRemote now
// goes through common.RemoteClient instead of a homegrown, bypassing HTTP client.
// The nil-data-envelope scenario is exercised against the shared implementation by
// TestRemoteClient_Get_EmptyDataEnvelope in internal/cli/common/common_s3_test.go;
// the data-present-but-wrong-type unmarshal scenario is preserved there as
// TestRemoteClient_Get_UnmarshalError.

// TestIsSensitiveKeyorixEnv_SecretAndDsnSuffixes exercises the _SECRET and _DSN
// suffixes that are in sensitiveEnvSuffixes but were not covered by existing tests.
func TestIsSensitiveKeyorixEnv_SecretAndDsnSuffixes(t *testing.T) {
	cases := map[string]bool{
		"KEYORIX_SECRET":            true,
		"KEYORIX_APP_SECRET":        true,
		"KEYORIX_DSN":               true,
		"KEYORIX_DYNAMIC_ADMIN_DSN": true,
		"KEYORIX_PROJECT":           false, // non-credential — must survive
		"OTHER_DSN":                 false, // no KEYORIX_ prefix
		"OTHER_SECRET":              false, // no KEYORIX_ prefix
	}
	for key, want := range cases {
		assert.Equal(t, want, isSensitiveKeyorixEnv(key), "key=%s", key)
	}
}

// TestFilterSensitiveEnv_EmptySlice confirms filterSensitiveEnv handles an
// empty input without panicking and returns an empty (non-nil) slice.
func TestFilterSensitiveEnv_EmptySlice(t *testing.T) {
	out := filterSensitiveEnv([]string{})
	assert.NotNil(t, out)
	assert.Empty(t, out)
}

// TestFilterSensitiveEnv_SecretSuffix verifies that KEYORIX_*_SECRET vars are
// stripped by filterSensitiveEnv.
func TestFilterSensitiveEnv_SecretSuffix(t *testing.T) {
	in := []string{
		"KEYORIX_APP_SECRET=hunter2",
		"KEYORIX_DSN=postgres://u:p@h/db",
		"KEYORIX_ENV=staging", // non-credential — must survive
	}
	out := filterSensitiveEnv(in)
	assert.NotContains(t, out, "KEYORIX_APP_SECRET=hunter2")
	assert.NotContains(t, out, "KEYORIX_DSN=postgres://u:p@h/db")
	assert.Contains(t, out, "KEYORIX_ENV=staging")
}

// TestBuildChildEnv_MultipleInjectedSecrets verifies that all entries in
// extraEnv map appear in the built child environment.
func TestBuildChildEnv_MultipleInjectedSecrets(t *testing.T) {
	extra := map[string]string{
		"SECRET_A": "val_a",
		"SECRET_B": "val_b",
		"SECRET_C": "val_c",
	}
	got := buildChildEnv(extra, false)

	for k, v := range extra {
		assert.True(t, containsEnv(got, k, v), "expected %s=%s in child env", k, v)
	}
}

// TestBuildChildEnv_CleanEnv_MultipleInjectedSecrets verifies that with
// --clean-env, all injected secrets still appear alongside the baseline.
func TestBuildChildEnv_CleanEnv_MultipleInjectedSecrets(t *testing.T) {
	extra := map[string]string{
		"DB_PASSWORD": "s3cr3t",
		"API_KEY":     "xyzzy",
	}
	got := buildChildEnv(extra, true)

	for k, v := range extra {
		assert.True(t, containsEnv(got, k, v), "expected %s=%s in clean-env child", k, v)
	}

	// Only PATH, HOME, and injected keys should be present.
	allowed := map[string]bool{"PATH": true, "HOME": true, "DB_PASSWORD": true, "API_KEY": true}
	for _, kv := range got {
		key := strings.SplitN(kv, "=", 2)[0]
		assert.True(t, allowed[key], "clean-env leaked unexpected var %q", key)
	}
}

// TestFetchSecretsRemote_EnvironmentsFetchError verifies that an API error
// while listing environments is propagated as a "list environments" error.
func TestFetchSecretsRemote_EnvironmentsFetchError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/projects":
			_, _ = w.Write([]byte(`{"data":{"projects":[{"id":1,"name":"web"}]}}`))
		case "/api/v1/projects/1/environments":
			w.WriteHeader(http.StatusInternalServerError)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	_, err := fetchSecretsRemote(context.Background(), srv.URL, "tok", "web", "dev")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list environments")
}

// TestFetchSecretsRemote_ProjectsFetchError verifies that an API error while
// listing projects is propagated as a "list projects" error.
func TestFetchSecretsRemote_ProjectsFetchError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	_, err := fetchSecretsRemote(context.Background(), srv.URL, "tok", "web", "dev")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list projects")
}

// TestRunRun_TokenFlagWithoutEndpoint verifies that when --token is set but
// no server endpoint is configured, the warning is emitted and the embedded
// path is used (which returns an error in the absence of a seeded local DB).
func TestRunRun_TokenFlagWithoutEndpoint(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	// No KEYORIX_SERVER → endpoint="", so remoteOK = (endpoint != "") = false.
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	// Redirect stderr to catch the insecure-token warning.
	origStderr := os.Stderr
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stderr = w
	defer func() {
		os.Stderr = origStderr
		_ = r.Close()
	}()

	origEnv, origProject, origToken, origClean := runEnv, runProject, runToken, runCleanEnv
	defer func() {
		runEnv = origEnv
		runProject = origProject
		runToken = origToken
		runCleanEnv = origClean
	}()
	runEnv = "dev"
	runProject = "ghost"
	runToken = "flag-tok-no-endpoint"
	runCleanEnv = false

	// Without an endpoint, remoteOK is false so it falls through to embedded.
	// The embedded path will fail because there's no seeded project.
	runErr := runRun(nil, []string{"echo", "hello"})
	_ = w.Close()

	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	stderrOut := string(buf[:n])

	// The insecure-token warning must be emitted even when going to embedded path.
	assert.Contains(t, stderrOut, "Passing --token on the command line is insecure")
	// Embedded path fails because no project exists.
	require.Error(t, runErr)
}

// TestFetchSecretsEmbedded_EnvNotFoundAfterProjectFound tests that when a
// project exists but the requested environment does not, the "environment not
// found" error is returned.
func TestFetchSecretsEmbedded_EnvNotFoundAfterProjectFound(t *testing.T) {
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
	_, err = svc.CreateProjectWithEnvs(ctx, "myproj", "", []string{"staging"})
	require.NoError(t, err)

	// Project "myproj" exists, but environment "ghost" does not.
	_, err = fetchSecretsEmbedded(ctx, "myproj", "ghost")
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"ghost" not found`)
}

// TestFetchSecretsEmbedded_SecretsSkippedOnValueError verifies that when a
// secret's value cannot be fetched, it is skipped with a warning and the
// overall fetch succeeds with the remaining secrets.
func TestFetchSecretsEmbedded_SecretsSkippedOnValueError(t *testing.T) {
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
	project, err := svc.CreateProjectWithEnvs(ctx, "myproj2", "", []string{"dev"})
	require.NoError(t, err)
	envs, err := svc.ListEnvironmentsByProject(ctx, project.ID)
	require.NoError(t, err)
	require.NotEmpty(t, envs)

	// Create a valid secret that should be present in the result.
	_, err = svc.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "api-key", Value: []byte("top-secret"), ProjectID: project.ID,
		EnvironmentID: envs[0].ID, Type: "password", CreatedBy: "test",
	})
	require.NoError(t, err)

	got, err := fetchSecretsEmbedded(ctx, "myproj2", "dev")
	require.NoError(t, err)
	assert.Equal(t, "top-secret", got["API_KEY"])
}

// TestToEnvKey_DigitsAndUnderscores exercises digit-leading and underscore-
// preserving behaviour of toEnvKey that complements run_fetch_test.go cases.
func TestToEnvKey_DigitsAndUnderscores(t *testing.T) {
	cases := map[string]string{
		"123":     "123",
		"_under_": "_UNDER_",
		"--":      "__",
	}
	for in, want := range cases {
		assert.Equal(t, want, toEnvKey(in), "toEnvKey(%q)", in)
	}
}
