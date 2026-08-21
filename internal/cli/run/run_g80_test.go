// run_g80_test.go — additional coverage for branches not exercised by the
// existing run_test.go / run_extra_test.go / run_fetch_test.go / run_s2_test.go /
// run_s25_test.go / run_dangerous_env_test.go suites:
//   - fetchSecretsEmbedded's common.InitializeCoreService error branch
//   - fetchSecretsEmbedded's ListProjects error branch (via a canceled context)
//   - fetchSecretsEmbedded skipping a secret whose value fetch fails (expired secret)
//   - fetchSecretsRemote's invalid-endpoint branch
//   - fetchSecretsRemote's maxRunInjectedSecrets cap
//   - execChild's os.Exit(exitErr.ExitCode()) branch, tested via the repo's
//     established re-exec-the-test-binary pattern (see
//     cmd/validate-translations/main_s23_test.go's TestHelperProcess_S23_Main)
//     since calling os.Exit in-process would kill the whole `go test` run.
package run

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFetchSecretsEmbedded_InitializeServiceError verifies that when the
// underlying storage cannot be created (an unrecognized storage.type in the
// resolved config), fetchSecretsEmbedded surfaces it as a wrapped
// "failed to initialize service" error instead of panicking or returning a
// nil service that the rest of the function would then dereference.
func TestFetchSecretsEmbedded_InitializeServiceError(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "keyorix.yaml")
	require.NoError(t, config.Save(cfgPath, &config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
		// An unrecognized storage type makes the storage factory fail fast,
		// with no network I/O or migration involved (mirrors
		// internal/storage's own TestCreateStorage_RejectsUnknownStorageType).
		Storage: config.StorageConfig{Type: "postgres_typo"},
	}))
	t.Setenv("KEYORIX_CONFIG_PATH", cfgPath)
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	got, err := fetchSecretsEmbedded(context.Background(), "web", "dev")
	require.Error(t, err)
	assert.Nil(t, got)
	assert.Contains(t, err.Error(), "failed to initialize service")
}

// TestFetchSecretsEmbedded_ListProjectsError_ContextCanceled verifies that a
// canceled context propagates through the core service's storage layer and is
// surfaced as a wrapped "failed to list projects" error rather than the
// function hanging or panicking on a nil projects slice.
func TestFetchSecretsEmbedded_ListProjectsError_ContextCanceled(t *testing.T) {
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

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // canceled before fetchSecretsEmbedded's first ctx-consuming call

	got, err := fetchSecretsEmbedded(ctx, "web", "dev")
	require.Error(t, err)
	assert.Nil(t, got)
	assert.Contains(t, err.Error(), "failed to list projects")
}

// TestFetchSecretsEmbedded_SkipsExpiredSecret verifies the embedded-mode
// counterpart of TestFetchSecretsRemote_SkipsFailedSecretValue: a secret whose
// GetSecretValue call fails (here, because it is already expired) is skipped
// with a warning, and the fetch still succeeds with the other, valid secret's
// value present.
func TestFetchSecretsEmbedded_SkipsExpiredSecret(t *testing.T) {
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

	// A secret that is already expired: GetSecretValue's enforceSecretReadGuards
	// rejects it, which fetchSecretsEmbedded must treat as a skip-with-warning,
	// not a fatal error for the whole run.
	pastExpiration := time.Now().Add(-1 * time.Hour)
	_, err = svc.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "expired-secret", Value: []byte("should-not-be-injected"), ProjectID: project.ID,
		EnvironmentID: envs[0].ID, Type: "password", CreatedBy: "test", Expiration: &pastExpiration,
	})
	require.NoError(t, err)
	_, err = svc.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "live-secret", Value: []byte("should-be-injected"), ProjectID: project.ID,
		EnvironmentID: envs[0].ID, Type: "password", CreatedBy: "test",
	})
	require.NoError(t, err)

	got, err := fetchSecretsEmbedded(ctx, "web", "dev")
	require.NoError(t, err, "an expired secret must be skipped, not fail the whole fetch")
	assert.Equal(t, "should-be-injected", got["LIVE_SECRET"])
	assert.NotContains(t, got, "EXPIRED_SECRET", "an expired secret's value must never be injected into the child process")
}

// TestFetchSecretsRemote_InvalidEndpoint verifies that an endpoint which fails
// common.ValidateRemoteEndpointURL (e.g. no scheme) is rejected up front with a
// clear "invalid remote endpoint" error, before any HTTP request is attempted.
func TestFetchSecretsRemote_InvalidEndpoint(t *testing.T) {
	got, err := fetchSecretsRemote(context.Background(), "not-a-valid-endpoint", "tok", "web", "dev")
	require.Error(t, err)
	assert.Nil(t, got)
	assert.Contains(t, err.Error(), "invalid remote endpoint")
}

// TestFetchSecretsRemote_ExceedsMaxInjectedSecrets verifies the #G44 cap:
// fetchSecretsRemote refuses to continue, rather than silently truncating or
// exhausting memory/ARG_MAX, once the number of secrets seen crosses
// maxRunInjectedSecrets.
func TestFetchSecretsRemote_ExceedsMaxInjectedSecrets(t *testing.T) {
	const tooMany = 2001 // maxRunInjectedSecrets is 2000
	var secretsJSON strings.Builder
	secretsJSON.WriteString(`{"data":{"secrets":[`)
	for i := 0; i < tooMany; i++ {
		if i > 0 {
			secretsJSON.WriteByte(',')
		}
		fmt.Fprintf(&secretsJSON, `{"id":%d,"name":"s%d"}`, i+1, i+1)
	}
	secretsJSON.WriteString(`]}}`)
	body := secretsJSON.String()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/projects":
			_, _ = w.Write([]byte(`{"data":{"projects":[{"id":1,"name":"web"}]}}`))
		case "/api/v1/projects/1/environments":
			_, _ = w.Write([]byte(`{"data":{"environments":[{"id":2,"name":"dev"}]}}`))
		case "/api/v1/secrets":
			_, _ = w.Write([]byte(body))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	got, err := fetchSecretsRemote(context.Background(), srv.URL, "tok", "web", "dev")
	require.Error(t, err, "a project/environment with more than maxRunInjectedSecrets must abort the run")
	assert.Nil(t, got)
	assert.Contains(t, err.Error(), "more than 2000 secrets")
	assert.Contains(t, err.Error(), "web")
	assert.Contains(t, err.Error(), "dev")
}

// ---------------------------------------------------------------------------
// execChild — os.Exit(exitErr.ExitCode()) branch, exercised via a re-exec'd
// subprocess (calling os.Exit in-process would kill the whole `go test` run).
// Mirrors cmd/validate-translations/main_s23_test.go's TestHelperProcess
// pattern, scoped to this package with its own env var name.
// ---------------------------------------------------------------------------

// TestHelperProcess_G80_ExecChild is not a real test: it is invoked only by
// TestExecChild_NonZeroExitPropagatesAsProcessExitCode as a subprocess entry
// point. When run directly by `go test` (without GO_WANT_HELPER_PROCESS_RUN_G80
// set) it is a no-op.
func TestHelperProcess_G80_ExecChild(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS_RUN_G80") != "1" {
		return
	}
	// The child command itself exits 7; execChild must translate that into an
	// *exec.ExitError, hit the errors.As branch, and os.Exit(7) — never
	// reaching this test's own return/pass/fail machinery.
	err := execChild([]string{"sh", "-c", "exit 7"}, nil, false)
	// Only reachable if execChild did NOT os.Exit, which is itself a bug this
	// subprocess is designed to catch.
	fmt.Fprintf(os.Stderr, "execChild returned instead of os.Exit-ing: %v\n", err)
	os.Exit(9)
}

// TestExecChild_NonZeroExitPropagatesAsProcessExitCode verifies that when the
// launched child command exits non-zero, execChild's *exec.ExitError branch
// terminates the CURRENT process with that same exit code (os.Exit), rather
// than returning a Go error the caller could otherwise recover from.
func TestExecChild_NonZeroExitPropagatesAsProcessExitCode(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcess_G80_ExecChild") // #nosec G204 -- re-execs the trusted test binary itself for os.Exit isolation
	cmd.Env = append(os.Environ(), "GO_WANT_HELPER_PROCESS_RUN_G80=1")

	out, err := cmd.CombinedOutput()
	exitErr, ok := err.(*exec.ExitError)
	require.True(t, ok, "expected the subprocess to terminate via os.Exit with a non-zero code, got err=%v output=%s", err, out)
	assert.Equal(t, 7, exitErr.ExitCode(), "execChild must os.Exit with the child command's own exit code")
}
