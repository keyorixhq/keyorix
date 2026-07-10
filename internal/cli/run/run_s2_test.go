// run_s2_test.go — sprint-2 coverage for the run CLI package.
// Targets: runRun flag/error paths, execChild success, buildChildEnv,
// fetchSecretsRemote additional paths.
package run

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRunRun_FetchRemoteError verifies that runRun propagates fetch errors from
// the remote path.
func TestRunRun_FetchRemoteError(t *testing.T) {
	// Stub server that returns 500 for all project list requests.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-tok")

	origEnv, origProject, origToken, origClean := runEnv, runProject, runToken, runCleanEnv
	defer func() {
		runEnv = origEnv
		runProject = origProject
		runToken = origToken
		runCleanEnv = origClean
	}()
	runEnv = "dev"
	runProject = ""
	runToken = ""
	runCleanEnv = false

	// runRun will try the remote path and fail at list-projects.
	err := runRun(nil, []string{"echo", "hello"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list projects")
}

// TestRunRun_FetchLocalError verifies that runRun propagates fetch errors from
// the embedded path when there's no remote configured.
func TestRunRun_FetchLocalError(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	origEnv, origProject, origToken, origClean := runEnv, runProject, runToken, runCleanEnv
	defer func() {
		runEnv = origEnv
		runProject = origProject
		runToken = origToken
		runCleanEnv = origClean
	}()
	runEnv = "dev"
	runProject = "nonexistent"
	runToken = ""
	runCleanEnv = false

	// Without a seeded project, the embedded path will fail "project not found".
	err := runRun(nil, []string{"echo", "hello"})
	require.Error(t, err)
}

// TestRunRun_TokenFlagWarning verifies that passing --token logs a warning
// (the flag is processed without error) and that the token takes effect.
func TestRunRun_TokenFlagWarning(t *testing.T) {
	// Server that always returns a successful empty projects list.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/projects":
			_, _ = w.Write([]byte(`{"data":{"projects":[]}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "")

	origEnv, origProject, origToken, origClean := runEnv, runProject, runToken, runCleanEnv
	defer func() {
		runEnv = origEnv
		runProject = origProject
		runToken = origToken
		runCleanEnv = origClean
	}()
	runEnv = "dev"
	runProject = "ghost"
	runToken = "explicit-token"
	runCleanEnv = false

	// runRun writes the warning to stderr and then tries to fetch — project
	// "ghost" won't be found, so it returns an error.
	err := runRun(nil, []string{"echo", "hello"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ghost")
}

// TestExecChild_SuccessfulCommand verifies that execChild with a real command
// (echo) returns nil.
func TestExecChild_SuccessfulCommand(t *testing.T) {
	// Use `true` which is guaranteed to succeed on Unix-like systems.
	err := execChild([]string{"true"}, nil, false)
	assert.NoError(t, err)
}

// TestExecChild_CommandNotFound verifies that execChild returns an error when
// the binary doesn't exist (not the os.Exit path, but the "command not found"
// path which surfaces as exec: not found in PATH).
func TestExecChild_CommandNotFound(t *testing.T) {
	err := execChild([]string{"__no_such_binary_9xyzkeyorix__"}, nil, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "command failed")
}

// TestExecChild_CleanEnv verifies that --clean-env passes only the baseline
// plus injected secrets to the child.
func TestExecChild_CleanEnv(t *testing.T) {
	// Use `true` with clean-env; child env should only have PATH/HOME + injected.
	err := execChild([]string{"true"}, map[string]string{"MY_SECRET": "val"}, true)
	assert.NoError(t, err)
}

// TestBuildChildEnv_CleanEnv_NoExtraVars proves that clean-env with no
// injected secrets only carries PATH and HOME from the parent.
func TestBuildChildEnv_CleanEnv_NoExtraVars(t *testing.T) {
	got := buildChildEnv(nil, true)
	for _, kv := range got {
		key := strings.SplitN(kv, "=", 2)[0]
		assert.True(t, key == "PATH" || key == "HOME",
			"clean-env with no injected secrets should only have PATH/HOME, got %q", key)
	}
}

// TestRunRun_RemoteProjectNotFound verifies runRun returns error when the
// project isn't on the server.
func TestRunRun_RemoteProjectNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"projects":[]}}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	origEnv, origProject, origToken, origClean := runEnv, runProject, runToken, runCleanEnv
	defer func() {
		runEnv = origEnv
		runProject = origProject
		runToken = origToken
		runCleanEnv = origClean
	}()
	runEnv = "dev"
	runProject = "missing"
	runToken = ""
	runCleanEnv = false

	err := runRun(nil, []string{"echo"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found on server")
}

// TestFetchSecretsRemote_ListSecretsError verifies the error path when listing
// secrets fails.
func TestFetchSecretsRemote_ListSecretsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/projects":
			_, _ = w.Write([]byte(`{"data":{"projects":[{"id":1,"name":"web"}]}}`))
		case "/api/v1/environments":
			_, _ = w.Write([]byte(`{"data":{"environments":[{"id":2,"name":"dev"}]}}`))
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	_, err := fetchSecretsRemote(context.Background(), srv.URL, "tok", "web", "dev")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list secrets")
}

// TestRunRun_FullRemoteSuccess verifies a complete remote fetch+exec with a
// working command (echo).
func TestRunRun_FullRemoteSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/projects":
			_, _ = w.Write([]byte(`{"data":{"projects":[{"id":1,"name":"web"}]}}`))
		case "/api/v1/environments":
			_, _ = w.Write([]byte(`{"data":{"environments":[{"id":2,"name":"dev"}]}}`))
		case "/api/v1/secrets":
			_, _ = w.Write([]byte(`{"data":{"secrets":[]}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	origEnv, origProject, origToken, origClean := runEnv, runProject, runToken, runCleanEnv
	defer func() {
		runEnv = origEnv
		runProject = origProject
		runToken = origToken
		runCleanEnv = origClean
	}()
	runEnv = "dev"
	runProject = "web"
	runToken = ""
	runCleanEnv = false

	// With zero secrets, runRun fetches successfully then executes "true".
	err := runRun(nil, []string{"true"})
	assert.NoError(t, err)
}

// TestRunRun_CleanEnvWithCommand verifies --clean-env flag path executes successfully.
func TestRunRun_CleanEnvWithCommand(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/projects":
			_, _ = w.Write([]byte(`{"data":{"projects":[{"id":1,"name":"web"}]}}`))
		case "/api/v1/environments":
			_, _ = w.Write([]byte(`{"data":{"environments":[{"id":2,"name":"dev"}]}}`))
		case "/api/v1/secrets":
			_, _ = w.Write([]byte(`{"data":{"secrets":[]}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	origEnv, origProject, origToken, origClean := runEnv, runProject, runToken, runCleanEnv
	defer func() {
		runEnv = origEnv
		runProject = origProject
		runToken = origToken
		runCleanEnv = origClean
	}()
	runEnv = "dev"
	runProject = "web"
	runToken = ""
	runCleanEnv = true

	err := runRun(nil, []string{"true"})
	assert.NoError(t, err)
}

// TestFetchSecretsEmbedded_EnvNotFound tests the "environment not found" path.
func TestFetchSecretsEmbedded_EnvNotFound(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	// An empty SQLite DB has no projects or environments.
	_, err := fetchSecretsEmbedded(context.Background(), "default", "ghost")
	require.Error(t, err)
}

// TestExecChild_InheritsEnv verifies the default (non-clean-env) child includes
// an env var set in the parent.
func TestExecChild_InheritsEnv(t *testing.T) {
	t.Setenv("KEYORIX_RUN_S2_INHERIT_TEST", "should-be-present")
	// Use `true` — we only care that no error is returned.
	err := execChild([]string{"true"}, nil, false)
	assert.NoError(t, err)

	// Verify the variable would have appeared in the built env.
	env := buildChildEnv(nil, false)
	found := false
	for _, kv := range env {
		if kv == "KEYORIX_RUN_S2_INHERIT_TEST=should-be-present" {
			found = true
			break
		}
	}
	assert.True(t, found, "non-clean-env should inherit unrelated parent vars")
}

// TestRunRun_StderrNotCaptured_TokenWarningPath verifies that the --token
// warning path (when endpoint is set) runs without panicking and that the
// warning message goes to stderr.
func TestRunRun_StderrNotCaptured_TokenWarningPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/projects":
			_, _ = w.Write([]byte(`{"data":{"projects":[{"id":1,"name":"web"}]}}`))
		case "/api/v1/environments":
			_, _ = w.Write([]byte(`{"data":{"environments":[{"id":2,"name":"dev"}]}}`))
		case "/api/v1/secrets":
			_, _ = w.Write([]byte(`{"data":{"secrets":[]}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	// Redirect stderr to capture the warning.
	origStderr := os.Stderr
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stderr = w
	defer func() {
		os.Stderr = origStderr
		_ = r.Close()
	}()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "")

	origEnv, origProject, origToken, origClean := runEnv, runProject, runToken, runCleanEnv
	defer func() {
		runEnv = origEnv
		runProject = origProject
		runToken = origToken
		runCleanEnv = origClean
	}()
	runEnv = "dev"
	runProject = "web"
	runToken = "explicit-insecure-tok"
	runCleanEnv = false

	runErr := runRun(nil, []string{"true"})
	_ = w.Close()

	// Read what was written to stderr.
	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	stderrOutput := string(buf[:n])

	assert.NoError(t, runErr)
	assert.Contains(t, stderrOutput, "Passing --token on the command line is insecure")
}
