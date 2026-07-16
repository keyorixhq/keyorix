// secret_s17_test.go — coverage sprint 17 for internal/cli/secret.
// Targets:
//   - interactiveCreate (61.4%): the "name is empty" early-exit path, and the
//     term.ReadPassword failure path (both reachable without a real terminal)
//   - promptRotateValue (62.5%): the ReadPassword failure path via a non-tty fd
//   - buildCreateRequest: the symlink rejection path (line 152-154)
//   - runCreateRemote: the rc.Post error path (line 98-100)
//   - runCreate: the embedded-mode return (line 76) via a non-interactive request
//     with no remote client configured
package secret

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// saveCreateFlags saves and restores all package-level create flags.
func saveCreateFlags(t *testing.T) {
	t.Helper()
	origName := createName
	origType := createType
	origProject := createProjectID
	origEnv := createEnvironmentID
	origMax := createMaxReads
	origExp := createExpiration
	origVal := createValue
	origFile := createFromFile
	origInteractive := createInteractive
	origDesc := createDescription
	t.Cleanup(func() {
		createName = origName
		createType = origType
		createProjectID = origProject
		createEnvironmentID = origEnv
		createMaxReads = origMax
		createExpiration = origExp
		createValue = origVal
		createFromFile = origFile
		createInteractive = origInteractive
		createDescription = origDesc
		createCmd.Flags().Lookup("value").Changed = false
	})
}

// ─────────────────────── interactiveCreate ───────────────────────────────────

// TestInteractiveCreate_EmptyNameReturnsError covers the "name == ''" early
// exit in interactiveCreate (lines 219-221 of create.go). We redirect os.Stdin
// to a pipe that immediately delivers a bare newline, so ask("Secret name", "")
// returns "" and the function returns an error without ever reaching
// term.ReadPassword.
func TestInteractiveCreate_EmptyNameReturnsError(t *testing.T) {
	origStdin := os.Stdin
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = origStdin })

	// A bare newline → ask() returns "" (no default)
	_, _ = w.Write([]byte("\n"))
	_ = w.Close()

	_, gotErr := interactiveCreate()
	require.Error(t, gotErr)
	assert.Contains(t, gotErr.Error(), "secret name is required")
}

// TestInteractiveCreate_ReadPasswordFailureReturnsError covers the
// term.ReadPassword error branch (lines 228-231 of create.go). We provide a
// valid name so the function proceeds past the name check, then provide
// defaults for type/projectID/environmentID. Because fd 0 is not a terminal in
// test environments, term.ReadPassword returns an error.
func TestInteractiveCreate_ReadPasswordFailureReturnsError(t *testing.T) {
	origStdin := os.Stdin
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = origStdin })

	// Provide: name, type (default), projectID (default), environmentID (default).
	// Each ask() call reads one line. After that, term.ReadPassword(fd 0) fires
	// on the real fd 0 which is not a terminal in test environments → error.
	input := strings.Join([]string{
		"my-test-secret", // name
		"",               // type → default "generic"
		"",               // projectID → default "1"
		"",               // environmentID → default "1"
	}, "\n") + "\n"
	_, _ = w.Write([]byte(input))
	_ = w.Close()

	_, gotErr := interactiveCreate()
	// In a non-terminal environment term.ReadPassword fails; interactiveCreate
	// must return that error rather than proceeding with an empty/undefined value.
	require.Error(t, gotErr)
}

// ─────────────────────── promptRotateValue ───────────────────────────────────

// TestPromptRotateValue_NonTerminalFails covers the term.ReadPassword error
// path in promptRotateValue (lines 36-37 of rotate.go). The test runner's
// stdin is not a PTY, so term.ReadPassword returns an error which is wrapped
// and returned.
func TestPromptRotateValue_NonTerminalFails(t *testing.T) {
	_, err := promptRotateValue()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read secret value")
}

// ─────────────────────── buildCreateRequest ──────────────────────────────────

// TestBuildCreateRequest_SymlinkRejected covers the symlink-rejection guard
// (lines 148-150 of create.go). We create a real file and a symlink pointing
// to it, then set createFromFile to the symlink path.
func TestBuildCreateRequest_SymlinkRejected(t *testing.T) {
	saveCreateFlags(t)

	dir := t.TempDir()
	target := filepath.Join(dir, "real.txt")
	require.NoError(t, os.WriteFile(target, []byte("secret"), 0600))
	link := filepath.Join(dir, "link.txt")
	require.NoError(t, os.Symlink(target, link))

	createName = "my-secret"
	// Use a relative path from dir — buildCreateRequest will Lstat it.
	// We need to chdir so the relative path resolves correctly.
	origDir, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	t.Cleanup(func() { _ = os.Chdir(origDir) })

	createFromFile = "link.txt" // relative; absolute paths are also rejected

	_, gotErr := buildCreateRequest()
	require.Error(t, gotErr)
	assert.Contains(t, gotErr.Error(), "symlinks are not allowed")
}

// ─────────────────────── runCreateRemote ─────────────────────────────────────

// TestRunCreateRemote_PostError covers the rc.Post failure path (lines 98-100
// of create.go). We spin up a server that returns a 500, configure
// KEYORIX_SERVER/TOKEN so NewRemoteClient returns a client, then call
// runCreateRemote directly.
func TestRunCreateRemote_PostError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	rc, ok := common.NewRemoteClient()
	require.True(t, ok, "NewRemoteClient must succeed with KEYORIX_SERVER set")

	req := &core.CreateSecretRequest{
		Name:          "err-test",
		Value:         []byte("v"),
		Type:          "generic",
		ProjectID:     1,
		EnvironmentID: 1,
		CreatedBy:     "cli-user",
	}
	err := runCreateRemote(context.Background(), rc, req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create secret")
}

// ─────────────────────── runCreate embedded path ─────────────────────────────

// TestRunCreate_EmbeddedModeErrors covers the runCreateEmbedded call path
// (line 76 of create.go). When no KEYORIX_SERVER/TOKEN are set, NewRemoteClient
// returns (nil, false) and runCreate falls through to runCreateEmbedded, which
// fails because there is no valid local config (no keyorix.yaml in the test
// environment). We verify runCreate returns an error rather than panicking.
func TestRunCreate_EmbeddedModeErrors(t *testing.T) {
	saveCreateFlags(t)

	// Ensure no remote client is configured.
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir()) // isolate CLI config

	createName = "embedded-test"
	createValue = "somevalue"
	createInteractive = false

	// Point config resolution at a temp dir with no keyorix.yaml so
	// InitializeCoreService fails with a config-not-found error.
	t.Setenv("KEYORIX_CONFIG_PATH", filepath.Join(t.TempDir(), "no-config.yaml"))

	err := runCreate(createCmd, nil)
	require.Error(t, err)
}
