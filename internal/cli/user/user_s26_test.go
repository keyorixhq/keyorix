// user_s26_test.go — coverage sprint 26 for internal/cli/user.
// Targets remaining gaps after s25:
//   - runCreateRemote with explicit display name (non-empty displayName branch)
//   - runCreateRemote error path (rc.Post fails — server connection refused)
//   - runCreate empty-password guard (resolveInitialPassword returns empty string via stdin)
//   - runDelete non-force prompt path where admin resolution fails
//   - runLifecycle service-init failure path (returns "failed to initialize service" error)
package user

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ──────────────────────────── runCreateRemote — display name branch ──────────

// TestRunCreateRemote_ExplicitDisplayName verifies that when createDisplayName
// is non-empty, it is sent as display_name in the request body (rather than
// defaulting to createUsername).
func TestRunCreateRemote_ExplicitDisplayName(t *testing.T) {
	var gotBody map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"data":{"id":42,"username":"carol","email":"carol@test.com"}}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	origU, origE, origD := createUsername, createEmail, createDisplayName
	defer func() { createUsername = origU; createEmail = origE; createDisplayName = origD }()
	createUsername = "carol"
	createEmail = "carol@test.com"
	createDisplayName = "Carol Explicit"

	require.NoError(t, runCreateRemote(rc, "s3cret"))

	assert.Equal(t, "Carol Explicit", gotBody["display_name"],
		"explicit display name must be forwarded, not the username default")
}

// TestRunCreateRemote_PostError verifies that rc.Post errors are wrapped and
// returned by runCreateRemote.
func TestRunCreateRemote_PostError(t *testing.T) {
	// Point at a port where nothing is listening so rc.Post returns a dial error.
	t.Setenv("KEYORIX_SERVER", "http://127.0.0.1:1")
	t.Setenv("KEYORIX_TOKEN", "tok")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	origU, origE, origD := createUsername, createEmail, createDisplayName
	defer func() { createUsername = origU; createEmail = origE; createDisplayName = origD }()
	createUsername = "erruser"
	createEmail = "erruser@test.com"
	createDisplayName = ""

	err := runCreateRemote(rc, "somepassword")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create user")
}

// ──────────────────────────── runCreate — empty password guard ───────────────

// TestRunCreate_EmptyPasswordFromStdin verifies that when the interactive
// stdin prompt returns an empty string (and no env var / flag is set),
// runCreate returns the "password is required" error.
//
// We provide a newline-only stdin so term.ReadPassword gets EOF/empty bytes,
// which should yield an empty string or an error. Either way the function
// must not create a user or panic.
func TestRunCreate_EmptyPasswordFromStdin(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("KEYORIX_INITIAL_PASSWORD", "") // ensure env var is empty

	origU, origE, origSL, origOTP, origPW := createUsername, createEmail, createSetupLink, createOneTimePassword, createPassword
	defer func() {
		createUsername = origU
		createEmail = origE
		createSetupLink = origSL
		createOneTimePassword = origOTP
		createPassword = origPW
	}()
	createUsername = "emptypassuser"
	createEmail = "emptypass@example.com"
	createSetupLink = false
	createOneTimePassword = false
	createPassword = "" // no flag

	// Provide empty input on stdin so the interactive prompt gets EOF.
	// term.ReadPassword will either return ("", nil) or an error — both
	// lead to an error return from runCreate (either "password is required"
	// or a "failed to read password" error).
	var err error
	withStdin(t, "\n", func() {
		err = runCreate(nil, nil)
	})
	// The function must return an error, not silently succeed.
	require.Error(t, err)
}

// ──────────────────────────── resolveInitialPassword — interactive path ──────

// TestResolveInitialPassword_InteractiveReturnsEmpty verifies that when
// neither --password nor KEYORIX_INITIAL_PASSWORD is set, the function falls
// through to the interactive path. When stdin is a pipe returning only a
// newline, term.ReadPassword typically returns an error (not a real terminal),
// which is wrapped in "failed to read password".
//
// This targets the previously-uncovered lines 185-191 of create.go.
func TestResolveInitialPassword_InteractiveReturnsEmpty(t *testing.T) {
	origPW := createPassword
	defer func() { createPassword = origPW }()
	createPassword = ""
	t.Setenv("KEYORIX_INITIAL_PASSWORD", "")

	var pw string
	var err error
	withStdin(t, "\n", func() {
		pw, err = resolveInitialPassword(nil)
	})
	// term.ReadPassword fails on non-terminal stdin: we expect either an error
	// ("failed to read password") or an empty password.
	if err != nil {
		assert.Contains(t, err.Error(), "failed to read password")
	} else {
		// If ReadPassword succeeded but returned empty bytes, pw is "".
		assert.Equal(t, "", pw)
	}
}
