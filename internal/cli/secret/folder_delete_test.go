// folder_delete_test.go — CLI tests for the confirmation gate on
// `keyorix secret folder delete` (G27): the command must not delete anything
// unless the operator either passes --force or answers "yes" at the
// interactive prompt.
package secret

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// captureStdoutFolder redirects os.Stdout to a pipe for the duration of fn and
// returns everything written to it.
func captureStdoutFolder(t *testing.T, fn func()) string {
	t.Helper()
	origStdout := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w

	fn()

	require.NoError(t, w.Close())
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	os.Stdout = origStdout
	return buf.String()
}

// withFolderStdin redirects os.Stdin to a pipe pre-loaded with input for the
// duration of fn.
func withFolderStdin(t *testing.T, input string, fn func()) {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	_, err = w.WriteString(input)
	require.NoError(t, err)
	require.NoError(t, w.Close())

	origStdin := os.Stdin
	os.Stdin = r
	defer func() {
		os.Stdin = origStdin
		_ = r.Close()
	}()

	fn()
}

// ── confirmFolderDeletion ────────────────────────────────────────────────────

func TestConfirmFolderDeletion(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  bool
	}{
		{"explicit yes", "yes\n", true},
		{"short y", "y\n", true},
		{"explicit no", "no\n", false},
		{"short n", "n\n", false},
		// A destructive prompt must fail CLOSED: a blank line (accidental Enter)
		// or unrecognized input must never be treated as confirmation.
		{"blank line does not confirm", "\n", false},
		{"garbage does not confirm", "sure whatever\n", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var got bool
			withFolderStdin(t, c.input, func() {
				got = confirmFolderDeletion("Delete folder 1? This cannot be undone.")
			})
			assert.Equal(t, c.want, got)
		})
	}
}

func TestFolderDeleteCmd_HasForceBypassFlag(t *testing.T) {
	f := folderDeleteCmd.Flags().Lookup("force")
	require.NotNil(t, f, "folder delete must expose --force to bypass the confirmation prompt for scripted use")
	assert.Equal(t, "false", f.DefValue, "confirmation must be required by default")
}

// ── runFolderDelete: no mutation without confirmation ───────────────────────

func folderDeleteStub(t *testing.T, handler http.HandlerFunc) func() {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")
	return srv.Close
}

func TestRunFolderDelete_NoForce_Declined_NoAPICall(t *testing.T) {
	called := false
	done := folderDeleteStub(t, func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	defer done()

	origID := folderDeleteID
	origForce := folderDeleteForce
	t.Cleanup(func() {
		folderDeleteID = origID
		folderDeleteForce = origForce
	})
	folderDeleteID = 123
	folderDeleteForce = false

	var out string
	withFolderStdin(t, "no\n", func() {
		out = captureStdoutFolder(t, func() {
			err := runFolderDelete(folderDeleteCmd, nil)
			require.NoError(t, err)
		})
	})

	assert.False(t, called, "API must not be called when the operator declines the confirmation prompt")
	assert.Contains(t, out, "Deletion cancelled")
}

func TestRunFolderDelete_NoForce_Confirmed_CallsAPI(t *testing.T) {
	called := false
	done := folderDeleteStub(t, func(w http.ResponseWriter, r *http.Request) {
		called = true
		assert.Equal(t, http.MethodDelete, r.Method)
		assert.Equal(t, "/api/v1/folders/123", r.URL.Path)
		w.WriteHeader(http.StatusOK)
	})
	defer done()

	origID := folderDeleteID
	origForce := folderDeleteForce
	t.Cleanup(func() {
		folderDeleteID = origID
		folderDeleteForce = origForce
	})
	folderDeleteID = 123
	folderDeleteForce = false

	withFolderStdin(t, "yes\n", func() {
		err := runFolderDelete(folderDeleteCmd, nil)
		require.NoError(t, err)
	})

	assert.True(t, called, "API must be called once the operator confirms with yes")
}

func TestRunFolderDelete_Force_SkipsPrompt_CallsAPI(t *testing.T) {
	called := false
	done := folderDeleteStub(t, func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	defer done()

	origID := folderDeleteID
	origForce := folderDeleteForce
	t.Cleanup(func() {
		folderDeleteID = origID
		folderDeleteForce = origForce
	})
	folderDeleteID = 123
	folderDeleteForce = true

	// No stdin needed at all — --force must bypass the prompt entirely.
	err := runFolderDelete(folderDeleteCmd, nil)
	require.NoError(t, err)
	assert.True(t, called, "API must be called when --force is set, without requiring any stdin input")
}
