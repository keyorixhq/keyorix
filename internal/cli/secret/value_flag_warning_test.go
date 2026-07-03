// value_flag_warning_test.go — verifies that 'secret create' and 'secret update'
// warn on stderr when a secret value is passed via --value (ps/proc + shell-history
// exposure), matching the same property already covered for 'secret rotate' in
// rotate_test.go.
package secret

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// captureStderr redirects os.Stderr for the duration of fn and returns everything
// written to it.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stderr
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stderr = w
	defer func() { os.Stderr = orig }()

	fn()

	require.NoError(t, w.Close())
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	return string(out)
}

func TestRunCreate_ValueFlagWarnsOnCommandLine(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"id":1,"name":"x","type":"generic","project_id":1,"environment_id":1}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	origName, origValue, origInteractive := createName, createValue, createInteractive
	t.Cleanup(func() { createName, createValue, createInteractive = origName, origValue, origInteractive })
	createInteractive = false
	require.NoError(t, createCmd.Flags().Set("name", "my-secret"))
	require.NoError(t, createCmd.Flags().Set("value", "s3cr3t-on-argv"))
	t.Cleanup(func() {
		_ = createCmd.Flags().Set("value", "")
		createCmd.Flags().Lookup("value").Changed = false
		createCmd.Flags().Lookup("name").Changed = false
	})

	out := captureStderr(t, func() {
		_ = runCreate(createCmd, nil)
	})
	assert.Contains(t, out, "--value")
	assert.Contains(t, out, "ps/proc")
}

func TestRunUpdate_ValueFlagWarnsOnCommandLine(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"id":1,"name":"x","type":"generic","project_id":1,"environment_id":1}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	origID, origValue, origInteractive := updateID, updateValue, updateInteractive
	t.Cleanup(func() { updateID, updateValue, updateInteractive = origID, origValue, origInteractive })
	updateID = 1
	updateInteractive = false
	require.NoError(t, updateCmd.Flags().Set("value", "s3cr3t-on-argv"))
	t.Cleanup(func() {
		_ = updateCmd.Flags().Set("value", "")
		updateCmd.Flags().Lookup("value").Changed = false
	})

	out := captureStderr(t, func() {
		_ = runUpdate(updateCmd, nil)
	})
	assert.Contains(t, out, "--value")
	assert.Contains(t, out, "ps/proc")
}
