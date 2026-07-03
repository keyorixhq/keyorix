package legalhold

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLiftRequiresConfirmation guards #350: `legal-hold lift` re-arms the
// purge/retention/JIT-expiry jobs a hold exists to block, so it must not fire
// on the server without either an interactive "yes" or --yes, matching the
// `dynamic-secret revoke-all --yes` convention.
func TestLiftRequiresConfirmation(t *testing.T) {
	var deleteCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete && r.URL.Path == "/api/v1/legal-hold" {
			deleteCalls++
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	liftReason = "test lift reason"
	defer func() { liftReason = "" }()

	t.Run("declining the prompt aborts without calling the server", func(t *testing.T) {
		deleteCalls = 0
		liftYes = false
		cmd := &cobra.Command{}
		cmd.SetIn(strings.NewReader("no\n"))
		require.NoError(t, liftCmd.RunE(cmd, nil))
		assert.Equal(t, 0, deleteCalls, "declining the prompt must not lift the hold")
	})

	t.Run("typing yes at the prompt lifts the hold", func(t *testing.T) {
		deleteCalls = 0
		liftYes = false
		cmd := &cobra.Command{}
		cmd.SetIn(strings.NewReader("yes\n"))
		require.NoError(t, liftCmd.RunE(cmd, nil))
		assert.Equal(t, 1, deleteCalls, "confirming at the prompt must lift the hold")
	})

	t.Run("--yes skips the prompt and lifts the hold", func(t *testing.T) {
		deleteCalls = 0
		liftYes = true
		defer func() { liftYes = false }()
		cmd := &cobra.Command{}
		cmd.SetIn(strings.NewReader(""))
		require.NoError(t, liftCmd.RunE(cmd, nil))
		assert.Equal(t, 1, deleteCalls, "--yes must skip the prompt and lift the hold")
	})

	t.Run("missing --reason is refused before the prompt", func(t *testing.T) {
		deleteCalls = 0
		liftYes = true
		liftReason = ""
		defer func() { liftYes = false; liftReason = "test lift reason" }()
		cmd := &cobra.Command{}
		require.Error(t, liftCmd.RunE(cmd, nil))
		assert.Equal(t, 0, deleteCalls, "a missing reason must not lift the hold")
	})
}
