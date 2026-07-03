package machine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRevokeMachineRequiresConfirmation guards #351: `machine revoke` is a
// one-way, irreversible credential-kill action (MachineRevoked has no
// outgoing transitions) and must not fire on the server without either a
// correctly typed machine name or --force, matching `secret delete`'s
// typed-name confirmation convention.
func TestRevokeMachineRequiresConfirmation(t *testing.T) {
	var putCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && r.URL.Path == "/api/v1/projects/3/machine-identities/5" {
			putCalls++
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	m := &models.MachineIdentity{Name: "ci-runner"}
	m.ID = 5
	m.ProjectID = 3

	t.Run("wrong name aborts without calling the server", func(t *testing.T) {
		putCalls = 0
		revokeForce = false
		cmd := &cobra.Command{}
		cmd.SetIn(strings.NewReader("not-the-name\n"))
		require.NoError(t, revokeMachine(cmd, context.Background(), 3, m))
		assert.Equal(t, 0, putCalls, "a name mismatch must not revoke the machine identity")
	})

	t.Run("typing the correct name revokes", func(t *testing.T) {
		putCalls = 0
		revokeForce = false
		cmd := &cobra.Command{}
		cmd.SetIn(strings.NewReader("ci-runner\n"))
		require.NoError(t, revokeMachine(cmd, context.Background(), 3, m))
		assert.Equal(t, 1, putCalls, "typing the correct name must revoke the machine identity")
	})

	t.Run("--force skips the prompt and revokes", func(t *testing.T) {
		putCalls = 0
		revokeForce = true
		defer func() { revokeForce = false }()
		cmd := &cobra.Command{}
		cmd.SetIn(strings.NewReader(""))
		require.NoError(t, revokeMachine(cmd, context.Background(), 3, m))
		assert.Equal(t, 1, putCalls, "--force must skip the prompt and revoke")
	})
}

func TestRevokeCmd_HasForceFlag(t *testing.T) {
	revoke, _, err := MachineCmd.Find([]string{"revoke"})
	require.NoError(t, err)
	assert.NotNil(t, revoke.Flags().Lookup("force"), "revoke should have a --force flag")
}
