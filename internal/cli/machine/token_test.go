// token_test.go — tests for machine token issue/list/revoke commands.
package machine

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── TestMachineTokenIssue_OutputsToken ────────────────────────────────────────

// TestMachineTokenIssue_OutputsToken verifies that issue prints the raw token and
// confirms it won't be shown again.
func TestMachineTokenIssue_OutputsToken(t *testing.T) {
	projectID, _, machineName := setupMachineLocalDB(t)
	_ = projectID

	origName := tokenIssueName
	origProj := tokenProjectName
	origDays := tokenIssueExpiryDays
	origClass := tokenIssueClass
	defer func() {
		tokenIssueName = origName
		tokenProjectName = origProj
		tokenIssueExpiryDays = origDays
		tokenIssueClass = origClass
	}()

	tokenIssueName = "deploy-key"
	tokenProjectName = "testproject"
	tokenIssueExpiryDays = 0
	tokenIssueClass = ""

	out := captureStdout(t, func() {
		err := runTokenIssue(nil, []string{machineName})
		require.NoError(t, err)
	})

	assert.Contains(t, out, "Machine token issued")
	assert.Contains(t, out, "will not be shown again")
	assert.Contains(t, out, "kx_machine_")
	assert.Contains(t, out, "Token:")
	assert.Contains(t, out, "ID:")
	assert.Contains(t, out, "Prefix:")
}

// ── TestMachineTokenIssue_ExpiresInDays ──────────────────────────────────────

// TestMachineTokenIssue_ExpiresInDays confirms that --expires-in-days 30 sets the
// expiry and it appears in the output.
func TestMachineTokenIssue_ExpiresInDays(t *testing.T) {
	_, _, machineName := setupMachineLocalDB(t)

	origName := tokenIssueName
	origProj := tokenProjectName
	origDays := tokenIssueExpiryDays
	origClass := tokenIssueClass
	defer func() {
		tokenIssueName = origName
		tokenProjectName = origProj
		tokenIssueExpiryDays = origDays
		tokenIssueClass = origClass
	}()

	tokenIssueName = "short-lived"
	tokenProjectName = "testproject"
	tokenIssueExpiryDays = 30
	tokenIssueClass = ""

	out := captureStdout(t, func() {
		err := runTokenIssue(nil, []string{machineName})
		require.NoError(t, err)
	})

	// expiry line should appear, not "never"
	assert.Contains(t, out, "Expires:")
	assert.NotContains(t, out, "Expires: never")
}

// ── TestMachineTokenList_ShowsExistingTokens ──────────────────────────────────

// TestMachineTokenList_ShowsExistingTokens issues a token then lists it and checks
// the table header and the token's name appear.
func TestMachineTokenList_ShowsExistingTokens(t *testing.T) {
	_, _, machineName := setupMachineLocalDB(t)

	// issue a token first
	origName := tokenIssueName
	origProj := tokenProjectName
	origDays := tokenIssueExpiryDays
	origClass := tokenIssueClass
	defer func() {
		tokenIssueName = origName
		tokenProjectName = origProj
		tokenIssueExpiryDays = origDays
		tokenIssueClass = origClass
	}()

	tokenIssueName = "list-test-token"
	tokenProjectName = "testproject"
	tokenIssueExpiryDays = 0
	tokenIssueClass = ""

	captureStdout(t, func() {
		err := runTokenIssue(nil, []string{machineName})
		require.NoError(t, err)
	})

	// now list
	out := captureStdout(t, func() {
		err := runTokenList(nil, []string{machineName})
		require.NoError(t, err)
	})

	assert.Contains(t, out, "ID")
	assert.Contains(t, out, "NAME")
	assert.Contains(t, out, "list-test-token")
}

// ── TestMachineTokenRevoke_RequiresForceOrConfirm ─────────────────────────────

// TestMachineTokenRevoke_RequiresForceOrConfirm verifies that without --force and
// when stdin sends "n", the token is NOT revoked (the DELETE is never called).
func TestMachineTokenRevoke_RequiresForceOrConfirm(t *testing.T) {
	var deleteCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			deleteCalls++
		}
		if r.Method == http.MethodGet && r.URL.Path == "/api/v1/projects" {
			_, _ = w.Write([]byte(`{"data":{"projects":[{"id":10,"name":"proj"}]}}`))
			return
		}
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/machine-identities") {
			_, _ = w.Write([]byte(`{"data":{"machine_identities":[{"id":20,"name":"ci-bot","state":"active"}]}}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":null}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	origForce := tokenRevokeForce
	origProj := tokenProjectName
	defer func() {
		tokenRevokeForce = origForce
		tokenProjectName = origProj
	}()

	tokenRevokeForce = false
	tokenProjectName = "proj"

	cmd := &cobra.Command{}
	cmd.SetIn(strings.NewReader("n\n"))

	err := runTokenRevoke(cmd, []string{"ci-bot", "42"})
	require.NoError(t, err)
	assert.Equal(t, 0, deleteCalls, "answering 'n' must not call DELETE")
}

// ── TestMachineTokenRevoke_Force_Succeeds ─────────────────────────────────────

// TestMachineTokenRevoke_Force_Succeeds verifies that --force bypasses the
// confirmation prompt and issues the DELETE.
func TestMachineTokenRevoke_Force_Succeeds(t *testing.T) {
	var deleteCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/projects":
			_, _ = w.Write([]byte(`{"data":{"projects":[{"id":10,"name":"proj"}]}}`))
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/machine-identities"):
			_, _ = w.Write([]byte(`{"data":{"machine_identities":[{"id":20,"name":"ci-bot","state":"active"}]}}`))
		case r.Method == http.MethodDelete:
			deleteCalls++
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":null}`))
		}
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	origForce := tokenRevokeForce
	origProj := tokenProjectName
	defer func() {
		tokenRevokeForce = origForce
		tokenProjectName = origProj
	}()

	tokenRevokeForce = true
	tokenProjectName = "proj"

	cmd := &cobra.Command{}
	cmd.SetIn(strings.NewReader(""))

	out := captureStdout(t, func() {
		err := runTokenRevoke(cmd, []string{"ci-bot", "42"})
		require.NoError(t, err)
	})

	assert.Equal(t, 1, deleteCalls, "--force must call DELETE")
	assert.Contains(t, out, "Machine token revoked")
}

// ── TestTokenCmd_Registered ───────────────────────────────────────────────────

func TestTokenCmd_Registered(t *testing.T) {
	cmd, _, err := MachineCmd.Find([]string{"token"})
	require.NoError(t, err)
	assert.Equal(t, "token", cmd.Name())
}

func TestTokenIssueCmd_Registered(t *testing.T) {
	cmd, _, err := MachineCmd.Find([]string{"token", "issue"})
	require.NoError(t, err)
	assert.Equal(t, "issue", cmd.Name())
	assert.NotNil(t, cmd.Flags().Lookup("name"))
	assert.NotNil(t, cmd.Flags().Lookup("expires-in-days"))
	assert.NotNil(t, cmd.Flags().Lookup("classification"))
	assert.NotNil(t, cmd.Flags().Lookup("project"))
}

func TestTokenListCmd_Registered(t *testing.T) {
	cmd, _, err := MachineCmd.Find([]string{"token", "list"})
	require.NoError(t, err)
	assert.Equal(t, "list", cmd.Name())
	assert.NotNil(t, cmd.Flags().Lookup("project"))
}

func TestTokenRevokeCmd_Registered(t *testing.T) {
	cmd, _, err := MachineCmd.Find([]string{"token", "revoke"})
	require.NoError(t, err)
	assert.Equal(t, "revoke", cmd.Name())
	assert.NotNil(t, cmd.Flags().Lookup("force"))
	assert.NotNil(t, cmd.Flags().Lookup("project"))
}

// ── TestMachineTokenIssue_NameRequired ───────────────────────────────────────

func TestMachineTokenIssue_NameRequired(t *testing.T) {
	origName := tokenIssueName
	defer func() { tokenIssueName = origName }()
	tokenIssueName = ""

	err := runTokenIssue(nil, []string{"ci-bot"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--name is required")
}

// ── TestMachineTokenRevoke_InvalidTokenID ────────────────────────────────────

func TestMachineTokenRevoke_InvalidTokenID(t *testing.T) {
	err := runTokenRevoke(&cobra.Command{}, []string{"ci-bot", "not-a-number"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid token ID")
}

// ── TestPrintTokenTable_Empty ─────────────────────────────────────────────────

func TestPrintTokenTable_Empty(t *testing.T) {
	out := captureStdout(t, func() {
		printTokenTable(nil)
	})
	assert.Contains(t, out, "No tokens found")
}

// ── TestMachineTokenList_RemotePath ──────────────────────────────────────────

func TestMachineTokenList_RemotePath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/projects":
			_, _ = w.Write([]byte(`{"data":{"projects":[{"id":5,"name":"myproj"}]}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/projects/5/machine-identities":
			_, _ = w.Write([]byte(`{"data":{"machine_identities":[{"id":11,"name":"worker","state":"active"}]}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/projects/5/machine-identities/11/tokens":
			_, _ = w.Write([]byte(`{"data":{"tokens":[{"id":99,"name":"ci-token","prefix":"kx_machine_ab12","revoked":false}]}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	origProj := tokenProjectName
	defer func() { tokenProjectName = origProj }()
	tokenProjectName = "myproj"

	out := captureStdout(t, func() {
		err := runTokenList(nil, []string{"worker"})
		require.NoError(t, err)
	})

	assert.Contains(t, out, "ci-token")
	assert.Contains(t, out, "kx_machine_ab12")
}

// ── TestMachineTokenIssue_RemotePath ─────────────────────────────────────────

func TestMachineTokenIssue_RemotePath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/projects":
			_, _ = w.Write([]byte(`{"data":{"projects":[{"id":7,"name":"remoteproj"}]}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/projects/7/machine-identities":
			_, _ = w.Write([]byte(`{"data":{"machine_identities":[{"id":33,"name":"bot","state":"active"}]}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/projects/7/machine-identities/33/tokens":
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"data":{"token":"kx_machine_therawtoken","id":55,"prefix":"kx_machine_th12","expires_at":null}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	origName := tokenIssueName
	origProj := tokenProjectName
	origDays := tokenIssueExpiryDays
	defer func() {
		tokenIssueName = origName
		tokenProjectName = origProj
		tokenIssueExpiryDays = origDays
	}()

	tokenIssueName = "remote-key"
	tokenProjectName = "remoteproj"
	tokenIssueExpiryDays = 0

	out := captureStdout(t, func() {
		err := runTokenIssue(nil, []string{"bot"})
		require.NoError(t, err)
	})

	assert.Contains(t, out, "kx_machine_therawtoken")
	assert.Contains(t, out, "55")
}

// ── TestMachineTokenRevoke_LocalPath ─────────────────────────────────────────

func TestMachineTokenRevoke_LocalPath(t *testing.T) {
	_, _, machineName := setupMachineLocalDB(t)

	// issue a token so we have a credential ID to revoke
	origIssueName := tokenIssueName
	origIssueProj := tokenProjectName
	origIssueDays := tokenIssueExpiryDays
	origIssueClass := tokenIssueClass
	defer func() {
		tokenIssueName = origIssueName
		tokenProjectName = origIssueProj
		tokenIssueExpiryDays = origIssueDays
		tokenIssueClass = origIssueClass
	}()

	tokenIssueName = "revoke-me"
	tokenProjectName = "testproject"
	tokenIssueExpiryDays = 0
	tokenIssueClass = ""

	var issuedIDStr string
	captureStdout(t, func() {
		// Capture the issued ID from the output — parse "ID:      N"
		out := captureStdout(t, func() {
			err := runTokenIssue(nil, []string{machineName})
			require.NoError(t, err)
		})
		// Find "ID:      <num>" line
		for _, line := range strings.Split(out, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "ID:") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					issuedIDStr = parts[1]
				}
			}
		}
	})

	// If we didn't parse the ID, fall back to "1" (first issued credential in fresh DB)
	if issuedIDStr == "" {
		issuedIDStr = "1"
	}

	origForce := tokenRevokeForce
	defer func() { tokenRevokeForce = origForce }()
	tokenRevokeForce = true

	cmd := &cobra.Command{}
	cmd.SetIn(strings.NewReader(""))

	out := captureStdout(t, func() {
		err := runTokenRevoke(cmd, []string{machineName, issuedIDStr})
		require.NoError(t, err)
	})

	assert.Contains(t, out, "Machine token revoked")
}
