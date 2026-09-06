// lifecycle_remote_test.go — remote-mode coverage for suspend/reactivate/
// force-password-reset/revoke-sessions/delete/list/resend-setup-link: each
// must POST/DELETE/GET to the real REST endpoint (server/http/router.go)
// instead of silently falling back to a stray local SQLite file once a
// remote server is configured (KEYORIX_SERVER/KEYORIX_TOKEN).
package user

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// remoteTestServer builds an httptest server that answers GET
// /api/v1/users/{id} (the remoteUserLabel lookup every command below performs
// first) with the given email, and dispatches every other request to extra.
func remoteTestServer(t *testing.T, email string, extra http.HandlerFunc) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/api/v1/users/5" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"data":{"id":5,"email":%q}}`, email)
			return
		}
		extra(w, r)
	}))
}

func TestSuspendCmd_Remote_PostsToServer(t *testing.T) {
	var gotPath, gotMethod string
	srv := remoteTestServer(t, "alice@example.com", func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":null}`)
	})
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	origID, origBy := suspendUserID, suspendBy
	defer func() { suspendUserID = origID; suspendBy = origBy }()
	suspendUserID, suspendBy = 5, "admin@example.com"

	out := captureOutput(t, func() {
		require.NoError(t, suspendCmd.RunE(suspendCmd, nil))
	})

	assert.Equal(t, "POST", gotMethod)
	assert.Equal(t, "/api/v1/users/5/suspend", gotPath)
	assert.Contains(t, out, "Suspending user 5 (alice@example.com) on "+srv.URL)
	assert.Contains(t, out, "user 5 (alice@example.com) has been suspended on "+srv.URL)
}

func TestReactivateCmd_Remote_PostsToServer(t *testing.T) {
	var gotPath string
	srv := remoteTestServer(t, "bob@example.com", func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":null}`)
	})
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	origID, origBy := reactivateUserID, reactivateBy
	defer func() { reactivateUserID = origID; reactivateBy = origBy }()
	reactivateUserID, reactivateBy = 5, "admin@example.com"

	out := captureOutput(t, func() {
		require.NoError(t, reactivateCmd.RunE(reactivateCmd, nil))
	})

	assert.Equal(t, "/api/v1/users/5/reactivate", gotPath)
	assert.Contains(t, out, "has been reactivated on "+srv.URL)
}

func TestForcePasswordResetCmd_Remote_PostsToServer(t *testing.T) {
	var gotPath string
	srv := remoteTestServer(t, "carol@example.com", func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":null}`)
	})
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	origID, origBy := forcePasswordResetUserID, forcePasswordResetBy
	defer func() { forcePasswordResetUserID = origID; forcePasswordResetBy = origBy }()
	forcePasswordResetUserID, forcePasswordResetBy = 5, "admin@example.com"

	out := captureOutput(t, func() {
		require.NoError(t, forcePasswordResetCmd.RunE(forcePasswordResetCmd, nil))
	})

	assert.Equal(t, "/api/v1/users/5/require-password-reset", gotPath)
	assert.Contains(t, out, "has been required to reset their password on "+srv.URL)
}

func TestSuspendCmd_Remote_ServerErrorPropagates(t *testing.T) {
	srv := remoteTestServer(t, "dave@example.com", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	origID, origBy := suspendUserID, suspendBy
	defer func() { suspendUserID = origID; suspendBy = origBy }()
	suspendUserID, suspendBy = 5, "admin@example.com"

	err := suspendCmd.RunE(suspendCmd, nil)
	require.Error(t, err, "a 404 from the server must fail loudly, not be swallowed as success")
	assert.Contains(t, err.Error(), "404")
}

func TestRevokeSessionsCmd_Remote_ReturnsCount(t *testing.T) {
	srv := remoteTestServer(t, "erin@example.com", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/users/5/revoke-sessions", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"revoked":3}}`)
	})
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	origID, origBy := revokeSessionsUserID, revokeSessionsBy
	defer func() { revokeSessionsUserID = origID; revokeSessionsBy = origBy }()
	revokeSessionsUserID, revokeSessionsBy = 5, "admin@example.com"

	out := captureOutput(t, func() {
		require.NoError(t, revokeSessionsCmd.RunE(revokeSessionsCmd, nil))
	})

	assert.Contains(t, out, "Revoked 3 active session(s) for user 5 (erin@example.com) on "+srv.URL)
}

func TestRevokeSessionsCmd_Remote_ZeroRevokedIsStatedExplicitly(t *testing.T) {
	srv := remoteTestServer(t, "frank@example.com", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"revoked":0}}`)
	})
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	origID, origBy := revokeSessionsUserID, revokeSessionsBy
	defer func() { revokeSessionsUserID = origID; revokeSessionsBy = origBy }()
	revokeSessionsUserID, revokeSessionsBy = 5, "admin@example.com"

	out := captureOutput(t, func() {
		require.NoError(t, revokeSessionsCmd.RunE(revokeSessionsCmd, nil))
	})

	assert.Contains(t, out, "0 sessions revoked for user 5 (frank@example.com) on "+srv.URL+" -- none were active.")
}

func TestRunDelete_Remote_ForceDeletesOnServer(t *testing.T) {
	var gotMethod, gotPath string
	srv := remoteTestServer(t, "gail@example.com", func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	})
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	origID, origBy, origForce := deleteUserID, deleteBy, deleteForce
	defer func() { deleteUserID = origID; deleteBy = origBy; deleteForce = origForce }()
	deleteUserID, deleteBy, deleteForce = 5, "admin@example.com", true

	out := captureOutput(t, func() {
		require.NoError(t, runDelete(nil, nil))
	})

	assert.Equal(t, "DELETE", gotMethod)
	assert.Equal(t, "/api/v1/users/5", gotPath)
	assert.Contains(t, out, "Deleting user 5 (gail@example.com) on "+srv.URL)
	assert.Contains(t, out, "user 5 (gail@example.com) deleted on "+srv.URL)
}

func TestRunDelete_Remote_CancelledPromptNeverCallsDelete(t *testing.T) {
	called := false
	srv := remoteTestServer(t, "henry@example.com", func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	origID, origBy, origForce := deleteUserID, deleteBy, deleteForce
	defer func() { deleteUserID = origID; deleteBy = origBy; deleteForce = origForce }()
	deleteUserID, deleteBy, deleteForce = 5, "admin@example.com", false

	var out string
	withStdin(t, "no\n", func() {
		out = captureOutput(t, func() {
			require.NoError(t, runDelete(nil, nil))
		})
	})

	assert.Contains(t, out, "Deletion cancelled")
	assert.False(t, called, "declining the confirmation must never reach the DELETE endpoint")
}

func TestRunList_Remote_PrintsUsersFromServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/users", r.URL.Path)
		assert.Equal(t, "1", r.URL.Query().Get("page"))
		assert.Equal(t, "20", r.URL.Query().Get("page_size"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"users":[{"id":1,"username":"admin","email":"admin@example.com","active":true}],"total":1}}`)
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	origPage, origSize := listPage, listPageSize
	defer func() { listPage = origPage; listPageSize = origSize }()
	listPage, listPageSize = 1, 20

	out := captureOutput(t, func() {
		require.NoError(t, runList(nil, nil))
	})

	assert.Contains(t, out, "Total: 1")
	assert.Contains(t, out, "admin")
	assert.Contains(t, out, "admin@example.com")
}

func TestResendSetupLinkCmd_Remote_ReissuesOnServer(t *testing.T) {
	var gotPath string
	srv := remoteTestServer(t, "ivy@example.com", func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"email":"ivy@example.com","channel":"out_of_band","delivered":false,"link_for_admin":"https://app.example.com/auth/setup/xyz"}}`)
	})
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	origID, origBy := resendSetupLinkUserID, resendSetupLinkBy
	defer func() { resendSetupLinkUserID = origID; resendSetupLinkBy = origBy }()
	resendSetupLinkUserID, resendSetupLinkBy = 5, "admin@example.com"

	out := captureOutput(t, func() {
		require.NoError(t, resendSetupLinkCmd.RunE(resendSetupLinkCmd, nil))
	})

	assert.Equal(t, "/api/v1/users/5/resend-setup-link", gotPath)
	assert.Contains(t, out, "Reissuing setup link for user 5 (ivy@example.com) on "+srv.URL)
	assert.Contains(t, out, "xyz")
}

// TestRemoteUserLabel_FallsBackWhenLookupFails confirms a failed GET (e.g. the
// caller lacks users.read, or the user was already deleted) degrades to the
// bare "user <id>" label rather than blocking or erroring the caller.
func TestRemoteUserLabel_FallsBackWhenLookupFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	label := remoteUserLabel(context.Background(), rc, 99)
	assert.Equal(t, "user 99", label)
}
