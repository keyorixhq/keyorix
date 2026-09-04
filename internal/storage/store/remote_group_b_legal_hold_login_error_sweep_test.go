// remote_group_b_legal_hold_login_error_sweep_test.go — closes the remaining
// uncovered branches in remote_legal_hold.go, remote_login_attempts.go, and
// remote_login_verify.go:
//   - remote_legal_hold.go: CreateLegalHold's generic transport-error fallback
//     (distinct from the already-covered legalHoldAlreadyActiveCode branch) and
//     malformed-JSON branch; GetActiveLegalHold's transport-error and
//     malformed-JSON branches; UpdateLegalHold's transport-error branch. The
//     !resp.Success branches for all three methods and CreateLegalHold's
//     already-active branch are already covered by
//     remote_coverage_policies_memberships_auth_test.go / remote_misc_test.go.
//   - remote_login_attempts.go: the transport-error branch of all three
//     methods, and the malformed-JSON branch of CountRecentLoginAttempts and
//     PruneLoginAttempts (had no error-path tests at all before this file).
//   - remote_login_verify.go: VerifyLoginCredentials' !resp.Success and
//     malformed-JSON branches -- TestRemoteStorage_VerifyLoginCredentials_Failure
//     (remote_misc_test.go) only reaches the transport-error branch (it writes
//     a 401 status, which the HTTP client converts to a network-level error
//     before resp is ever populated).
package store_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- remote_legal_hold.go ---

func TestRemoteStorage_CreateLegalHold_TransportError_S36(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfigNoRetry("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.CreateLegalHold(context.Background(), &models.LegalHold{Reason: "test", PlacedBy: 1})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create legal hold")
}

func TestRemoteStorage_CreateLegalHold_MalformedJSON_S36(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiOK("{bad}"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.CreateLegalHold(context.Background(), &models.LegalHold{Reason: "test", PlacedBy: 1})
	assert.Error(t, err)
}

func TestRemoteStorage_GetActiveLegalHold_TransportError_S36(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfigNoRetry("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.GetActiveLegalHold(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get active legal hold")
}

func TestRemoteStorage_GetActiveLegalHold_MalformedJSON_S36(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiOK("{bad}"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetActiveLegalHold(context.Background())
	assert.Error(t, err)
}

func TestRemoteStorage_UpdateLegalHold_TransportError_S36(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfigNoRetry("http://127.0.0.1:0"))
	require.NoError(t, err)

	err = rs.UpdateLegalHold(context.Background(), &models.LegalHold{ID: 1, Reason: "test"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to update legal hold")
}

// --- remote_login_attempts.go ---

func TestRemoteStorage_RecordLoginAttempt_TransportError_S36(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfigNoRetry("http://127.0.0.1:0"))
	require.NoError(t, err)

	err = rs.RecordLoginAttempt(context.Background(), "10.0.0.1", time.Now())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to record login attempt")
}

func TestRemoteStorage_CountRecentLoginAttempts_TransportError_S36(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfigNoRetry("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.CountRecentLoginAttempts(context.Background(), "10.0.0.1", time.Now())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to count login attempts")
}

func TestRemoteStorage_CountRecentLoginAttempts_MalformedJSON_S36(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiOK("{bad}"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.CountRecentLoginAttempts(context.Background(), "10.0.0.1", time.Now())
	assert.Error(t, err)
}

func TestRemoteStorage_PruneLoginAttempts_TransportError_S36(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfigNoRetry("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.PruneLoginAttempts(context.Background(), time.Now())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to prune login attempts")
}

func TestRemoteStorage_PruneLoginAttempts_MalformedJSON_S36(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiOK("{bad}"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.PruneLoginAttempts(context.Background(), time.Now())
	assert.Error(t, err)
}

// --- remote_login_verify.go ---

func TestRemoteStorage_VerifyLoginCredentials_NotSuccess_S36(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiNotOK("INVALID_CREDENTIALS", "wrong password"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, _, err = rs.VerifyLoginCredentials(context.Background(), "alice", "wrong", "UA", "127.0.0.1")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid credentials")
}

func TestRemoteStorage_VerifyLoginCredentials_MalformedJSON_S36(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiOK("{bad}"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, _, err = rs.VerifyLoginCredentials(context.Background(), "alice", "s3cr3t", "UA", "127.0.0.1")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid credentials")
}
