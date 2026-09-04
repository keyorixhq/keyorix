package store_test

// remote_realimpl_zero_coverage_test.go covers RemoteStorage methods that
// were still at 0% but, unlike remote_stub_zero_coverage_test.go's targets,
// are genuine HTTP-proxying implementations (they call rs.client and decode
// a real response) rather than one-line unsupported stubs.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- remote_mfa_stepup_grant.go: PruneMFAStepUpGrants ---

func TestRemoteStorage_PruneMFAStepUpGrants_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/system/mfa/stepup-grants/prune", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{"deleted": 7}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	deleted, err := rs.PruneMFAStepUpGrants(context.Background(), time.Now().UTC())
	require.NoError(t, err)
	assert.Equal(t, int64(7), deleted)
}

func TestRemoteStorage_PruneMFAStepUpGrants_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write(apiErr("STORAGE_ERROR", "db down"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	deleted, err := rs.PruneMFAStepUpGrants(context.Background(), time.Now().UTC())
	require.Error(t, err)
	assert.Zero(t, deleted)
}

func TestRemoteStorage_PruneMFAStepUpGrants_SuccessFalse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(apiErr("STORAGE_ERROR", "db down"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	deleted, err := rs.PruneMFAStepUpGrants(context.Background(), time.Now().UTC())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "prune MFA step-up grants failed")
	assert.Zero(t, deleted)
}

func TestRemoteStorage_PruneMFAStepUpGrants_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"data":{bad json}}`))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	deleted, err := rs.PruneMFAStepUpGrants(context.Background(), time.Now().UTC())
	require.Error(t, err)
	assert.Zero(t, deleted)
}

// --- remote_secret_acl.go: DeleteSecretACLsByUserAndProject ---

func TestRemoteStorage_DeleteSecretACLsByUserAndProject_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/system/rbac/delete-secret-acls-by-user-and-project", r.URL.Path)
		_, _ = w.Write(apiOK(nil))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.DeleteSecretACLsByUserAndProject(context.Background(), 1, 2)
	require.NoError(t, err)
}

func TestRemoteStorage_DeleteSecretACLsByUserAndProject_TransportError(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfigNoRetry("http://127.0.0.1:0"))
	require.NoError(t, err)

	err = rs.DeleteSecretACLsByUserAndProject(context.Background(), 1, 2)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to delete secret ACLs by user and project")
}

func TestRemoteStorage_DeleteSecretACLsByUserAndProject_SuccessFalse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(apiErr("STORAGE_ERROR", "db down"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.DeleteSecretACLsByUserAndProject(context.Background(), 1, 2)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "delete secret ACLs by user and project failed")
}

// --- remote_secrets.go: ClearProjectSecretOwnership ---

func TestRemoteStorage_ClearProjectSecretOwnership_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/system/rbac/clear-project-secret-ownership", r.URL.Path)
		_, _ = w.Write(apiOK(nil))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.ClearProjectSecretOwnership(context.Background(), 1, 2)
	require.NoError(t, err)
}

func TestRemoteStorage_ClearProjectSecretOwnership_TransportError(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfigNoRetry("http://127.0.0.1:0"))
	require.NoError(t, err)

	err = rs.ClearProjectSecretOwnership(context.Background(), 1, 2)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to clear project secret ownership")
}

func TestRemoteStorage_ClearProjectSecretOwnership_SuccessFalse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(apiErr("STORAGE_ERROR", "db down"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.ClearProjectSecretOwnership(context.Background(), 1, 2)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "clear project secret ownership failed")
}
