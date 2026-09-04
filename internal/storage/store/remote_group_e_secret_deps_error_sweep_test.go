// remote_group_e_secret_deps_error_sweep_test.go — targeted coverage sweep for
// remote_secret_dependencies.go: transport-error and decode-error branches for
// GetSecretDependency/ListSecretDependenciesForProject, plus
// CreateSecretDependencyExclusive's generic (non-duplicate/non-cycle)
// transport-error fallback and its !resp.Success branch, none of which had a
// test — only the success, duplicate, and cycle paths did.
package store_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRemoteStorage_GetSecretDependency_TransportError_S36(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfigNoRetry("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.GetSecretDependency(context.Background(), 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get secret dependency")
}

func TestRemoteStorage_ListSecretDependenciesForProject_TransportError_S36(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfigNoRetry("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.ListSecretDependenciesForProject(context.Background(), 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list secret dependencies")
}

// TestRemoteStorage_ListSecretDependenciesForProject_NotSuccess_S36 exercises
// the !resp.Success branch specifically: a 2xx round trip whose body says
// success:false. A non-2xx status (errHandler) does NOT reach this branch —
// makeRequest converts every 4xx/5xx into a non-nil transport error before
// resp is ever populated (see remote/client.go's own doc comment), so it
// would exercise the err != nil branch above instead.
func TestRemoteStorage_ListSecretDependenciesForProject_NotSuccess_S36(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiErr("INTERNAL_ERROR", "db down"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListSecretDependenciesForProject(context.Background(), 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "list secret dependencies failed")
}

// TestRemoteStorage_ListSecretDependenciesForProject_BadJSON_S36 exercises
// decodeSecretDependencyList's own JSON-decode-error branch, distinct from
// the !resp.Success branch above.
func TestRemoteStorage_ListSecretDependenciesForProject_BadJSON_S36(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":"not-an-object"}`))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListSecretDependenciesForProject(context.Background(), 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

// TestRemoteStorage_CreateSecretDependencyExclusive_TransportError_S36 hits
// the generic "failed to create secret dependency" fallback (the transport
// error is a plain connection failure, not a *remote.HTTPError carrying a
// duplicate/cycle ErrorType, so errors.As fails and execution falls through
// to the final return in the err != nil branch).
func TestRemoteStorage_CreateSecretDependencyExclusive_TransportError_S36(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfigNoRetry("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.CreateSecretDependencyExclusive(context.Background(), &models.SecretDependency{
		ProjectID: 1, DependentSecretID: 2, DependsOnSecretID: 3,
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create secret dependency")
}

// TestRemoteStorage_CreateSecretDependencyExclusive_NotSuccess_S36 exercises
// the !resp.Success branch specifically: a 2xx round trip whose body says
// success:false. A non-2xx status (errHandler) does NOT reach this branch —
// it instead becomes a *remote.HTTPError, taking the err != nil path above.
func TestRemoteStorage_CreateSecretDependencyExclusive_NotSuccess_S36(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiErr("INTERNAL_ERROR", "db down"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.CreateSecretDependencyExclusive(context.Background(), &models.SecretDependency{
		ProjectID: 1, DependentSecretID: 2, DependsOnSecretID: 3,
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "create secret dependency failed")
}
