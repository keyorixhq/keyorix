// remote_group_e_secrets_error_sweep_test.go — targeted coverage sweep for
// remote_secrets.go's transport-error (rs.client.X returns err != nil) and
// decode-error branches across CreateSecret, GetSecretByName, UpdateSecret,
// DeleteSecret, GetSecretIncludingDeleted, RestoreSecret, ListSecrets, and
// ListSecretVersions, plus buildSecretFilterPath's nil-filter shortcut, none
// of which had a test — only their !resp.Success/decode-error or success
// paths did (see remote_secrets_test.go, remote_storage_test.go,
// remote_coverage_mfa_rbac_secrets_test.go).
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

func TestRemoteStorage_CreateSecret_TransportError_S36(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfigNoRetry("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.CreateSecret(context.Background(), &models.SecretNode{Name: "s", Type: "password"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create secret")
}

func TestRemoteStorage_CreateSecret_BadJSON_S36(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":"not-an-object"}`))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.CreateSecret(context.Background(), &models.SecretNode{Name: "s", Type: "password"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestRemoteStorage_GetSecretByName_TransportError_S36(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfigNoRetry("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.GetSecretByName(context.Background(), "s", 1, 2)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get secret by name")
}

func TestRemoteStorage_UpdateSecret_TransportError_S36(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfigNoRetry("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.UpdateSecret(context.Background(), &models.SecretNode{ID: 1, Name: "s"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to update secret")
}

func TestRemoteStorage_DeleteSecret_TransportError_S36(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfigNoRetry("http://127.0.0.1:0"))
	require.NoError(t, err)

	err = rs.DeleteSecret(context.Background(), 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to delete secret")
}

func TestRemoteStorage_GetSecretIncludingDeleted_TransportError_S36(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfigNoRetry("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.GetSecretIncludingDeleted(context.Background(), 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get secret including deleted")
}

func TestRemoteStorage_GetSecretIncludingDeleted_BadJSON_S36(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":"not-an-object"}`))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetSecretIncludingDeleted(context.Background(), 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestRemoteStorage_RestoreSecret_TransportError_S36(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfigNoRetry("http://127.0.0.1:0"))
	require.NoError(t, err)

	err = rs.RestoreSecret(context.Background(), 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to restore secret")
}

func TestRemoteStorage_ListSecrets_TransportError_S36(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfigNoRetry("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, _, err = rs.ListSecrets(context.Background(), nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list secrets")
}

// TestRemoteStorage_ListSecrets_NilFilter_S36 exercises
// buildSecretFilterPath's `if filter == nil { return apiSecretsPath }`
// shortcut — every other ListSecrets call in the package passes a non-nil
// filter.
func TestRemoteStorage_ListSecrets_NilFilter_S36(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/secrets", r.URL.Path)
		assert.Empty(t, r.URL.RawQuery)
		_, _ = w.Write(apiOK(map[string]interface{}{"secrets": []map[string]interface{}{}, "total": 0}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	secrets, total, err := rs.ListSecrets(context.Background(), nil)
	require.NoError(t, err)
	assert.Empty(t, secrets)
	assert.Zero(t, total)
}

func TestRemoteStorage_ListSecretVersions_TransportError_S36(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfigNoRetry("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.ListSecretVersions(context.Background(), 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list secret versions")
}
