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

// --- Secret CRUD (CreateSecret, GetSecret, ListSecrets already in remote_storage_test.go) ---

func TestRemoteStorage_GetSecretsByIDs(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		callCount++
		switch r.URL.Path {
		case "/api/v1/secrets/1":
			_, _ = w.Write(apiOK(map[string]interface{}{"id": 1, "name": "secret-one", "type": "password"}))
		case "/api/v1/secrets/2":
			_, _ = w.Write(apiOK(map[string]interface{}{"id": 2, "name": "secret-two", "type": "api_key"}))
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	secrets, err := rs.GetSecretsByIDs(context.Background(), []uint{1, 2})
	require.NoError(t, err)
	require.Len(t, secrets, 2)
	assert.Equal(t, "secret-one", secrets[0].Name)
	assert.Equal(t, "secret-two", secrets[1].Name)
}

func TestRemoteStorage_GetSecretsByIDs_SkipsErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/secrets/1" {
			_, _ = w.Write(apiOK(map[string]interface{}{"id": 1, "name": "good-secret"}))
		} else {
			// Return an error response for ID 2.
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"success":false,"error":{"code":"NOT_FOUND","message":"not found"}}`))
		}
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	// GetSecretsByIDs skips errors rather than returning them.
	secrets, err := rs.GetSecretsByIDs(context.Background(), []uint{1, 2})
	require.NoError(t, err)
	require.Len(t, secrets, 1)
	assert.Equal(t, "good-secret", secrets[0].Name)
}

func TestRemoteStorage_GetSecretByName(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/secrets/by-name", r.URL.Path)
		assert.Equal(t, "my-secret", r.URL.Query().Get("name"))
		assert.Equal(t, "3", r.URL.Query().Get("project_id"))
		assert.Equal(t, "7", r.URL.Query().Get("environment_id"))
		_, _ = w.Write(apiOK(map[string]interface{}{"id": 42, "name": "my-secret", "type": "password"}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	secret, err := rs.GetSecretByName(context.Background(), "my-secret", 3, 7)
	require.NoError(t, err)
	assert.Equal(t, uint(42), secret.ID)
	assert.Equal(t, "my-secret", secret.Name)
}

func TestRemoteStorage_UpdateSecret(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "PUT", r.Method)
		assert.Equal(t, "/api/v1/secrets/42", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{"id": 42, "name": "my-secret", "type": "password"}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	secret, err := rs.UpdateSecret(context.Background(), &models.SecretNode{ID: 42, Name: "my-secret"})
	require.NoError(t, err)
	assert.Equal(t, uint(42), secret.ID)
}

func TestRemoteStorage_DeleteSecret(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "DELETE", r.Method)
		assert.Equal(t, "/api/v1/secrets/42", r.URL.Path)
		_, _ = w.Write(apiOK(nil))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.DeleteSecret(context.Background(), 42)
	require.NoError(t, err)
}

func TestRemoteStorage_GetSecretIncludingDeleted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/system/secrets/42/including-deleted", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"secret": map[string]interface{}{"ID": 42, "Name": "deleted-secret", "Type": "password"},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	secret, err := rs.GetSecretIncludingDeleted(context.Background(), 42)
	require.NoError(t, err)
	require.NotNil(t, secret)
	assert.Equal(t, uint(42), secret.ID)
}

func TestRemoteStorage_RestoreSecret(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/secrets/42/restore", r.URL.Path)
		_, _ = w.Write(apiOK(nil))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.RestoreSecret(context.Background(), 42)
	require.NoError(t, err)
}

// --- Retention / purge proxies ---

func TestRemoteStorage_PurgeDeletedSecretsBefore(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/system/retention/secrets/purge", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{"purged": 3}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	purged, err := rs.PurgeDeletedSecretsBefore(context.Background(), time.Now())
	require.NoError(t, err)
	assert.Equal(t, int64(3), purged)
}

func TestRemoteStorage_DeleteAnomalyAlertsBefore(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/system/retention/anomaly-alerts/purge", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{"purged": 7}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	purged, err := rs.DeleteAnomalyAlertsBefore(context.Background(), time.Now(), time.Now())
	require.NoError(t, err)
	assert.Equal(t, int64(7), purged)
}

func TestRemoteStorage_DeleteClosedAccessReviewsBefore(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/system/retention/access-reviews/purge-closed", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{"campaigns_purged": 2, "items_purged": 10}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	campaigns, items, err := rs.DeleteClosedAccessReviewsBefore(context.Background(), time.Now())
	require.NoError(t, err)
	assert.Equal(t, int64(2), campaigns)
	assert.Equal(t, int64(10), items)
}

func TestRemoteStorage_DeleteExpiredBreakGlassBefore(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/system/retention/break-glass/purge-expired", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{"purged": 1}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	purged, err := rs.DeleteExpiredBreakGlassBefore(context.Background(), time.Now())
	require.NoError(t, err)
	assert.Equal(t, int64(1), purged)
}

func TestRemoteStorage_DeleteResolvedAccessRequestsBefore(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/system/retention/access-requests/purge-resolved", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{"requests_purged": 4, "approvals_purged": 8}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	requests, approvals, err := rs.DeleteResolvedAccessRequestsBefore(context.Background(), time.Now())
	require.NoError(t, err)
	assert.Equal(t, int64(4), requests)
	assert.Equal(t, int64(8), approvals)
}

// --- Server-side-only operations (unsupported in remote mode) ---

func TestRemoteStorage_ListProjectSecretsForDrift_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.ListProjectSecretsForDrift(context.Background(), 1)
	assert.Error(t, err)
}

func TestRemoteStorage_ListOrphanedSecrets_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.ListOrphanedSecrets(context.Background(), 1)
	assert.Error(t, err)
}

func TestRemoteStorage_CountOrphanedSecretsByProject_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.CountOrphanedSecretsByProject(context.Background(), []uint{1, 2})
	assert.Error(t, err)
}

func TestRemoteStorage_CountExpiringSecretsByProject_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.CountExpiringSecretsByProject(context.Background(), []uint{1, 2}, time.Now())
	assert.Error(t, err)
}

func TestRemoteStorage_ListLiveSecretNamesByProject_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, _, err = rs.ListLiveSecretNamesByProject(context.Background(), []uint{1}, 100)
	assert.Error(t, err)
}

func TestRemoteStorage_GetSecretTags_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.GetSecretTags(context.Background(), 1)
	assert.Error(t, err)
}

func TestRemoteStorage_SetSecretTags_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://127.0.0.1:0"))
	require.NoError(t, err)

	err = rs.SetSecretTags(context.Background(), 1, []string{"prod"})
	assert.Error(t, err)
}

func TestRemoteStorage_SetSecretCertNotAfter_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://127.0.0.1:0"))
	require.NoError(t, err)

	now := time.Now()
	err = rs.SetSecretCertNotAfter(context.Background(), 1, &now)
	assert.Error(t, err)
}

func TestRemoteStorage_TryIncrementSecretReadCount_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://127.0.0.1:0"))
	require.NoError(t, err)

	ok, err := rs.TryIncrementSecretReadCount(context.Background(), 1, 5)
	assert.Error(t, err)
	assert.False(t, ok)
}

func TestRemoteStorage_TryIncrementSecretNodeReadCount_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://127.0.0.1:0"))
	require.NoError(t, err)

	ok, err := rs.TryIncrementSecretNodeReadCount(context.Background(), 1, 5)
	assert.Error(t, err)
	assert.False(t, ok)
}

// --- Secret version operations ---

func TestRemoteStorage_CreateSecretVersion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/secrets/42/versions", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"ID": 100, "SecretNodeID": 42, "VersionNumber": 1, "ReadCount": 0,
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	version, err := rs.CreateSecretVersion(context.Background(), &models.SecretVersion{
		SecretNodeID:  42,
		VersionNumber: 1,
	})
	require.NoError(t, err)
	assert.Equal(t, 1, version.VersionNumber)
}

func TestRemoteStorage_GetSecretVersion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/secrets/42/versions/2", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"ID": 200, "SecretNodeID": 42, "VersionNumber": 2, "ReadCount": 3,
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	version, err := rs.GetSecretVersion(context.Background(), 42, 2)
	require.NoError(t, err)
	assert.Equal(t, 2, version.VersionNumber)
	assert.Equal(t, 3, version.ReadCount)
}

func TestRemoteStorage_ListSecretVersions(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/secrets/42/versions", r.URL.Path)
		_, _ = w.Write(apiOK([]map[string]interface{}{
			{"ID": 100, "SecretNodeID": 42, "VersionNumber": 1, "ReadCount": 0},
			{"ID": 200, "SecretNodeID": 42, "VersionNumber": 2, "ReadCount": 1},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	versions, err := rs.ListSecretVersions(context.Background(), 42)
	require.NoError(t, err)
	require.Len(t, versions, 2)
	assert.Equal(t, 1, versions[0].VersionNumber)
}

// --- TransitionSecretStatus ---

func TestRemoteStorage_TransitionSecretStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPut, r.Method)
		assert.Equal(t, "/api/v1/system/secrets/42/transition-status", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{"matched": true}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	matched, err := rs.TransitionSecretStatus(context.Background(),
		&models.SecretNode{ID: 42, Status: "suspended"}, "active")
	require.NoError(t, err)
	assert.True(t, matched)
}

func TestRemoteStorage_TransitionSecretStatus_NotMatched(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiOK(map[string]interface{}{"matched": false}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	matched, err := rs.TransitionSecretStatus(context.Background(),
		&models.SecretNode{ID: 42, Status: "active"}, "suspended")
	require.NoError(t, err)
	assert.False(t, matched)
}

func TestRemoteStorage_GetSecretVersions(t *testing.T) {
	// GetSecretVersions is an alias for ListSecretVersions; same URL.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/secrets/42/versions", r.URL.Path)
		_, _ = w.Write(apiOK([]map[string]interface{}{
			{"ID": 100, "SecretNodeID": 42, "VersionNumber": 1, "ReadCount": 0},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	versions, err := rs.GetSecretVersions(context.Background(), 42)
	require.NoError(t, err)
	require.Len(t, versions, 1)
}

func TestRemoteStorage_GetLatestSecretVersion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/secrets/42/versions/latest", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"ID": 300, "SecretNodeID": 42, "VersionNumber": 3, "ReadCount": 5,
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	version, err := rs.GetLatestSecretVersion(context.Background(), 42)
	require.NoError(t, err)
	assert.Equal(t, 3, version.VersionNumber)
	assert.Equal(t, 5, version.ReadCount)
}

func TestRemoteStorage_IncrementSecretReadCount(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/secret-versions/100/increment-read-count", r.URL.Path)
		_, _ = w.Write(apiOK(nil))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.IncrementSecretReadCount(context.Background(), 100)
	require.NoError(t, err)
}
