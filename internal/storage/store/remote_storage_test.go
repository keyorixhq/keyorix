package store_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/remote"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testConfig(serverURL string) *remote.Config {
	return &remote.Config{
		BaseURL:        serverURL,
		APIKey:         "test-key",
		TimeoutSeconds: 30,
		RetryAttempts:  3,
		TLSVerify:      false,
	}
}

// testConfigNoRetry is testConfig with RetryAttempts: 0, for tests that
// deliberately hit an unreachable target (e.g. "http://127.0.0.1:0") just to
// exercise a transport-error (`err != nil`) return branch. HTTPClient.Request's
// retry loop backs off attempt*attempt seconds between attempts
// (internal/storage/remote/client.go), so testConfig's RetryAttempts: 3 burns a
// full, unavoidable 1+4+9=14s per call against a target that can never succeed —
// harmless for one test, but serial-additive across the many such tests in this
// package. RetryAttempts: 0 makes exactly one attempt (no backoff), hitting the
// identical code path in a few milliseconds instead.
func testConfigNoRetry(serverURL string) *remote.Config {
	cfg := testConfig(serverURL)
	cfg.RetryAttempts = 0
	return cfg
}

func apiOK(data interface{}) []byte {
	type resp struct {
		Success bool        `json:"success"`
		Data    interface{} `json:"data"`
	}
	b, _ := json.Marshal(resp{Success: true, Data: data})
	return b
}

func TestNewRemoteStorage_Valid(t *testing.T) {
	cfg := &remote.Config{
		BaseURL:        "https://api.example.com",
		APIKey:         "test-key",
		TimeoutSeconds: 30,
		RetryAttempts:  3,
		TLSVerify:      true,
	}
	rs, err := store.NewRemoteStorage(cfg)
	require.NoError(t, err)
	assert.NotNil(t, rs)
}

func TestNewRemoteStorage_InvalidConfig(t *testing.T) {
	_, err := store.NewRemoteStorage(&remote.Config{})
	assert.Error(t, err)
}

func TestRemoteStorage_CreateSecret(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/secrets", r.URL.Path)
		assert.Equal(t, "Bearer test-key", r.Header.Get("Authorization"))
		_, _ = w.Write(apiOK(map[string]interface{}{"id": 1, "name": "test-secret", "type": "password"}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	result, err := rs.CreateSecret(context.Background(), &models.SecretNode{Name: "test-secret", Type: "password"})
	require.NoError(t, err)
	assert.Equal(t, uint(1), result.ID)
	assert.Equal(t, "test-secret", result.Name)
}

// TestRemoteStorage_CreateSecret_SendsParentID is the #G80 regression:
// ParentID was omitted from the wire request entirely, so every secret
// created inside a folder under storage.type: remote was silently created at
// project root instead.
func TestRemoteStorage_CreateSecret_SendsParentID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ParentID *uint `json:"parent_id"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		require.NotNil(t, body.ParentID)
		assert.Equal(t, uint(42), *body.ParentID)
		_, _ = w.Write(apiOK(map[string]interface{}{"id": 1, "name": "test-secret", "type": "password"}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	parentID := uint(42)
	_, err = rs.CreateSecret(context.Background(), &models.SecretNode{Name: "test-secret", Type: "password", ParentID: &parentID})
	require.NoError(t, err)
}

func TestRemoteStorage_GetSecret(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/secrets/1", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{"id": 1, "name": "test-secret", "type": "password"}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	result, err := rs.GetSecret(context.Background(), 1)
	require.NoError(t, err)
	assert.Equal(t, uint(1), result.ID)
	assert.Equal(t, "test-secret", result.Name)
}

func TestRemoteStorage_ListSecrets(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/secrets", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"secrets": []map[string]interface{}{
				{"id": 1, "name": "secret1", "type": "password"},
				{"id": 2, "name": "secret2", "type": "api_key"},
			},
			"total": 2,
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	secrets, total, err := rs.ListSecrets(context.Background(), &corestorage.SecretFilter{Page: 1, PageSize: 10})
	require.NoError(t, err)
	assert.Len(t, secrets, 2)
	assert.Equal(t, int64(2), total)
	assert.Equal(t, "secret1", secrets[0].Name)
}

// TestRemoteStorage_Health_RealServerShape mirrors the ACTUAL, unwrapped body
// server/http/handlers/health.go writes for GET /health — {"status":"healthy",
// "timestamp":...,"uptime":...}, no {"success":...,"data":...} envelope, since
// /health is an unauthenticated liveness probe outside /api/v1/*, not a normal
// API route. G80 Wave 0c: the sibling test below (apiOK-wrapped) was passing
// against a shape the real server never produces, masking a real bug —
// RemoteStorage.Health() reported every genuinely healthy server as unhealthy.
// Confirmed red before the fix (Health checked resp.Success, which is false
// for this unwrapped body), green after (Health now only checks for a
// transport/4xx/5xx error, which rs.client.Get already surfaces).
func TestRemoteStorage_Health_RealServerShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/health", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":    "healthy",
			"timestamp": "2026-08-27T00:00:00Z",
			"uptime":    "1h0m0s",
		})
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)
	assert.NoError(t, rs.Health(context.Background()))
}

func TestRemoteStorage_Health(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/health", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]string{"status": "healthy"}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)
	assert.NoError(t, rs.Health(context.Background()))
}

func TestRemoteStorage_Health_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   map[string]string{"code": "SERVICE_UNAVAILABLE", "message": "unavailable"},
		})
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)
	err = rs.Health(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "health check failed")
}
