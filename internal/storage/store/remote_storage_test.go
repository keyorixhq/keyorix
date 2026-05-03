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
		w.Write(apiOK(map[string]interface{}{"id": 1, "name": "test-secret", "type": "password"}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	result, err := rs.CreateSecret(context.Background(), &models.SecretNode{Name: "test-secret", Type: "password"})
	require.NoError(t, err)
	assert.Equal(t, uint(1), result.ID)
	assert.Equal(t, "test-secret", result.Name)
}

func TestRemoteStorage_GetSecret(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/secrets/1", r.URL.Path)
		w.Write(apiOK(map[string]interface{}{"id": 1, "name": "test-secret", "type": "password"}))
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
		w.Write(apiOK(map[string]interface{}{
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

func TestRemoteStorage_Health(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/health", r.URL.Path)
		w.Write(apiOK(map[string]string{"status": "healthy"}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)
	assert.NoError(t, rs.Health(context.Background()))
}

func TestRemoteStorage_Health_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]interface{}{
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
