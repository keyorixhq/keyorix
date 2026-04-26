package remote

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRemoteStorage(t *testing.T) {
	config := &Config{
		BaseURL:        "https://api.example.com",
		APIKey:         "test-key",
		TimeoutSeconds: 30,
		RetryAttempts:  3,
		TLSVerify:      true,
	}

	storage, err := NewRemoteStorage(config)
	require.NoError(t, err)
	assert.NotNil(t, storage)
	assert.NotNil(t, storage.client)
}

func TestNewRemoteStorage_InvalidConfig(t *testing.T) {
	config := &Config{
		// Missing required fields
	}

	_, err := NewRemoteStorage(config)
	assert.Error(t, err)
}

func TestRemoteStorage_CreateSecret(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/secrets", r.URL.Path)
		assert.Equal(t, "Bearer test-key", r.Header.Get("Authorization"))

		// Return a mock response
		response := APIResponse{
			Success: true,
			Data:    json.RawMessage(`{"id": 1, "name": "test-secret", "type": "password"}`),
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	// Create remote storage
	config := &Config{
		BaseURL:        server.URL,
		APIKey:         "test-key",
		TimeoutSeconds: 30,
		RetryAttempts:  3,
		TLSVerify:      false,
	}

	rs, err := NewRemoteStorage(config)
	require.NoError(t, err)

	// Test creating a secret
	secret := &models.SecretNode{
		Name: "test-secret",
		Type: "password",
	}

	result, err := rs.CreateSecret(context.Background(), secret)
	require.NoError(t, err)
	assert.Equal(t, uint(1), result.ID)
	assert.Equal(t, "test-secret", result.Name)
	assert.Equal(t, "password", result.Type)
}

func TestRemoteStorage_CreateSecret_Error(t *testing.T) {
	// Create a test server that returns an error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		response := APIResponse{
			Success: false,
			Error: &APIError{
				Code:    "INVALID_REQUEST",
				Message: "Invalid secret data",
			},
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	// Create remote storage
	config := &Config{
		BaseURL:        server.URL,
		APIKey:         "test-key",
		TimeoutSeconds: 30,
		RetryAttempts:  3,
		TLSVerify:      false,
	}

	rs, err := NewRemoteStorage(config)
	require.NoError(t, err)

	// Test creating a secret with error
	secret := &models.SecretNode{
		Name: "test-secret",
		Type: "password",
	}

	_, err = rs.CreateSecret(context.Background(), secret)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create secret")
}

func TestRemoteStorage_GetSecret(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/secrets/1", r.URL.Path)

		// Return a mock response
		response := APIResponse{
			Success: true,
			Data:    json.RawMessage(`{"id": 1, "name": "test-secret", "type": "password"}`),
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	// Create remote storage
	config := &Config{
		BaseURL:        server.URL,
		APIKey:         "test-key",
		TimeoutSeconds: 30,
		RetryAttempts:  3,
		TLSVerify:      false,
	}

	rs, err := NewRemoteStorage(config)
	require.NoError(t, err)

	// Test getting a secret
	result, err := rs.GetSecret(context.Background(), 1)
	require.NoError(t, err)
	assert.Equal(t, uint(1), result.ID)
	assert.Equal(t, "test-secret", result.Name)
	assert.Equal(t, "password", result.Type)
}

func TestRemoteStorage_ListSecrets(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/secrets", r.URL.Path)

		// Return a mock response
		response := APIResponse{
			Success: true,
			Data: json.RawMessage(`{
				"secrets": [
					{"id": 1, "name": "secret1", "type": "password"},
					{"id": 2, "name": "secret2", "type": "api_key"}
				],
				"total": 2
			}`),
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	// Create remote storage
	config := &Config{
		BaseURL:        server.URL,
		APIKey:         "test-key",
		TimeoutSeconds: 30,
		RetryAttempts:  3,
		TLSVerify:      false,
	}

	rs, err := NewRemoteStorage(config)
	require.NoError(t, err)

	// Test listing secrets
	filter := &storage.SecretFilter{
		Page:     1,
		PageSize: 10,
	}

	secrets, total, err := rs.ListSecrets(context.Background(), filter)
	require.NoError(t, err)
	assert.Len(t, secrets, 2)
	assert.Equal(t, int64(2), total)
	assert.Equal(t, "secret1", secrets[0].Name)
	assert.Equal(t, "secret2", secrets[1].Name)
}

func TestRemoteStorage_Health(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/health", r.URL.Path)

		// Return a mock response
		response := APIResponse{
			Success: true,
			Data:    json.RawMessage(`{"status": "healthy"}`),
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	// Create remote storage
	config := &Config{
		BaseURL:        server.URL,
		APIKey:         "test-key",
		TimeoutSeconds: 30,
		RetryAttempts:  3,
		TLSVerify:      false,
	}

	rs, err := NewRemoteStorage(config)
	require.NoError(t, err)

	// Test health check
	err = rs.Health(context.Background())
	assert.NoError(t, err)
}

func TestRemoteStorage_Health_Error(t *testing.T) {
	// Create a test server that returns an error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		response := APIResponse{
			Success: false,
			Error: &APIError{
				Code:    "SERVICE_UNAVAILABLE",
				Message: "Service temporarily unavailable",
			},
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	// Create remote storage
	config := &Config{
		BaseURL:        server.URL,
		APIKey:         "test-key",
		TimeoutSeconds: 30,
		RetryAttempts:  3,
		TLSVerify:      false,
	}

	rs, err := NewRemoteStorage(config)
	require.NoError(t, err)

	// Test health check with error
	err = rs.Health(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "health check failed")
}
