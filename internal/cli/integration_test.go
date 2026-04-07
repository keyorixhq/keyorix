package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/remote"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// InitializeCoreService initializes a core service for testing
func InitializeCoreService() (*core.KeyorixCore, error) {
	// Load configuration
	cfg, err := config.Load("keyorix.yaml")
	if err != nil {
		return nil, err
	}

	// Create storage using factory
	factory := storage.NewStorageFactory()
	storageImpl, err := factory.CreateStorage(cfg)
	if err != nil {
		return nil, err
	}

	// Create core service
	return core.NewKeyorixCore(storageImpl), nil
}

func TestRemoteCLIIntegration(t *testing.T) {
	// Create a temporary directory for test configuration
	tempDir, err := os.MkdirTemp("", "keyorix-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Change to temp directory for test
	oldWd, _ := os.Getwd()
	os.Chdir(tempDir)
	defer os.Chdir(oldWd)

	// Create a mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/health":
			response := remote.APIResponse{
				Success: true,
				Data:    json.RawMessage(`{"status": "healthy"}`),
			}
			json.NewEncoder(w).Encode(response)
		case "/api/v1/secrets":
			if r.Method == "GET" {
				response := remote.APIResponse{
					Success: true,
					Data: json.RawMessage(`{
						"secrets": [],
						"total": 0
					}`),
				}
				json.NewEncoder(w).Encode(response)
			} else if r.Method == "POST" {
				response := remote.APIResponse{
					Success: true,
					Data:    json.RawMessage(`{"id": 1, "name": "test-secret", "type": "password"}`),
				}
				json.NewEncoder(w).Encode(response)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Create test configuration
	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type: "remote",
			Remote: &config.RemoteConfig{
				BaseURL:        server.URL,
				APIKey:         "test-api-key",
				TimeoutSeconds: 30,
				RetryAttempts:  3,
				TLSVerify:      false,
			},
		},
	}

	// Save configuration
	err = config.Save("keyorix.yaml", cfg)
	require.NoError(t, err)

	// Test CLI initialization with remote storage
	service, err := InitializeCoreService()
	require.NoError(t, err)
	assert.NotNil(t, service)

	// Test health check
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = service.HealthCheck(ctx)
	assert.NoError(t, err)
}

func TestLocalToRemoteSwitching(t *testing.T) {
	// Create a temporary directory for test configuration
	tempDir, err := os.MkdirTemp("", "keyorix-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Change to temp directory for test
	oldWd, _ := os.Getwd()
	os.Chdir(tempDir)
	defer os.Chdir(oldWd)

	// Start with local configuration
	localCfg := &config.Config{
		Storage: config.StorageConfig{
			Type: "local",
			Database: config.DatabaseConfig{
				Path: "./test-secrets.db",
			},
		},
	}

	err = config.Save("keyorix.yaml", localCfg)
	require.NoError(t, err)

	// Test local initialization
	service1, err := InitializeCoreService()
	require.NoError(t, err)
	assert.NotNil(t, service1)

	// Create a mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := remote.APIResponse{
			Success: true,
			Data:    json.RawMessage(`{"status": "healthy"}`),
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	// Switch to remote configuration
	remoteCfg := &config.Config{
		Storage: config.StorageConfig{
			Type: "remote",
			Remote: &config.RemoteConfig{
				BaseURL:        server.URL,
				APIKey:         "test-api-key",
				TimeoutSeconds: 30,
				RetryAttempts:  3,
				TLSVerify:      false,
			},
		},
	}

	err = config.Save("keyorix.yaml", remoteCfg)
	require.NoError(t, err)

	// Test remote initialization
	service2, err := InitializeCoreService()
	require.NoError(t, err)
	assert.NotNil(t, service2)

	// Test health check on remote service
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = service2.HealthCheck(ctx)
	assert.NoError(t, err)
}

func TestConfigurationPersistence(t *testing.T) {
	// Create a temporary directory for test configuration
	tempDir, err := os.MkdirTemp("", "keyorix-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Change to temp directory for test
	oldWd, _ := os.Getwd()
	os.Chdir(tempDir)
	defer os.Chdir(oldWd)

	// Create and save configuration
	originalCfg := &config.Config{
		Storage: config.StorageConfig{
			Type: "remote",
			Remote: &config.RemoteConfig{
				BaseURL:        "https://api.example.com",
				APIKey:         "test-key-123",
				TimeoutSeconds: 45,
				RetryAttempts:  5,
				TLSVerify:      true,
			},
		},
	}

	err = config.Save("keyorix.yaml", originalCfg)
	require.NoError(t, err)

	// Verify file exists
	_, err = os.Stat("keyorix.yaml")
	assert.NoError(t, err)

	// Load configuration back
	loadedCfg, err := config.Load("keyorix.yaml")
	require.NoError(t, err)

	// Verify configuration matches
	assert.Equal(t, "remote", loadedCfg.Storage.Type)
	assert.NotNil(t, loadedCfg.Storage.Remote)
	assert.Equal(t, "https://api.example.com", loadedCfg.Storage.Remote.BaseURL)
	assert.Equal(t, "test-key-123", loadedCfg.Storage.Remote.APIKey)
	assert.Equal(t, 45, loadedCfg.Storage.Remote.TimeoutSeconds)
	assert.Equal(t, 5, loadedCfg.Storage.Remote.RetryAttempts)
	assert.True(t, loadedCfg.Storage.Remote.TLSVerify)
}

func TestErrorHandling(t *testing.T) {
	// Create a temporary directory for test configuration
	tempDir, err := os.MkdirTemp("", "keyorix-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Change to temp directory for test
	oldWd, _ := os.Getwd()
	os.Chdir(tempDir)
	defer os.Chdir(oldWd)

	// Test with invalid remote configuration
	invalidCfg := &config.Config{
		Storage: config.StorageConfig{
			Type:   "remote",
			Remote: &config.RemoteConfig{
				// Missing required fields
			},
		},
	}

	err = config.Save("keyorix.yaml", invalidCfg)
	require.NoError(t, err)

	// This should fail due to invalid configuration
	_, err = InitializeCoreService()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "base_url is required")
}

func TestEnvironmentVariableSupport(t *testing.T) {
	// Create a temporary directory for test configuration
	tempDir, err := os.MkdirTemp("", "keyorix-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Change to temp directory for test
	oldWd, _ := os.Getwd()
	os.Chdir(tempDir)
	defer os.Chdir(oldWd)

	// Set environment variable
	os.Setenv("TEST_API_KEY", "env-api-key-123")
	defer os.Unsetenv("TEST_API_KEY")

	// Create configuration with environment variable reference
	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type: "remote",
			Remote: &config.RemoteConfig{
				BaseURL:        "https://api.example.com",
				APIKey:         "${TEST_API_KEY}",
				TimeoutSeconds: 30,
				RetryAttempts:  3,
				TLSVerify:      true,
			},
		},
	}

	err = config.Save("keyorix.yaml", cfg)
	require.NoError(t, err)

	// Load and verify environment variable expansion
	loadedCfg, err := config.Load("keyorix.yaml")
	require.NoError(t, err)

	// The API key should still be the template in the loaded config
	assert.Equal(t, "${TEST_API_KEY}", loadedCfg.Storage.Remote.APIKey)

	// But when creating the remote config, it should be expanded
	remoteConfig := &remote.Config{
		BaseURL:        loadedCfg.Storage.Remote.BaseURL,
		APIKey:         loadedCfg.Storage.Remote.APIKey,
		TimeoutSeconds: loadedCfg.Storage.Remote.TimeoutSeconds,
		RetryAttempts:  loadedCfg.Storage.Remote.RetryAttempts,
		TLSVerify:      loadedCfg.Storage.Remote.TLSVerify,
	}

	err = remoteConfig.Validate()
	require.NoError(t, err)

	// After validation, the API key should be expanded
	assert.Equal(t, "env-api-key-123", remoteConfig.GetAPIKeyFromEnv())
}
