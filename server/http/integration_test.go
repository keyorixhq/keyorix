package http

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// memDBSeq makes each in-memory test DB name unique.
var memDBSeq atomic.Int64

// uniqueMemDSN returns a uniquely-named shared-cache in-memory SQLite DSN. A fixed-name
// "file::memory:?cache=shared" is ONE database for the whole process, so tests that use
// it collide (e.g. one test's rows leak into another's), which makes them pass alone but
// fail when run together. A unique name per call isolates each test's DB while keeping it
// consistent across the connection pool. extra carries extra pragmas (e.g. "&_timeout=…").
func uniqueMemDSN(extra string) string {
	return fmt.Sprintf("file:kxtest_%d?mode=memory&cache=shared%s", memDBSeq.Add(1), extra)
}

// newTestCore creates a minimal *core.KeyorixCore backed by an in-memory SQLite DB.
func newTestCore(t *testing.T) *core.KeyorixCore {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(uniqueMemDSN("&_timeout=30000&_journal_mode=WAL")), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	err = db.AutoMigrate(
		&models.SecretNode{},
		&models.SecretVersion{},
		&models.User{},
		&models.Role{},
		&models.UserRole{},
		&models.Group{},
		&models.UserGroup{},
		&models.GroupRole{},
		&models.ShareRecord{},
		&models.AuditEvent{},
		&models.Session{},
		&models.Project{},
		&models.Project{},
		&models.Environment{},
		&models.Permission{},
		&models.RolePermission{},
		&models.LoginAttempt{},
		&models.PasswordHistory{},
		&models.PersonalAccessToken{},
	)
	require.NoError(t, err)
	return core.NewKeyorixCore(store.NewLocalStorage(db))
}

// createTestToken seeds the system and returns a real admin session token.
func createTestToken(t *testing.T, c *core.KeyorixCore) string {
	t.Helper()
	ctx := context.Background()
	// SeedSystem creates admin user, roles, permissions, project, environments
	c.SetBootstrapToken("test-bootstrap-token")
	_, err := c.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username: "testadmin",
		Email:    "testadmin@example.com",
		Password: "TestPassword123!",
		Token:    "test-bootstrap-token",
	})
	if err != nil {
		t.Logf("BootstrapSystem: %v (may already be initialised)", err)
	}
	session, _, err := c.Login(ctx, &core.LoginRequest{
		Username: "testadmin",
		Password: "TestPassword123!",
	})
	if err != nil {
		t.Fatalf("createTestToken: login failed: %v", err)
	}
	return session.SessionToken
}

// createLimitedToken creates a non-admin user and returns a valid session token.
// The user has only read permissions (no write/delete), so restricted endpoints return 403.
func createLimitedToken(t *testing.T, c *core.KeyorixCore) string {
	t.Helper()
	ctx := context.Background()
	_, err := c.CreateUser(ctx, &core.CreateUserRequest{
		Username: "limiteduser",
		Email:    "limited@example.com",
		Password: "Qr7#Kp2$Lm5@Vn9!",
	})
	if err != nil {
		t.Fatalf("createLimitedToken: create user failed: %v", err)
	}
	session, _, err := c.Login(ctx, &core.LoginRequest{
		Username: "limiteduser",
		Password: "Qr7#Kp2$Lm5@Vn9!",
	})
	if err != nil {
		t.Fatalf("createLimitedToken: login failed: %v", err)
	}
	return session.SessionToken
}

// Integration tests for the complete HTTP server
func TestHTTPServerIntegration(t *testing.T) {
	// Initialize i18n for testing
	err := i18n.InitializeForTesting()
	require.NoError(t, err)
	defer i18n.ResetForTesting()

	// Create test configuration
	cfg := &config.Config{
		Server: config.ServerConfig{
			HTTP: config.ServerInstanceConfig{
				Enabled:        true,
				Port:           "8080",
				SwaggerEnabled: true,
			},
		},
	}

	// One core backs both test servers — the workflow below uses `server` and `server2`
	// interchangeably with the same validToken, so they must share a database. (Each test
	// FUNCTION still gets its own isolated DB via newTestCore's unique DSN.)
	testCore := newTestCore(t)
	validToken := createTestToken(t, testCore)

	router, err := NewRouter(cfg, testCore)
	require.NoError(t, err)
	server := httptest.NewServer(router)
	defer server.Close()

	router2, err2 := NewRouter(cfg, testCore)
	require.NoError(t, err2)
	server2 := httptest.NewServer(router2)
	defer server2.Close()

	// Test cases for complete workflow
	t.Run("Complete Secret Management Workflow", func(t *testing.T) {
		client := &http.Client{Timeout: 10 * time.Second}
		baseURL := server2.URL

		// Step 1: Health check (no auth required)
		t.Run("Health Check", func(t *testing.T) {
			resp, err := client.Get(baseURL + "/health")
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

			var health map[string]interface{}
			err = json.NewDecoder(resp.Body).Decode(&health)
			require.NoError(t, err)

			assert.Equal(t, "healthy", health["status"])
			assert.Contains(t, health, "timestamp")
			assert.Contains(t, health, "uptime")
		})

		// Step 2: Try to access protected endpoint without auth (should fail)
		t.Run("Unauthorized Access", func(t *testing.T) {
			resp, err := client.Get(baseURL + "/api/v1/secrets")
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		})

		// Step 3: List secrets with valid auth
		var secretID uint
		t.Run("List Secrets", func(t *testing.T) {
			req, err := http.NewRequest("GET", baseURL+"/api/v1/secrets", nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+validToken)

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusOK, resp.StatusCode)

			var response map[string]interface{}
			err = json.NewDecoder(resp.Body).Decode(&response)
			require.NoError(t, err)

			assert.Contains(t, response, "data")
			if response["data"] == nil {
				t.Fatalf("expected data in response body, got nil. Full response: %v", response)
			}
			data := response["data"].(map[string]interface{})
			assert.Contains(t, data, "secrets")
			assert.Contains(t, data, "total")
		})

		// Step 4: Create a new secret
		t.Run("Create Secret", func(t *testing.T) {
			secretData := map[string]interface{}{
				"name":           "integration-test-secret",
				"value":          "super-secret-value",
				"project_id":     1,
				"environment_id": 1,
				"type":           "password",
				"metadata": map[string]string{
					"test":  "integration",
					"owner": "test-suite",
				},
				"tags": []string{"integration", "test", "automated"},
			}

			body, err := json.Marshal(secretData)
			require.NoError(t, err)

			req, err := http.NewRequest("POST", baseURL+"/api/v1/secrets", bytes.NewBuffer(body))
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+validToken)
			req.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusCreated, resp.StatusCode)

			var response map[string]interface{}
			err = json.NewDecoder(resp.Body).Decode(&response)
			require.NoError(t, err)

			assert.Contains(t, response, "data")
			assert.Contains(t, response, "message")

			if response["data"] == nil {
				t.Fatalf("expected data in response body, got nil. Full response: %v", response)
			}
			data := response["data"].(map[string]interface{})
			assert.Contains(t, data, "ID")
			assert.Equal(t, "integration-test-secret", data["Name"])

			// Store secret ID for later tests
			secretID = uint(data["ID"].(float64))
		})

		// Step 5: Get the created secret
		t.Run("Get Secret", func(t *testing.T) {
			req, err := http.NewRequest("GET", fmt.Sprintf("%s/api/v1/secrets/%d", baseURL, secretID), nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+validToken)

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusOK, resp.StatusCode)

			var response map[string]interface{}
			err = json.NewDecoder(resp.Body).Decode(&response)
			require.NoError(t, err)

			assert.Contains(t, response, "data")
			if response["data"] == nil {
				t.Fatalf("expected data in response body, got nil. Full response: %v", response)
			}
			data := response["data"].(map[string]interface{})
			assert.Equal(t, float64(secretID), data["ID"])
			assert.Equal(t, "integration-test-secret", data["Name"])
		})

		// Step 6: Update the secret
		t.Run("Update Secret", func(t *testing.T) {
			updateData := map[string]interface{}{
				"value": "updated-secret-value",
				"metadata": map[string]string{
					"test":       "integration",
					"owner":      "test-suite",
					"updated_by": "integration-test",
				},
			}

			body, err := json.Marshal(updateData)
			require.NoError(t, err)

			req, err := http.NewRequest("PUT", fmt.Sprintf("%s/api/v1/secrets/%d", baseURL, secretID), bytes.NewBuffer(body))
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+validToken)
			req.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusOK, resp.StatusCode)

			var response map[string]interface{}
			err = json.NewDecoder(resp.Body).Decode(&response)
			require.NoError(t, err)

			assert.Contains(t, response, "data")
			assert.Contains(t, response, "message")
		})

		// Step 7: Get secret versions
		t.Run("Get Secret Versions", func(t *testing.T) {
			req, err := http.NewRequest("GET", fmt.Sprintf("%s/api/v1/secrets/%d/versions", baseURL, secretID), nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+validToken)

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusOK, resp.StatusCode)

			var response map[string]interface{}
			err = json.NewDecoder(resp.Body).Decode(&response)
			require.NoError(t, err)

			assert.Contains(t, response, "data")
			data := response["data"].(map[string]interface{})
			assert.Contains(t, data, "versions")
		})

		// Step 8: Delete the secret
		t.Run("Delete Secret", func(t *testing.T) {
			req, err := http.NewRequest("DELETE", fmt.Sprintf("%s/api/v1/secrets/%d", baseURL, secretID), nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+validToken)

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusNoContent, resp.StatusCode)
		})

		// Step 9: Verify secret is deleted
		t.Run("Verify Secret Deleted", func(t *testing.T) {
			req, err := http.NewRequest("GET", fmt.Sprintf("%s/api/v1/secrets/%d", baseURL, secretID), nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+validToken)

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusNotFound, resp.StatusCode)
		})
	})

	// Test RBAC workflow
	t.Run("RBAC Management Workflow", func(t *testing.T) {
		client := &http.Client{Timeout: 10 * time.Second}
		baseURL := server.URL

		// Test user management
		t.Run("User Management", func(t *testing.T) {
			// List users
			req, err := http.NewRequest("GET", baseURL+"/api/v1/users", nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+validToken)

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusOK, resp.StatusCode)

			// Create user
			userData := map[string]interface{}{
				"username":     "integration-user",
				"email":        "integration@test.com",
				"display_name": "Integration Test User",
				"password":     "Qr7#Kp2$Lm5@Vn9!",
			}

			body, err := json.Marshal(userData)
			require.NoError(t, err)

			req, err = http.NewRequest("POST", baseURL+"/api/v1/users", bytes.NewBuffer(body))
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+validToken)
			req.Header.Set("Content-Type", "application/json")

			resp, err = client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusCreated, resp.StatusCode)
		})

		// Test role management
		t.Run("Role Management", func(t *testing.T) {
			// List roles
			req, err := http.NewRequest("GET", baseURL+"/api/v1/roles", nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+validToken)

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusOK, resp.StatusCode)

			// Create role
			roleData := map[string]interface{}{
				"name":        "integration-role",
				"description": "Role created by integration test",
				"permissions": []string{"secrets.read", "users.read"},
			}

			body, err := json.Marshal(roleData)
			require.NoError(t, err)

			req, err = http.NewRequest("POST", baseURL+"/api/v1/roles", bytes.NewBuffer(body))
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+validToken)
			req.Header.Set("Content-Type", "application/json")

			resp, err = client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusCreated, resp.StatusCode)
		})
	})

	// Test system endpoints
	t.Run("System Information", func(t *testing.T) {
		client := &http.Client{Timeout: 10 * time.Second}
		baseURL := server.URL

		// Get system info
		t.Run("System Info", func(t *testing.T) {
			req, err := http.NewRequest("GET", baseURL+"/api/v1/system/info", nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+validToken)

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusOK, resp.StatusCode)

			var response map[string]interface{}
			err = json.NewDecoder(resp.Body).Decode(&response)
			require.NoError(t, err)

			assert.Contains(t, response, "data")
			data := response["data"].(map[string]interface{})
			assert.Contains(t, data, "version")
			assert.Contains(t, data, "go_version")
			assert.Contains(t, data, "features")
		})

		// Get metrics
		t.Run("System Metrics", func(t *testing.T) {
			req, err := http.NewRequest("GET", baseURL+"/api/v1/system/metrics", nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+validToken)

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusOK, resp.StatusCode)

			var response map[string]interface{}
			err = json.NewDecoder(resp.Body).Decode(&response)
			require.NoError(t, err)

			assert.Contains(t, response, "data")
			data := response["data"].(map[string]interface{})
			assert.Contains(t, data, "memory")
			assert.Contains(t, data, "goroutines")
			assert.Contains(t, data, "gc")
		})
	})

	// Test audit endpoints
	t.Run("Audit Logs", func(t *testing.T) {
		client := &http.Client{Timeout: 10 * time.Second}
		baseURL := server.URL

		// Get audit logs
		t.Run("General Audit Logs", func(t *testing.T) {
			req, err := http.NewRequest("GET", baseURL+"/api/v1/audit/logs", nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+validToken)

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusOK, resp.StatusCode)

			var response map[string]interface{}
			err = json.NewDecoder(resp.Body).Decode(&response)
			require.NoError(t, err)

			assert.Contains(t, response, "data")
			data := response["data"].(map[string]interface{})
			assert.Contains(t, data, "logs")
			assert.Contains(t, data, "total")
		})

		// Get RBAC audit logs
		t.Run("RBAC Audit Logs", func(t *testing.T) {
			req, err := http.NewRequest("GET", baseURL+"/api/v1/audit/rbac-logs", nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+validToken)

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusOK, resp.StatusCode)

			var response map[string]interface{}
			err = json.NewDecoder(resp.Body).Decode(&response)
			require.NoError(t, err)

			assert.Contains(t, response, "data")
			data := response["data"].(map[string]interface{})
			assert.Contains(t, data, "logs")
			assert.Contains(t, data, "total")
		})
	})
}

// Test error scenarios
func TestHTTPServerErrorScenarios(t *testing.T) {
	// Initialize i18n for testing
	err := i18n.InitializeForTesting()
	require.NoError(t, err)
	defer i18n.ResetForTesting()

	cfg := &config.Config{
		Server: config.ServerConfig{
			HTTP: config.ServerInstanceConfig{
				Enabled: true,
				Port:    "8080",
			},
		},
	}

	testCore2 := newTestCore(t)
	router, err := NewRouter(cfg, testCore2)
	require.NoError(t, err)

	server := httptest.NewServer(router)
	defer server.Close()
	validToken := createTestToken(t, testCore2)
	limitedToken := createLimitedToken(t, testCore2)
	client := &http.Client{Timeout: 5 * time.Second}
	baseURL := server.URL

	t.Run("Authentication Errors", func(t *testing.T) {
		// Missing authorization header
		resp, err := client.Get(baseURL + "/api/v1/secrets")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

		// Invalid token
		req, err := http.NewRequest("GET", baseURL+"/api/v1/secrets", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer invalid-token")

		resp, err = client.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

		// Malformed authorization header
		req, err = http.NewRequest("GET", baseURL+"/api/v1/secrets", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "InvalidFormat token")

		resp, err = client.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("Authorization Errors", func(t *testing.T) {
		// Test user trying to delete (insufficient permissions)
		req, err := http.NewRequest("DELETE", baseURL+"/api/v1/secrets/1", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+limitedToken) // limited user lacks delete permission

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("Validation Errors", func(t *testing.T) {
		// Invalid JSON
		req, err := http.NewRequest("POST", baseURL+"/api/v1/secrets", bytes.NewBufferString("{invalid json}"))
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+validToken)
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

		// Missing required fields
		invalidSecret := map[string]interface{}{
			"name":  "", // empty name
			"value": "test",
		}

		body, err := json.Marshal(invalidSecret)
		require.NoError(t, err)

		req, err = http.NewRequest("POST", baseURL+"/api/v1/secrets", bytes.NewBuffer(body))
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+validToken)
		req.Header.Set("Content-Type", "application/json")

		resp, err = client.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("Not Found Errors", func(t *testing.T) {
		// Non-existent secret
		req, err := http.NewRequest("GET", baseURL+"/api/v1/secrets/99999", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+validToken)

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)

		// Non-existent endpoint
		req, err = http.NewRequest("GET", baseURL+"/api/v1/nonexistent", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+validToken)

		resp, err = client.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})
}

// The legacy admin-managed "service accounts" (APIClient/APIToken) issuance and
// management routes were removed (finding #131): the credentials they minted were
// never accepted by any authentication path, making them a dead, unscannable
// credential type. This locks in the removal — an accidental re-registration of
// the route without also wiring a real authentication consumer must fail this test.
func TestServiceAccountRoutesRemoved(t *testing.T) {
	err := i18n.InitializeForTesting()
	require.NoError(t, err)
	defer i18n.ResetForTesting()

	cfg := &config.Config{
		Server: config.ServerConfig{
			HTTP: config.ServerInstanceConfig{Enabled: true, Port: "8080"},
		},
	}
	testCore := newTestCore(t)
	router, err := NewRouter(cfg, testCore)
	require.NoError(t, err)

	server := httptest.NewServer(router)
	defer server.Close()
	validToken := createTestToken(t, testCore)
	client := &http.Client{Timeout: 5 * time.Second}

	for _, tc := range []struct {
		method, path string
	}{
		{"GET", "/api/v1/service-accounts"},
		{"POST", "/api/v1/service-accounts"},
		{"GET", "/api/v1/service-accounts/kx-client-deadbeef"},
		{"GET", "/api/v1/service-accounts/kx-client-deadbeef/tokens"},
		{"POST", "/api/v1/service-accounts/kx-client-deadbeef/tokens"},
	} {
		req, err := http.NewRequest(tc.method, server.URL+tc.path, nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+validToken)
		resp, err := client.Do(req)
		require.NoError(t, err)
		_ = resp.Body.Close()
		assert.Equalf(t, http.StatusNotFound, resp.StatusCode,
			"%s %s: the service-accounts issuance/management routes must stay removed", tc.method, tc.path)
	}
}

// Performance and load testing
func TestHTTPServerPerformance(t *testing.T) {
	// Initialize i18n for testing
	err := i18n.InitializeForTesting()
	require.NoError(t, err)
	defer i18n.ResetForTesting()

	cfg := &config.Config{
		Server: config.ServerConfig{
			HTTP: config.ServerInstanceConfig{
				Enabled: true,
				Port:    "8080",
			},
		},
	}

	router, err := NewRouter(cfg, newTestCore(t))
	require.NoError(t, err)

	server := httptest.NewServer(router)
	defer server.Close()

	t.Run("Concurrent Requests", func(t *testing.T) {
		const numGoroutines = 50
		const requestsPerGoroutine = 10

		results := make(chan int, numGoroutines*requestsPerGoroutine)

		for i := 0; i < numGoroutines; i++ {
			go func() {
				client := &http.Client{Timeout: 10 * time.Second}
				for j := 0; j < requestsPerGoroutine; j++ {
					req, err := http.NewRequest("GET", server.URL+"/health", nil)
					if err != nil {
						results <- 0
						continue
					}

					resp, err := client.Do(req)
					if err != nil {
						results <- 0
						continue
					}
					_ = resp.Body.Close()
					results <- resp.StatusCode
				}
			}()
		}

		successCount := 0
		for i := 0; i < numGoroutines*requestsPerGoroutine; i++ {
			code := <-results
			if code == http.StatusOK {
				successCount++
			}
		}

		// At least 95% success rate
		expectedMinSuccess := int(float64(numGoroutines*requestsPerGoroutine) * 0.95)
		assert.GreaterOrEqual(t, successCount, expectedMinSuccess)
	})

	t.Run("Response Time", func(t *testing.T) {
		client := &http.Client{Timeout: 10 * time.Second}

		// Measure response time for health check
		start := time.Now()
		resp, err := client.Get(server.URL + "/health")
		duration := time.Since(start)

		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Less(t, duration, 100*time.Millisecond) // Should respond within 100ms
	})
}

// TestPrivescRoutesRequireWrite is a regression test for the route-authorization
// audit: mutating /users and /groups routes must NOT be reachable with only the
// group-level users.read (held by the read-only system_auditor / system_viewer
// personas). Before the fix these inherited users.read and let a read-only caller
// edit/delete users and manage group membership (which confers the group's roles).
// The middleware gate runs before the handler, so a non-existent target still 403s.
func TestPrivescRoutesRequireWrite(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	cfg := &config.Config{Server: config.ServerConfig{HTTP: config.ServerInstanceConfig{Enabled: true, Port: "8080"}}}
	testCore := newTestCore(t)
	router, err := NewRouter(cfg, testCore)
	require.NoError(t, err)
	server := httptest.NewServer(router)
	defer server.Close()

	createTestToken(t, testCore) // bootstrap admin + seed roles
	// Create a uniquely-named read-only user (the shared-cache in-memory DB means a
	// fixed username from createLimitedToken can collide with other tests). New
	// users get system_viewer, which holds users.read but not users.write.
	ctx := context.Background()
	_, err = testCore.CreateUser(ctx, &core.CreateUserRequest{
		Username: "privesc_ro", Email: "privesc_ro@example.com", Password: "Qr7#Kp2$Lm5@Vn9!",
	})
	require.NoError(t, err)
	sess, _, err := testCore.Login(ctx, &core.LoginRequest{Username: "privesc_ro", Password: "Qr7#Kp2$Lm5@Vn9!"})
	require.NoError(t, err)
	limited := sess.SessionToken

	cases := []struct{ method, path string }{
		{http.MethodPut, "/api/v1/users/1"},
		{http.MethodDelete, "/api/v1/users/1"},
		{http.MethodPost, "/api/v1/users/1/restore"},
		{http.MethodPost, "/api/v1/groups"},
		{http.MethodPut, "/api/v1/groups/1"},
		{http.MethodDelete, "/api/v1/groups/1"},
		{http.MethodPost, "/api/v1/groups/1/members"},
		{http.MethodDelete, "/api/v1/groups/1/members/2"},
	}
	client := &http.Client{Timeout: 10 * time.Second}
	for _, tc := range cases {
		req, err := http.NewRequest(tc.method, server.URL+tc.path, bytes.NewReader([]byte("{}")))
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+limited)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		require.NoError(t, err)
		_ = resp.Body.Close()
		assert.Equalf(t, http.StatusForbidden, resp.StatusCode,
			"%s %s must be 403 for a users.read-only caller (privesc gate)", tc.method, tc.path)
	}
}

var routeParamRe = regexp.MustCompile(`\{[^}]+\}`)

// TestEveryMutatingRouteDeniesReadOnly is a preventive guard for the route-
// authorization privesc class (the root cause of #134/#135/#136): it walks the
// entire router and asserts that a read-only persona (system_viewer:
// users.read/secrets.read) cannot SUCCEED at any mutating route (POST/PUT/PATCH/
// DELETE) — the gate must deny it (non-2xx). Self-service and public routes a
// read-only/unauthenticated caller may legitimately reach are allowlisted. A new
// mutating route added without a write/scoped gate fails this test.
func TestEveryMutatingRouteDeniesReadOnly(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	cfg := &config.Config{Server: config.ServerConfig{HTTP: config.ServerInstanceConfig{Enabled: true, Port: "8080"}}}
	testCore := newTestCore(t)
	handler, err := NewRouter(cfg, testCore)
	require.NoError(t, err)
	routes, ok := handler.(chi.Routes)
	require.True(t, ok, "router must expose chi.Routes for walking")

	createTestToken(t, testCore) // bootstrap admin + seed roles
	// A default new user gets system_viewer (users.read + secrets.read) — a
	// read-only persona that must not be able to mutate anything.
	ctx := context.Background()
	_, err = testCore.CreateUser(ctx, &core.CreateUserRequest{
		Username: "ro_guard", Email: "ro_guard@example.com", Password: "Qr7#Kp2$Lm5@Vn9!",
	})
	require.NoError(t, err)
	sess, _, err := testCore.Login(ctx, &core.LoginRequest{Username: "ro_guard", Password: "Qr7#Kp2$Lm5@Vn9!"})
	require.NoError(t, err)
	roToken := sess.SessionToken

	server := httptest.NewServer(handler)
	defer server.Close()
	client := &http.Client{Timeout: 10 * time.Second}

	mutating := map[string]bool{
		http.MethodPost: true, http.MethodPut: true, http.MethodPatch: true, http.MethodDelete: true,
	}
	// Self-service (own account) and public routes a read-only/unauthenticated
	// caller may legitimately reach; everything else mutating must be denied.
	// /secrets/render is a READ operation behind a POST (it only carries a payload; it
	// mutates nothing and is gated on a *.read permission) — legitimately reachable by a
	// read-only persona, like /system/init. (/compliance/evidence/verify is a POST too,
	// but it is gated on audit.read which system_viewer lacks, so it is correctly DENIED
	// and not exempted here.) /sw.js is the SPA service-worker static asset, served by the
	// web handler for any method; serving the file for DELETE/PUT/etc. changes no state,
	// so it's not an API mutation. These are the only exemptions; any other mutating route
	// MUST be denied.
	allowExact := map[string]bool{
		"/system/init": true, "/health": true, "/metrics": true,
		"/api/v1/projects/{id}/secrets/render": true,
		"/sw.js":                               true, // static service-worker asset, not an API route
	}
	allowPrefix := []string{"/auth/", "/api/v1/auth/", "/notifications", "/api/v1/notifications"}
	allowed := func(route string) bool {
		if allowExact[route] {
			return true
		}
		for _, p := range allowPrefix {
			if strings.HasPrefix(route, p) {
				return true
			}
		}
		return false
	}

	var checked int
	walkErr := chi.Walk(routes, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if !mutating[method] || allowed(route) {
			return nil
		}
		path := routeParamRe.ReplaceAllString(route, "1") // {id} -> 1
		req, rerr := http.NewRequest(method, server.URL+path, bytes.NewReader([]byte("{}")))
		require.NoError(t, rerr)
		req.Header.Set("Authorization", "Bearer "+roToken)
		req.Header.Set("Content-Type", "application/json")
		resp, derr := client.Do(req)
		require.NoError(t, derr)
		code := resp.StatusCode
		_ = resp.Body.Close()
		// A read-only persona must never SUCCEED at a mutation. 2xx = the gate let
		// it through (missing users.write / roles.assign / scoped check).
		assert.NotContainsf(t, []int{200, 201, 202, 204}, code,
			"read-only persona succeeded at %s %s (HTTP %d) — missing write/scoped authorization gate", method, route, code)
		checked++
		return nil
	})
	require.NoError(t, walkErr)
	assert.Greater(t, checked, 25, "sanity: the walk should cover many mutating routes")
}
