package http

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
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
	// models.AllTestModels() is the single source of truth for the test schema —
	// add new models there (internal/storage/models/all_models.go), not here.
	err = db.AutoMigrate(models.AllTestModels()...)
	require.NoError(t, err)
	// Mirror internal/storage/factory.go's ensureProjectMembershipIndex exactly (the
	// same production migration path #309's TestConcurrency_InviteMember_
	// NoDuplicateActiveMembership relies on, internal/core/concurrency_invite_member_test.go):
	// AutoMigrate alone does not create this partial unique index, so without it, the
	// #511 project-membership-proxy tests exercising the "duplicate active membership"
	// path would silently miss the real DB-level guard CreateProjectMembership's
	// isUniqueViolation branch depends on.
	require.NoError(t, db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS uniq_project_memberships_active "+
		"ON project_memberships (project_id, user_id) WHERE state <> 'revoked'").Error)
	// Mirror internal/storage/factory.go's ensureLegalHoldActiveIndex exactly: without
	// this partial unique index, the legal-hold-proxy test exercising the
	// "already active" rejection path would silently miss the real DB-level guard
	// CreateLegalHold's isUniqueConstraintErr branch depends on.
	require.NoError(t, db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS uniq_legal_holds_active "+
		"ON legal_holds (released) WHERE released = false").Error)
	// Mirror internal/storage/factory.go's ensureBreakGlassActiveIndex exactly (the
	// same production migration path TestCreateBreakGlassActivation_
	// ConcurrentRaceYieldsExactlyOneWinner relies on,
	// internal/storage/store/local_break_glass_test.go): AutoMigrate alone does not
	// create this partial unique index, so without it, the #519 break-glass-proxy
	// concurrent-activation test would silently miss the real DB-level guard
	// CreateBreakGlassActivation's OnConflict DoNothing branch depends on.
	require.NoError(t, db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS uniq_break_glass_active_project_user "+
		"ON break_glass_activations (project_id, user_id) WHERE state = 'active'").Error)
	require.NoError(t, db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS uniq_users_email_active "+
		"ON users (LOWER(email)) WHERE deleted_at IS NULL AND email <> ''").Error)
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

// createNodeToken mints a #G79 node-type machine-identity bearer token — the
// credential RequireNodeCredential (server/middleware/node_credential.go) now requires
// to reach the /api/v1/system/* RemoteStorage-sync proxy tree. Bootstraps the system
// (via createTestToken) to get an admin actor authorized to create the identity and
// issue its token; only the node token is returned; the admin session itself no longer
// has any special access to the proxy tree, matching production (no role, including
// admin, grants node status).
func createNodeToken(t *testing.T, c *core.KeyorixCore) string {
	t.Helper()
	ctx := context.Background()
	_ = createTestToken(t, c) // bootstraps admin user/roles/project as a side effect
	admin, err := c.GetUserByEmail(ctx, "testadmin@example.com")
	require.NoError(t, err)
	projects, err := c.Storage().ListProjects(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, projects, "createTestToken must have seeded a default project")
	mi, err := c.CreateMachineIdentity(ctx, projects[0].ID, "test-node", core.MachineTypeNode, "test node credential", "", admin.ID)
	require.NoError(t, err)
	result, err := c.IssueMachineToken(ctx, projects[0].ID, mi.ID, admin.ID, core.IssueMachineTokenParams{Name: "test-node-token"})
	require.NoError(t, err)
	return result.PlainToken
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
	// so it's not an API mutation. POST .../access-requests and .../access-requests/
	// {requestId}/withdraw are deliberately self-service (router.go: CreateAccessRequest/
	// WithdrawAccessRequest carry no permission gate by design — any authenticated project
	// member may request access to a role, or withdraw their own pending request; only the
	// approve/reject step, ResolveAccessRequest, is gated on roles.assign). These are the
	// only exemptions; any other mutating route MUST be denied.
	allowExact := map[string]bool{
		"/system/init": true, "/health": true, "/metrics": true,
		"/api/v1/projects/{id}/secrets/render":  true,
		"/sw.js":                                true, // static service-worker asset, not an API route
		"/api/v1/projects/{id}/access-requests": true, // self-service create
		"/api/v1/projects/{id}/access-requests/{requestId}/withdraw": true, // self-service withdraw
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

// ── Phase 1 auth-cookie migration ──────────────────────────────────────────────

// newCookieClient returns an *http.Client with its own cookie jar scoped to
// baseURL, so cookies set by one request (e.g. login) are automatically sent on
// subsequent requests through this client — exactly how a browser behaves.
func newCookieClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	return &http.Client{Jar: jar, Timeout: 5 * time.Second}
}

// loginViaHTTP performs a real POST /auth/login and returns the response (body
// not yet closed — the caller must close it) so tests can inspect both the
// Set-Cookie headers and the JSON body.
func loginViaHTTP(t *testing.T, client *http.Client, baseURL, username, password string) *http.Response {
	t.Helper()
	body, err := json.Marshal(map[string]string{"username": username, "password": password})
	require.NoError(t, err)
	resp, err := client.Post(baseURL+"/auth/login", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	return resp
}

// csrfCookieValue reads the csrf_token cookie the jar picked up for baseURL —
// standing in for the SPA reading document.cookie to echo it back as a header.
func csrfCookieValue(t *testing.T, client *http.Client, baseURL string) string {
	t.Helper()
	u, err := url.Parse(baseURL)
	require.NoError(t, err)
	for _, c := range client.Jar.Cookies(u) {
		if c.Name == "csrf_token" {
			return c.Value
		}
	}
	return ""
}

func TestCookieAuth_LoginSetsCookiesAndDualModeWorks(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	cfg := &config.Config{Server: config.ServerConfig{HTTP: config.ServerInstanceConfig{Enabled: true, Port: "8080"}}}
	testCore := newTestCore(t)
	_ = createTestToken(t, testCore) // seeds testadmin/TestPassword123!

	router, err := NewRouter(cfg, testCore)
	require.NoError(t, err)
	server := httptest.NewServer(router)
	defer server.Close()

	client := newCookieClient(t)
	resp := loginViaHTTP(t, client, server.URL, "testadmin", "TestPassword123!")
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var sessionCookie, csrfCookie *http.Cookie
	for _, c := range resp.Cookies() {
		switch c.Name {
		case "kx_session":
			sessionCookie = c
		case "csrf_token":
			csrfCookie = c
		}
	}
	require.NotNil(t, sessionCookie, "login must set the session cookie")
	require.NotNil(t, csrfCookie, "login must set the CSRF cookie")
	assert.True(t, sessionCookie.HttpOnly, "session cookie must be HttpOnly")
	assert.False(t, csrfCookie.HttpOnly, "CSRF cookie must be readable by JS")
	assert.Equal(t, http.SameSiteLaxMode, sessionCookie.SameSite)

	var loginBody struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&loginBody))
	require.NotEmpty(t, loginBody.Data.Token, "Phase A keeps the token in the JSON body for dual-mode")

	t.Run("cookie-only auth works with no Authorization header", func(t *testing.T) {
		profResp, err := client.Get(server.URL + "/api/v1/auth/profile")
		require.NoError(t, err)
		defer func() { _ = profResp.Body.Close() }()
		assert.Equal(t, http.StatusOK, profResp.StatusCode)
	})

	t.Run("Bearer-only still works with no cookie (dual-mode)", func(t *testing.T) {
		bareClient := &http.Client{Timeout: 5 * time.Second} // no cookie jar
		req, err := http.NewRequest(http.MethodGet, server.URL+"/api/v1/auth/profile", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+loginBody.Data.Token)
		profResp, err := bareClient.Do(req)
		require.NoError(t, err)
		defer func() { _ = profResp.Body.Close() }()
		assert.Equal(t, http.StatusOK, profResp.StatusCode)
	})

	t.Run("cookie takes precedence when both cookie and a stale Bearer header are present", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, server.URL+"/api/v1/auth/profile", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer this-is-not-a-real-token")
		for _, c := range client.Jar.Cookies(mustParseURL(t, server.URL)) {
			req.AddCookie(c)
		}
		profResp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
		require.NoError(t, err)
		defer func() { _ = profResp.Body.Close() }()
		assert.Equal(t, http.StatusOK, profResp.StatusCode, "the valid cookie must win over the garbage Bearer header")
	})
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	require.NoError(t, err)
	return u
}

func TestCSRF_RequiredForCookieAuthenticatedMutations(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	cfg := &config.Config{Server: config.ServerConfig{HTTP: config.ServerInstanceConfig{Enabled: true, Port: "8080"}}}
	testCore := newTestCore(t)
	_ = createTestToken(t, testCore)

	router, err := NewRouter(cfg, testCore)
	require.NoError(t, err)
	server := httptest.NewServer(router)
	defer server.Close()

	client := newCookieClient(t)
	resp := loginViaHTTP(t, client, server.URL, "testadmin", "TestPassword123!")
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	profileUpdate := func() *http.Request {
		body, _ := json.Marshal(map[string]string{"display_name": "Test Admin", "email": "testadmin@example.com"})
		req, err := http.NewRequest(http.MethodPut, server.URL+"/api/v1/auth/profile", bytes.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		return req
	}

	t.Run("rejected with no CSRF header", func(t *testing.T) {
		r, err := client.Do(profileUpdate())
		require.NoError(t, err)
		defer func() { _ = r.Body.Close() }()
		assert.Equal(t, http.StatusForbidden, r.StatusCode)
	})

	t.Run("rejected with a wrong CSRF header", func(t *testing.T) {
		req := profileUpdate()
		req.Header.Set("X-CSRF-Token", "not-the-right-value")
		r, err := client.Do(req)
		require.NoError(t, err)
		defer func() { _ = r.Body.Close() }()
		assert.Equal(t, http.StatusForbidden, r.StatusCode)
	})

	t.Run("accepted with the matching CSRF header", func(t *testing.T) {
		req := profileUpdate()
		req.Header.Set("X-CSRF-Token", csrfCookieValue(t, client, server.URL))
		r, err := client.Do(req)
		require.NoError(t, err)
		defer func() { _ = r.Body.Close() }()
		assert.Equal(t, http.StatusOK, r.StatusCode)
	})

	t.Run("Bearer-only requests are exempt from CSRF (no cookie at all)", func(t *testing.T) {
		var loginBody struct {
			Data struct{ Token string } `json:"data"`
		}
		resp2 := loginViaHTTP(t, &http.Client{Timeout: 5 * time.Second}, server.URL, "testadmin", "TestPassword123!")
		defer func() { _ = resp2.Body.Close() }()
		require.NoError(t, json.NewDecoder(resp2.Body).Decode(&loginBody))

		req := profileUpdate()
		req.Header.Set("Authorization", "Bearer "+loginBody.Data.Token)
		// Deliberately no X-CSRF-Token — must still succeed, no cookie means CSRF doesn't apply.
		bareClient := &http.Client{Timeout: 5 * time.Second}
		r, err := bareClient.Do(req)
		require.NoError(t, err)
		defer func() { _ = r.Body.Close() }()
		assert.Equal(t, http.StatusOK, r.StatusCode)
	})
}

// TestImpersonationRoundTrip_CookieSwapAndRestore is the end-to-end proof for
// the impersonation redesign: the client never sees or holds an admin token at
// any point — starting impersonation swaps the cookie to the target's session,
// and ending it restores the ADMIN'S ORIGINAL session value (not a fresh one),
// purely via the server-side OriginalSessionID linkage.
func TestImpersonationRoundTrip_CookieSwapAndRestore(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	cfg := &config.Config{Server: config.ServerConfig{HTTP: config.ServerInstanceConfig{Enabled: true, Port: "8080"}}}
	testCore := newTestCore(t)
	_ = createTestToken(t, testCore) // seeds testadmin (admin role) /TestPassword123!

	ctx := context.Background()
	targetUser, err := testCore.CreateUser(ctx, &core.CreateUserRequest{
		Username: "target", Email: "target@example.com", Password: "CorrectHorseBattery9!",
	})
	require.NoError(t, err)

	router, err := NewRouter(cfg, testCore)
	require.NoError(t, err)
	server := httptest.NewServer(router)
	defer server.Close()

	client := newCookieClient(t)
	loginResp := loginViaHTTP(t, client, server.URL, "testadmin", "TestPassword123!")
	_ = loginResp.Body.Close()
	require.Equal(t, http.StatusOK, loginResp.StatusCode)

	adminSessionCookie := func() string {
		for _, c := range client.Jar.Cookies(mustParseURL(t, server.URL)) {
			if c.Name == "kx_session" {
				return c.Value
			}
		}
		return ""
	}
	originalAdminCookie := adminSessionCookie()
	require.NotEmpty(t, originalAdminCookie)

	type profileResult struct {
		Username      string `json:"username"`
		Impersonation *struct {
			AdminUsername string `json:"admin_username"`
		} `json:"impersonation"`
	}
	getProfile := func() profileResult {
		r, err := client.Get(server.URL + "/api/v1/auth/profile")
		require.NoError(t, err)
		defer func() { _ = r.Body.Close() }()
		require.Equal(t, http.StatusOK, r.StatusCode)
		var out struct {
			Data profileResult `json:"data"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&out))
		return out.Data
	}
	getProfileUsername := func() string { return getProfile().Username }
	initialProfile := getProfile()
	require.Equal(t, "testadmin", initialProfile.Username)
	require.Nil(t, initialProfile.Impersonation, "not impersonating yet — the field must be absent")

	startBody, _ := json.Marshal(map[string]uint{"user_id": targetUser.ID})
	startReq, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/admin/impersonate", bytes.NewReader(startBody))
	require.NoError(t, err)
	startReq.Header.Set("Content-Type", "application/json")
	startReq.Header.Set("X-CSRF-Token", csrfCookieValue(t, client, server.URL))
	startResp, err := client.Do(startReq)
	require.NoError(t, err)
	defer func() { _ = startResp.Body.Close() }()
	require.Equal(t, http.StatusOK, startResp.StatusCode)

	impersonationCookie := adminSessionCookie()
	require.NotEmpty(t, impersonationCookie)
	assert.NotEqual(t, originalAdminCookie, impersonationCookie, "the cookie must swap to the impersonation session")
	impersonatingProfile := getProfile()
	assert.Equal(t, "target", impersonatingProfile.Username, "requests now act as the impersonated user")
	require.NotNil(t, impersonatingProfile.Impersonation, "the client derives the banner from this, not local state")
	assert.Equal(t, "testadmin", impersonatingProfile.Impersonation.AdminUsername)

	endReq, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/auth/end-impersonation", nil)
	require.NoError(t, err)
	endReq.Header.Set("X-CSRF-Token", csrfCookieValue(t, client, server.URL))
	endResp, err := client.Do(endReq)
	require.NoError(t, err)
	defer func() { _ = endResp.Body.Close() }()
	require.Equal(t, http.StatusOK, endResp.StatusCode)

	var endBody struct {
		Data struct {
			AdminSessionRestored bool `json:"admin_session_restored"`
		} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(endResp.Body).Decode(&endBody))
	assert.True(t, endBody.Data.AdminSessionRestored)

	restoredCookie := adminSessionCookie()
	assert.Equal(t, originalAdminCookie, restoredCookie, "must restore the SAME original session, not a fresh one")
	assert.Equal(t, "testadmin", getProfileUsername(), "admin's own identity and permissions are back with no re-login")
}

// TestImpersonation_BreakGlassBlocked is the #G07 regression for the HTTP half
// of the ActivateBreakGlass gap: activation mints a durable, time-bound role
// grant attributed to whoever the session currently acts as — during
// impersonation that's the TARGET, not the admin — so it must be blocked the
// same way IssueMachineToken already is (POST /projects/{id}/machine-identities/{id}/tokens).
// Before this fix the route carried no BlockWhenImpersonating guard at all.
func TestImpersonation_BreakGlassBlocked(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	cfg := &config.Config{Server: config.ServerConfig{HTTP: config.ServerInstanceConfig{Enabled: true, Port: "8080"}}}
	testCore := newTestCore(t)
	_ = createTestToken(t, testCore) // seeds testadmin (admin role) /TestPassword123!

	ctx := context.Background()
	targetUser, err := testCore.CreateUser(ctx, &core.CreateUserRequest{
		Username: "bg-target", Email: "bg-target@example.com", Password: "CorrectHorseBattery9!",
	})
	require.NoError(t, err)
	project, err := testCore.CreateProject(ctx, "bg-project", "")
	require.NoError(t, err)

	router, err := NewRouter(cfg, testCore)
	require.NoError(t, err)
	server := httptest.NewServer(router)
	defer server.Close()

	client := newCookieClient(t)
	loginResp := loginViaHTTP(t, client, server.URL, "testadmin", "TestPassword123!")
	_ = loginResp.Body.Close()
	require.Equal(t, http.StatusOK, loginResp.StatusCode)

	startBody, _ := json.Marshal(map[string]uint{"user_id": targetUser.ID})
	startReq, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/admin/impersonate", bytes.NewReader(startBody))
	require.NoError(t, err)
	startReq.Header.Set("Content-Type", "application/json")
	startReq.Header.Set("X-CSRF-Token", csrfCookieValue(t, client, server.URL))
	startResp, err := client.Do(startReq)
	require.NoError(t, err)
	defer func() { _ = startResp.Body.Close() }()
	require.Equal(t, http.StatusOK, startResp.StatusCode)

	bgBody, _ := json.Marshal(map[string]string{"justification": "incident response"})
	bgReq, err := http.NewRequest(http.MethodPost,
		fmt.Sprintf("%s/api/v1/projects/%d/break-glass", server.URL, project.ID), bytes.NewReader(bgBody))
	require.NoError(t, err)
	bgReq.Header.Set("Content-Type", "application/json")
	bgReq.Header.Set("X-CSRF-Token", csrfCookieValue(t, client, server.URL))
	bgResp, err := client.Do(bgReq)
	require.NoError(t, err)
	defer func() { _ = bgResp.Body.Close() }()
	require.Equal(t, http.StatusForbidden, bgResp.StatusCode,
		"break-glass activation must be refused while impersonating, minting no grant attributed to the target")
	// Break-glass is disabled by default in this test's config too, which ALSO
	// returns 403 (a permission-denied from ActivateBreakGlass itself) — assert
	// on the specific message so this test can't pass for that unrelated reason
	// instead of the BlockWhenImpersonating guard actually under test.
	var bgErrBody struct {
		Message string `json:"message"`
	}
	require.NoError(t, json.NewDecoder(bgResp.Body).Decode(&bgErrBody))
	assert.Contains(t, bgErrBody.Message, "not permitted while impersonating")
}
