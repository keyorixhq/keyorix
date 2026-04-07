package http

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/local"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// newSharingTestCore creates a minimal *core.KeyorixCore for sharing tests.
func newSharingTestCore(t *testing.T) *core.KeyorixCore {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	return core.NewKeyorixCore(local.NewLocalStorage(db))
}

// TestSharingHTTPIntegration tests the complete HTTP API sharing workflow
func TestSharingHTTPIntegration(t *testing.T) {
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

	// Create router
	router, err := NewRouter(cfg, newSharingTestCore(t))
	require.NoError(t, err)

	// Create test server
	server := httptest.NewServer(router)
	defer server.Close()

	client := &http.Client{Timeout: 10 * time.Second}
	baseURL := server.URL

	t.Run("Complete Sharing Workflow via HTTP API", func(t *testing.T) {
		var secretID uint
		var shareID uint

		// Step 1: Create a secret to share
		t.Run("Create Secret", func(t *testing.T) {
			secretData := map[string]interface{}{
				"name":        "http-sharing-test-secret",
				"value":       "http-sharing-secret-value",
				"namespace":   "test",
				"zone":        "us-west-2",
				"environment": "integration",
				"type":        "password",
				"metadata": map[string]string{
					"test":  "http-sharing",
					"owner": "test-user",
				},
				"tags": []string{"http", "sharing", "integration"},
			}

			body, err := json.Marshal(secretData)
			require.NoError(t, err)

			req, err := http.NewRequest("POST", baseURL+"/api/v1/secrets", bytes.NewBuffer(body))
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer valid-token")
			req.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusCreated, resp.StatusCode)

			var response map[string]interface{}
			err = json.NewDecoder(resp.Body).Decode(&response)
			require.NoError(t, err)

			data := response["data"].(map[string]interface{})
			secretID = uint(data["id"].(float64))
		})

		// Step 2: Share the secret with another user
		t.Run("Share Secret", func(t *testing.T) {
			shareData := map[string]interface{}{
				"recipient_id": 2,
				"is_group":     false,
				"permission":   "read",
			}

			body, err := json.Marshal(shareData)
			require.NoError(t, err)

			req, err := http.NewRequest("POST", fmt.Sprintf("%s/api/v1/secrets/%d/share", baseURL, secretID), bytes.NewBuffer(body))
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer valid-token")
			req.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusCreated, resp.StatusCode)

			var response map[string]interface{}
			err = json.NewDecoder(resp.Body).Decode(&response)
			require.NoError(t, err)

			data := response["data"].(map[string]interface{})
			shareID = uint(data["id"].(float64))
			assert.Equal(t, float64(secretID), data["secret_id"])
			assert.Equal(t, float64(2), data["recipient_id"])
			assert.Equal(t, "read", data["permission"])
		})

		// Step 3: List shares for the secret
		t.Run("List Secret Shares", func(t *testing.T) {
			req, err := http.NewRequest("GET", fmt.Sprintf("%s/api/v1/secrets/%d/shares", baseURL, secretID), nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer valid-token")

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusOK, resp.StatusCode)

			var response map[string]interface{}
			err = json.NewDecoder(resp.Body).Decode(&response)
			require.NoError(t, err)

			data := response["data"].(map[string]interface{})
			shares := data["shares"].([]interface{})
			assert.Len(t, shares, 1)

			share := shares[0].(map[string]interface{})
			assert.Equal(t, float64(shareID), share["id"])
			assert.Equal(t, "read", share["permission"])
		})

		// Step 4: List shared secrets (from recipient's perspective)
		t.Run("List Shared Secrets", func(t *testing.T) {
			req, err := http.NewRequest("GET", baseURL+"/api/v1/shared-secrets", nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer recipient-token") // Different user token

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusOK, resp.StatusCode)

			var response map[string]interface{}
			err = json.NewDecoder(resp.Body).Decode(&response)
			require.NoError(t, err)

			data := response["data"].(map[string]interface{})
			secrets := data["secrets"].([]interface{})
			assert.Len(t, secrets, 1)

			secret := secrets[0].(map[string]interface{})
			assert.Equal(t, float64(secretID), secret["id"])
			assert.Equal(t, "http-sharing-test-secret", secret["name"])
		})

		// Step 5: Update share permission
		t.Run("Update Share Permission", func(t *testing.T) {
			updateData := map[string]interface{}{
				"permission": "write",
			}

			body, err := json.Marshal(updateData)
			require.NoError(t, err)

			req, err := http.NewRequest("PUT", fmt.Sprintf("%s/api/v1/shares/%d", baseURL, shareID), bytes.NewBuffer(body))
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer valid-token")
			req.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusOK, resp.StatusCode)

			var response map[string]interface{}
			err = json.NewDecoder(resp.Body).Decode(&response)
			require.NoError(t, err)

			data := response["data"].(map[string]interface{})
			assert.Equal(t, "write", data["permission"])
		})

		// Step 6: List all shares for current user
		t.Run("List User Shares", func(t *testing.T) {
			req, err := http.NewRequest("GET", baseURL+"/api/v1/shares", nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer valid-token")

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusOK, resp.StatusCode)

			var response map[string]interface{}
			err = json.NewDecoder(resp.Body).Decode(&response)
			require.NoError(t, err)

			data := response["data"].(map[string]interface{})
			shares := data["shares"].([]interface{})
			assert.GreaterOrEqual(t, len(shares), 1)

			// Find our share
			var foundShare map[string]interface{}
			for _, s := range shares {
				share := s.(map[string]interface{})
				if uint(share["id"].(float64)) == shareID {
					foundShare = share
					break
				}
			}
			require.NotNil(t, foundShare)
			assert.Equal(t, "write", foundShare["permission"])
		})

		// Step 7: Revoke the share
		t.Run("Revoke Share", func(t *testing.T) {
			req, err := http.NewRequest("DELETE", fmt.Sprintf("%s/api/v1/shares/%d", baseURL, shareID), nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer valid-token")

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusNoContent, resp.StatusCode)
		})

		// Step 8: Verify share is revoked
		t.Run("Verify Share Revoked", func(t *testing.T) {
			req, err := http.NewRequest("GET", fmt.Sprintf("%s/api/v1/secrets/%d/shares", baseURL, secretID), nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer valid-token")

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusOK, resp.StatusCode)

			var response map[string]interface{}
			err = json.NewDecoder(resp.Body).Decode(&response)
			require.NoError(t, err)

			data := response["data"].(map[string]interface{})
			shares := data["shares"].([]interface{})
			assert.Len(t, shares, 0)
		})

		// Step 9: Verify shared secrets list is empty for recipient
		t.Run("Verify Shared Secrets Empty", func(t *testing.T) {
			req, err := http.NewRequest("GET", baseURL+"/api/v1/shared-secrets", nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer recipient-token")

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusOK, resp.StatusCode)

			var response map[string]interface{}
			err = json.NewDecoder(resp.Body).Decode(&response)
			require.NoError(t, err)

			data := response["data"].(map[string]interface{})
			secrets := data["secrets"].([]interface{})
			assert.Len(t, secrets, 0)
		})

		// Clean up: Delete the secret
		t.Run("Cleanup Secret", func(t *testing.T) {
			req, err := http.NewRequest("DELETE", fmt.Sprintf("%s/api/v1/secrets/%d", baseURL, secretID), nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer valid-token")

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusNoContent, resp.StatusCode)
		})
	})

	t.Run("Group Sharing via HTTP API", func(t *testing.T) {
		var secretID uint
		var groupShareID uint

		// Step 1: Create a secret for group sharing
		t.Run("Create Secret for Group", func(t *testing.T) {
			secretData := map[string]interface{}{
				"name":      "group-sharing-test-secret",
				"value":     "group-sharing-secret-value",
				"namespace": "test",
				"type":      "password",
				"metadata": map[string]string{
					"test": "group-sharing",
				},
				"tags": []string{"group", "sharing", "test"},
			}

			body, err := json.Marshal(secretData)
			require.NoError(t, err)

			req, err := http.NewRequest("POST", baseURL+"/api/v1/secrets", bytes.NewBuffer(body))
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer valid-token")
			req.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusCreated, resp.StatusCode)

			var response map[string]interface{}
			err = json.NewDecoder(resp.Body).Decode(&response)
			require.NoError(t, err)

			data := response["data"].(map[string]interface{})
			secretID = uint(data["id"].(float64))
		})

		// Step 2: Share with a group
		t.Run("Share with Group", func(t *testing.T) {
			shareData := map[string]interface{}{
				"recipient_id": 1, // Group ID
				"is_group":     true,
				"permission":   "read",
			}

			body, err := json.Marshal(shareData)
			require.NoError(t, err)

			req, err := http.NewRequest("POST", fmt.Sprintf("%s/api/v1/secrets/%d/share", baseURL, secretID), bytes.NewBuffer(body))
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer valid-token")
			req.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusCreated, resp.StatusCode)

			var response map[string]interface{}
			err = json.NewDecoder(resp.Body).Decode(&response)
			require.NoError(t, err)

			data := response["data"].(map[string]interface{})
			groupShareID = uint(data["id"].(float64))
			assert.Equal(t, true, data["is_group"])
			assert.Equal(t, "read", data["permission"])
		})

		// Step 3: Update group permission
		t.Run("Update Group Permission", func(t *testing.T) {
			updateData := map[string]interface{}{
				"permission": "write",
			}

			body, err := json.Marshal(updateData)
			require.NoError(t, err)

			req, err := http.NewRequest("PUT", fmt.Sprintf("%s/api/v1/shares/%d", baseURL, groupShareID), bytes.NewBuffer(body))
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer valid-token")
			req.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusOK, resp.StatusCode)

			var response map[string]interface{}
			err = json.NewDecoder(resp.Body).Decode(&response)
			require.NoError(t, err)

			data := response["data"].(map[string]interface{})
			assert.Equal(t, "write", data["permission"])
		})

		// Step 4: Revoke group share
		t.Run("Revoke Group Share", func(t *testing.T) {
			req, err := http.NewRequest("DELETE", fmt.Sprintf("%s/api/v1/shares/%d", baseURL, groupShareID), nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer valid-token")

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusNoContent, resp.StatusCode)
		})

		// Clean up
		t.Run("Cleanup Group Secret", func(t *testing.T) {
			req, err := http.NewRequest("DELETE", fmt.Sprintf("%s/api/v1/secrets/%d", baseURL, secretID), nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer valid-token")

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusNoContent, resp.StatusCode)
		})
	})

	t.Run("Error Scenarios via HTTP API", func(t *testing.T) {
		// Test unauthorized access
		t.Run("Unauthorized Access", func(t *testing.T) {
			req, err := http.NewRequest("GET", baseURL+"/api/v1/shares", nil)
			require.NoError(t, err)
			// No authorization header

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		})

		// Test sharing non-existent secret
		t.Run("Share Non-existent Secret", func(t *testing.T) {
			shareData := map[string]interface{}{
				"recipient_id": 2,
				"permission":   "read",
			}

			body, err := json.Marshal(shareData)
			require.NoError(t, err)

			req, err := http.NewRequest("POST", baseURL+"/api/v1/secrets/99999/share", bytes.NewBuffer(body))
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer valid-token")
			req.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusNotFound, resp.StatusCode)
		})

		// Test invalid JSON
		t.Run("Invalid JSON", func(t *testing.T) {
			req, err := http.NewRequest("POST", baseURL+"/api/v1/secrets/1/share", bytes.NewBufferString("{invalid json}"))
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer valid-token")
			req.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		})

		// Test missing required fields
		t.Run("Missing Required Fields", func(t *testing.T) {
			shareData := map[string]interface{}{
				// Missing recipient_id and permission
				"is_group": false,
			}

			body, err := json.Marshal(shareData)
			require.NoError(t, err)

			req, err := http.NewRequest("POST", baseURL+"/api/v1/secrets/1/share", bytes.NewBuffer(body))
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer valid-token")
			req.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		})

		// Test invalid permission value
		t.Run("Invalid Permission", func(t *testing.T) {
			shareData := map[string]interface{}{
				"recipient_id": 2,
				"permission":   "invalid",
			}

			body, err := json.Marshal(shareData)
			require.NoError(t, err)

			req, err := http.NewRequest("POST", baseURL+"/api/v1/secrets/1/share", bytes.NewBuffer(body))
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer valid-token")
			req.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		})

		// Test updating non-existent share
		t.Run("Update Non-existent Share", func(t *testing.T) {
			updateData := map[string]interface{}{
				"permission": "write",
			}

			body, err := json.Marshal(updateData)
			require.NoError(t, err)

			req, err := http.NewRequest("PUT", baseURL+"/api/v1/shares/99999", bytes.NewBuffer(body))
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer valid-token")
			req.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusNotFound, resp.StatusCode)
		})

		// Test revoking non-existent share
		t.Run("Revoke Non-existent Share", func(t *testing.T) {
			req, err := http.NewRequest("DELETE", baseURL+"/api/v1/shares/99999", nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer valid-token")

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusNotFound, resp.StatusCode)
		})
	})

	t.Run("Permission Enforcement via HTTP API", func(t *testing.T) {
		var secretID uint
		var shareID uint

		// Step 1: Create a secret as owner
		t.Run("Create Secret as Owner", func(t *testing.T) {
			secretData := map[string]interface{}{
				"name":  "permission-test-secret",
				"value": "permission-test-value",
				"type":  "password",
			}

			body, err := json.Marshal(secretData)
			require.NoError(t, err)

			req, err := http.NewRequest("POST", baseURL+"/api/v1/secrets", bytes.NewBuffer(body))
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer owner-token")
			req.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusCreated, resp.StatusCode)

			var response map[string]interface{}
			err = json.NewDecoder(resp.Body).Decode(&response)
			require.NoError(t, err)

			data := response["data"].(map[string]interface{})
			secretID = uint(data["id"].(float64))
		})

		// Step 2: Share with read-only permission
		t.Run("Share with Read Permission", func(t *testing.T) {
			shareData := map[string]interface{}{
				"recipient_id": 2,
				"permission":   "read",
			}

			body, err := json.Marshal(shareData)
			require.NoError(t, err)

			req, err := http.NewRequest("POST", fmt.Sprintf("%s/api/v1/secrets/%d/share", baseURL, secretID), bytes.NewBuffer(body))
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer owner-token")
			req.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusCreated, resp.StatusCode)

			var response map[string]interface{}
			err = json.NewDecoder(resp.Body).Decode(&response)
			require.NoError(t, err)

			data := response["data"].(map[string]interface{})
			shareID = uint(data["id"].(float64))
		})

		// Step 3: Try to update share as recipient (should fail)
		t.Run("Recipient Cannot Update Share", func(t *testing.T) {
			updateData := map[string]interface{}{
				"permission": "write",
			}

			body, err := json.Marshal(updateData)
			require.NoError(t, err)

			req, err := http.NewRequest("PUT", fmt.Sprintf("%s/api/v1/shares/%d", baseURL, shareID), bytes.NewBuffer(body))
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer recipient-token")
			req.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		})

		// Step 4: Try to revoke share as recipient (should fail)
		t.Run("Recipient Cannot Revoke Share", func(t *testing.T) {
			req, err := http.NewRequest("DELETE", fmt.Sprintf("%s/api/v1/shares/%d", baseURL, shareID), nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer recipient-token")

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		})

		// Step 5: Owner can still manage the share
		t.Run("Owner Can Update Share", func(t *testing.T) {
			updateData := map[string]interface{}{
				"permission": "write",
			}

			body, err := json.Marshal(updateData)
			require.NoError(t, err)

			req, err := http.NewRequest("PUT", fmt.Sprintf("%s/api/v1/shares/%d", baseURL, shareID), bytes.NewBuffer(body))
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer owner-token")
			req.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusOK, resp.StatusCode)
		})

		// Clean up
		t.Run("Owner Can Revoke Share", func(t *testing.T) {
			req, err := http.NewRequest("DELETE", fmt.Sprintf("%s/api/v1/shares/%d", baseURL, shareID), nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer owner-token")

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusNoContent, resp.StatusCode)
		})

		t.Run("Cleanup Permission Secret", func(t *testing.T) {
			req, err := http.NewRequest("DELETE", fmt.Sprintf("%s/api/v1/secrets/%d", baseURL, secretID), nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer owner-token")

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusNoContent, resp.StatusCode)
		})
	})
}

// TestSharingHTTPConcurrency tests concurrent access to sharing endpoints
func TestSharingHTTPConcurrency(t *testing.T) {
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

	router, err := NewRouter(cfg, newSharingTestCore(t))
	require.NoError(t, err)

	server := httptest.NewServer(router)
	defer server.Close()

	t.Run("Concurrent Share Operations", func(t *testing.T) {
		const numGoroutines = 10
		const requestsPerGoroutine = 5

		results := make(chan int, numGoroutines*requestsPerGoroutine)

		// Create a secret first
		client := &http.Client{Timeout: 10 * time.Second}
		secretData := map[string]interface{}{
			"name":  "concurrent-test-secret",
			"value": "concurrent-test-value",
			"type":  "password",
		}

		body, err := json.Marshal(secretData)
		require.NoError(t, err)

		req, err := http.NewRequest("POST", server.URL+"/api/v1/secrets", bytes.NewBuffer(body))
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer valid-token")
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		var response map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&response)
		require.NoError(t, err)

		data := response["data"].(map[string]interface{})
		secretID := uint(data["id"].(float64))

		// Perform concurrent share operations
		for i := 0; i < numGoroutines; i++ {
			go func(goroutineID int) {
				client := &http.Client{Timeout: 10 * time.Second}
				for j := 0; j < requestsPerGoroutine; j++ {
					shareData := map[string]interface{}{
						"recipient_id": goroutineID*requestsPerGoroutine + j + 10, // Unique recipient IDs
						"permission":   "read",
					}

					body, err := json.Marshal(shareData)
					if err != nil {
						results <- 0
						continue
					}

					req, err := http.NewRequest("POST", fmt.Sprintf("%s/api/v1/secrets/%d/share", server.URL, secretID), bytes.NewBuffer(body))
					if err != nil {
						results <- 0
						continue
					}
					req.Header.Set("Authorization", "Bearer valid-token")
					req.Header.Set("Content-Type", "application/json")

					resp, err := client.Do(req)
					if err != nil {
						results <- 0
						continue
					}
					_ = resp.Body.Close()
					results <- resp.StatusCode
				}
			}(i)
		}

		// Collect results
		successCount := 0
		for i := 0; i < numGoroutines*requestsPerGoroutine; i++ {
			select {
			case code := <-results:
				if code == http.StatusCreated {
					successCount++
				}
			case <-time.After(10 * time.Second):
				t.Fatal("Timeout waiting for concurrent requests")
			}
		}

		// At least 80% success rate (some might fail due to conflicts)
		expectedMinSuccess := int(float64(numGoroutines*requestsPerGoroutine) * 0.8)
		assert.GreaterOrEqual(t, successCount, expectedMinSuccess)
	})
}
