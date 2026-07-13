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

// dynamicConfigWireData returns a minimal wire payload for a DynamicSecretConfig.
func dynamicConfigWireData(id uint, name string) map[string]interface{} {
	return map[string]interface{}{
		"id":                  id,
		"name":                name,
		"project_id":          uint(1),
		"environment_id":      uint(2),
		"backend_type":        "postgres",
		"creation_template":   "CREATE ROLE {{name}}",
		"default_ttl_seconds": 3600,
		"max_ttl_seconds":     86400,
		"max_active_leases":   10,
		"classification":      "confidential",
		"disabled":            false,
		"created_by":          "admin",
		"created_at":          time.Now().UTC().Format(time.RFC3339),
		"updated_at":          time.Now().UTC().Format(time.RFC3339),
	}
}

// dynamicLeaseWireData returns a minimal wire payload for a DynamicSecretLease.
func dynamicLeaseWireData(id uint, leaseID string, configID uint) map[string]interface{} {
	return map[string]interface{}{
		"id":             id,
		"config_id":      configID,
		"lease_id":       leaseID,
		"project_id":     uint(1),
		"environment_id": uint(2),
		"role_name":      "app_reader",
		"status":         "active",
		"revoke_reason":  "",
		"revoke_error":   "",
		"issued_at":      time.Now().UTC().Format(time.RFC3339),
		"expires_at":     time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	}
}

// --- CreateDynamicSecretConfig ---

func TestRemoteStorage_CreateDynamicSecretConfig(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/system/dynamic-secrets/configs", r.URL.Path)
		_, _ = w.Write(apiOK(dynamicConfigWireData(1, "pg-dynamic")))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	c := &models.DynamicSecretConfig{
		Name:          "pg-dynamic",
		ProjectID:     1,
		EnvironmentID: 2,
		BackendType:   "postgres",
		CreatedBy:     "admin",
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	result, err := rs.CreateDynamicSecretConfig(context.Background(), c)
	require.NoError(t, err)
	assert.Equal(t, uint(1), result.ID)
	assert.Equal(t, "pg-dynamic", result.Name)
	assert.Equal(t, "postgres", result.BackendType)
}

// --- GetDynamicSecretConfig ---

func TestRemoteStorage_GetDynamicSecretConfig(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/system/dynamic-secrets/configs/1", r.URL.Path)
		_, _ = w.Write(apiOK(dynamicConfigWireData(1, "pg-dynamic")))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	result, err := rs.GetDynamicSecretConfig(context.Background(), 1)
	require.NoError(t, err)
	assert.Equal(t, uint(1), result.ID)
	assert.Equal(t, "pg-dynamic", result.Name)
}

// --- ListDynamicSecretConfigs ---

func TestRemoteStorage_ListDynamicSecretConfigs_NoEnvironment(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/system/dynamic-secrets/configs", r.URL.Path)
		assert.Equal(t, "1", r.URL.Query().Get("project_id"))
		// environment_id=0 should not be added to the query
		assert.Empty(t, r.URL.Query().Get("environment_id"))
		_, _ = w.Write(apiOK(map[string]interface{}{
			"configs": []map[string]interface{}{
				dynamicConfigWireData(1, "pg-dynamic"),
				dynamicConfigWireData(2, "mysql-dynamic"),
			},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	results, err := rs.ListDynamicSecretConfigs(context.Background(), 1, 0)
	require.NoError(t, err)
	assert.Len(t, results, 2)
	assert.Equal(t, uint(1), results[0].ID)
	assert.Equal(t, "pg-dynamic", results[0].Name)
}

func TestRemoteStorage_ListDynamicSecretConfigs_WithEnvironment(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "1", r.URL.Query().Get("project_id"))
		assert.Equal(t, "2", r.URL.Query().Get("environment_id"))
		_, _ = w.Write(apiOK(map[string]interface{}{
			"configs": []map[string]interface{}{
				dynamicConfigWireData(1, "pg-dynamic"),
			},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	results, err := rs.ListDynamicSecretConfigs(context.Background(), 1, 2)
	require.NoError(t, err)
	assert.Len(t, results, 1)
}

// --- UpdateDynamicSecretConfig ---

func TestRemoteStorage_UpdateDynamicSecretConfig(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPut, r.Method)
		assert.Equal(t, "/api/v1/system/dynamic-secrets/configs/1", r.URL.Path)
		_, _ = w.Write(apiOK(nil))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	c := &models.DynamicSecretConfig{
		ID:            1,
		Name:          "pg-dynamic",
		ProjectID:     1,
		EnvironmentID: 2,
		BackendType:   "postgres",
		CreatedBy:     "admin",
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	err = rs.UpdateDynamicSecretConfig(context.Background(), c)
	require.NoError(t, err)
}

// --- CountDynamicSecretConfigsByClassification ---

func TestRemoteStorage_CountDynamicSecretConfigsByClassification(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/system/dynamic-secrets/configs/classification-counts", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"counts": map[string]interface{}{
				"confidential": 3,
				"public":       1,
			},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	counts, err := rs.CountDynamicSecretConfigsByClassification(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 3, counts["confidential"])
	assert.Equal(t, 1, counts["public"])
}

// --- CreateDynamicSecretLease ---

func TestRemoteStorage_CreateDynamicSecretLease(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/system/dynamic-secrets/leases", r.URL.Path)
		_, _ = w.Write(apiOK(dynamicLeaseWireData(1, "lease-abc", 1)))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	l := &models.DynamicSecretLease{
		ConfigID:      1,
		LeaseID:       "lease-abc",
		ProjectID:     1,
		EnvironmentID: 2,
		RoleName:      "app_reader",
		Status:        "active",
		IssuedAt:      time.Now(),
		ExpiresAt:     time.Now().Add(time.Hour),
	}
	result, err := rs.CreateDynamicSecretLease(context.Background(), l)
	require.NoError(t, err)
	assert.Equal(t, uint(1), result.ID)
	assert.Equal(t, "lease-abc", result.LeaseID)
	assert.Equal(t, "active", result.Status)
}

// --- GetDynamicSecretLease ---

func TestRemoteStorage_GetDynamicSecretLease(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/system/dynamic-secrets/leases/lease-abc", r.URL.Path)
		_, _ = w.Write(apiOK(dynamicLeaseWireData(1, "lease-abc", 1)))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	result, err := rs.GetDynamicSecretLease(context.Background(), "lease-abc")
	require.NoError(t, err)
	assert.Equal(t, uint(1), result.ID)
	assert.Equal(t, "lease-abc", result.LeaseID)
}

// --- ListDynamicSecretLeases ---

func TestRemoteStorage_ListDynamicSecretLeases(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/system/dynamic-secrets/leases", r.URL.Path)
		assert.Equal(t, "1", r.URL.Query().Get("config_id"))
		_, _ = w.Write(apiOK(map[string]interface{}{
			"leases": []map[string]interface{}{
				dynamicLeaseWireData(1, "lease-abc", 1),
				dynamicLeaseWireData(2, "lease-def", 1),
			},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	results, err := rs.ListDynamicSecretLeases(context.Background(), 1)
	require.NoError(t, err)
	assert.Len(t, results, 2)
	assert.Equal(t, "lease-abc", results[0].LeaseID)
}

// --- CountActiveLeases ---

func TestRemoteStorage_CountActiveLeases(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/system/dynamic-secrets/leases/active-count", r.URL.Path)
		assert.Equal(t, "1", r.URL.Query().Get("config_id"))
		_, _ = w.Write(apiOK(map[string]interface{}{
			"count": int64(3),
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	count, err := rs.CountActiveLeases(context.Background(), 1)
	require.NoError(t, err)
	assert.Equal(t, int64(3), count)
}

// --- UpdateDynamicSecretLease ---

func TestRemoteStorage_UpdateDynamicSecretLease(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPut, r.Method)
		assert.Equal(t, "/api/v1/system/dynamic-secrets/leases/lease-abc", r.URL.Path)
		_, _ = w.Write(apiOK(nil))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	l := &models.DynamicSecretLease{
		ID:            1,
		ConfigID:      1,
		LeaseID:       "lease-abc",
		ProjectID:     1,
		EnvironmentID: 2,
		RoleName:      "app_reader",
		Status:        "revoked",
		RevokeReason:  "expired",
		IssuedAt:      time.Now().Add(-2 * time.Hour),
		ExpiresAt:     time.Now().Add(-time.Hour),
	}
	err = rs.UpdateDynamicSecretLease(context.Background(), l)
	require.NoError(t, err)
}

// --- ListExpiredActiveLeases ---

func TestRemoteStorage_ListExpiredActiveLeases(t *testing.T) {
	before := time.Now().UTC()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/system/dynamic-secrets/leases/expired", r.URL.Path)
		assert.NotEmpty(t, r.URL.Query().Get("before"))
		_, _ = w.Write(apiOK(map[string]interface{}{
			"leases": []map[string]interface{}{
				dynamicLeaseWireData(1, "lease-old", 1),
			},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	results, err := rs.ListExpiredActiveLeases(context.Background(), before)
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "lease-old", results[0].LeaseID)
}
