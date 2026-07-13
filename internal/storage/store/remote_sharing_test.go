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

func testShareRecord(id, secretID, ownerID, recipientID uint) *models.ShareRecord {
	return &models.ShareRecord{
		ID:          id,
		SecretID:    secretID,
		OwnerID:     ownerID,
		RecipientID: recipientID,
		Permission:  "read",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
}

// shareRecordData returns a minimal ShareRecord wire payload. ShareRecord has no
// json tags so the encoding/json default (PascalCase) field names are used.
func shareRecordData(id, secretID, ownerID, recipientID uint) map[string]interface{} {
	return map[string]interface{}{
		"ID":          id,
		"SecretID":    secretID,
		"OwnerID":     ownerID,
		"RecipientID": recipientID,
		"Permission":  "read",
		"CreatedAt":   time.Now().UTC().Format(time.RFC3339),
		"UpdatedAt":   time.Now().UTC().Format(time.RFC3339),
	}
}

// --- CreateShareRecord ---

func TestRemoteStorage_CreateShareRecord(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/shares", r.URL.Path)
		_, _ = w.Write(apiOK(shareRecordData(1, 10, 2, 3)))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	result, err := rs.CreateShareRecord(context.Background(), testShareRecord(0, 10, 2, 3))
	require.NoError(t, err)
	assert.Equal(t, uint(1), result.ID)
	assert.Equal(t, uint(10), result.SecretID)
	assert.Equal(t, uint(3), result.RecipientID)
}

// --- GetShareRecord ---

func TestRemoteStorage_GetShareRecord(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/shares/1", r.URL.Path)
		_, _ = w.Write(apiOK(shareRecordData(1, 10, 2, 3)))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	result, err := rs.GetShareRecord(context.Background(), 1)
	require.NoError(t, err)
	assert.Equal(t, uint(1), result.ID)
	assert.Equal(t, uint(10), result.SecretID)
}

// --- UpdateShareRecord ---

func TestRemoteStorage_UpdateShareRecord(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPut, r.Method)
		assert.Equal(t, "/api/v1/shares/1", r.URL.Path)
		_, _ = w.Write(apiOK(shareRecordData(1, 10, 2, 3)))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	result, err := rs.UpdateShareRecord(context.Background(), testShareRecord(1, 10, 2, 3))
	require.NoError(t, err)
	assert.Equal(t, uint(1), result.ID)
}

// --- DeleteShareRecord ---

func TestRemoteStorage_DeleteShareRecord(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodDelete, r.Method)
		assert.Equal(t, "/api/v1/shares/1", r.URL.Path)
		_, _ = w.Write(apiOK(nil))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.DeleteShareRecord(context.Background(), 1)
	require.NoError(t, err)
}

// --- ListSharesBySecret ---

func TestRemoteStorage_ListSharesBySecret(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/secrets/10/shares", r.URL.Path)
		_, _ = w.Write(apiOK([]map[string]interface{}{
			shareRecordData(1, 10, 2, 3),
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	results, err := rs.ListSharesBySecret(context.Background(), 10)
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, uint(1), results[0].ID)
}

// --- ListSharesBySecretIDs ---

func TestRemoteStorage_ListSharesBySecretIDs(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		assert.Equal(t, http.MethodGet, r.Method)
		_, _ = w.Write(apiOK([]map[string]interface{}{
			shareRecordData(uint(callCount), uint(callCount*10), 2, 3),
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	results, err := rs.ListSharesBySecretIDs(context.Background(), []uint{10, 20})
	require.NoError(t, err)
	assert.Len(t, results, 2)
	assert.Equal(t, 2, callCount)
}

func TestRemoteStorage_ListSharesBySecretIDs_Empty(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://127.0.0.1:0"))
	require.NoError(t, err)

	results, err := rs.ListSharesBySecretIDs(context.Background(), nil)
	require.NoError(t, err)
	assert.Nil(t, results)
}

// --- ListSharesByUser ---

func TestRemoteStorage_ListSharesByUser(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/system/shares/by-user/3", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"shares": []map[string]interface{}{
				shareRecordData(1, 10, 2, 3),
			},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	results, err := rs.ListSharesByUser(context.Background(), 3)
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, uint(3), results[0].RecipientID)
}

// --- ListSharesByOwner ---

func TestRemoteStorage_ListSharesByOwner(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/system/shares/by-owner/2", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"shares": []map[string]interface{}{
				shareRecordData(1, 10, 2, 3),
			},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	results, err := rs.ListSharesByOwner(context.Background(), 2)
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, uint(2), results[0].OwnerID)
}

// --- ListSharesByGroup ---

func TestRemoteStorage_ListSharesByGroup(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/groups/5/shares", r.URL.Path)
		_, _ = w.Write(apiOK([]map[string]interface{}{
			shareRecordData(2, 10, 2, 5),
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	results, err := rs.ListSharesByGroup(context.Background(), 5)
	require.NoError(t, err)
	assert.Len(t, results, 1)
}

// --- ListSharedSecrets ---

func TestRemoteStorage_ListSharedSecrets(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/users/3/shared-secrets", r.URL.Path)
		_, _ = w.Write(apiOK([]map[string]interface{}{
			{"id": 10, "name": "db-password", "type": "password"},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	results, err := rs.ListSharedSecrets(context.Background(), 3)
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "db-password", results[0].Name)
}

// --- CheckSharePermission ---

func TestRemoteStorage_CheckSharePermission(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/secrets/10/permissions", r.URL.Path)
		assert.Equal(t, "3", r.URL.Query().Get("user_id"))
		_, _ = w.Write(apiOK(map[string]interface{}{
			"permission": "write",
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	perm, err := rs.CheckSharePermission(context.Background(), 10, 3)
	require.NoError(t, err)
	assert.Equal(t, "write", perm)
}

// --- DeleteExpiredShareRecords ---

func TestRemoteStorage_DeleteExpiredShareRecords(t *testing.T) {
	before := time.Now().UTC()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/system/retention/share-records/purge-expired", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"removed": []map[string]interface{}{
				shareRecordData(7, 10, 2, 3),
			},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	removed, err := rs.DeleteExpiredShareRecords(context.Background(), before)
	require.NoError(t, err)
	assert.Len(t, removed, 1)
	assert.Equal(t, uint(7), removed[0].ID)
}
