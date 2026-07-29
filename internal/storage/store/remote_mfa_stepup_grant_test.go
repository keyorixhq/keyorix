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

func TestRemoteStorage_CreateMFAStepUpGrant_Success(t *testing.T) {
	exp := time.Now().UTC().Add(15 * time.Minute)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/system/mfa/stepup-grants", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"id":         uint(7),
			"user_id":    uint(42),
			"expires_at": exp,
			"created_at": time.Now().UTC(),
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	grant := &models.MFAStepUpGrant{UserID: 42, ExpiresAt: exp}
	err = rs.CreateMFAStepUpGrant(context.Background(), grant)
	require.NoError(t, err)
	assert.Equal(t, uint(7), grant.ID)
	assert.Equal(t, uint(42), grant.UserID)
}

func TestRemoteStorage_CreateMFAStepUpGrant_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"success":false,"error":{"code":"STORAGE_ERROR","message":"db down"}}`))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.CreateMFAStepUpGrant(context.Background(), &models.MFAStepUpGrant{
		UserID:    42,
		ExpiresAt: time.Now().UTC().Add(15 * time.Minute),
	})
	require.Error(t, err)
}

func TestRemoteStorage_CreateMFAStepUpGrant_SuccessFalse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":false,"error":{"code":"CONFLICT","message":"already exists"}}`))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.CreateMFAStepUpGrant(context.Background(), &models.MFAStepUpGrant{
		UserID:    42,
		ExpiresAt: time.Now().UTC().Add(15 * time.Minute),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create MFA step-up grant failed")
}

func TestRemoteStorage_CreateMFAStepUpGrant_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"data":{bad json}}`))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.CreateMFAStepUpGrant(context.Background(), &models.MFAStepUpGrant{
		UserID:    42,
		ExpiresAt: time.Now().UTC().Add(15 * time.Minute),
	})
	require.Error(t, err)
}

func TestRemoteStorage_GetActiveMFAStepUpGrant_Success(t *testing.T) {
	now := time.Now().UTC()
	exp := now.Add(10 * time.Minute)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/system/mfa/stepup-grants/active", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"id":         uint(3),
			"user_id":    uint(42),
			"expires_at": exp,
			"created_at": now,
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	g, err := rs.GetActiveMFAStepUpGrant(context.Background(), 42, now)
	require.NoError(t, err)
	require.NotNil(t, g)
	assert.Equal(t, uint(3), g.ID)
	assert.Equal(t, uint(42), g.UserID)
}

func TestRemoteStorage_GetActiveMFAStepUpGrant_NullResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Server returns {"success":true,"data":null} — no active grant.
		_, _ = w.Write(apiOK(nil))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	g, err := rs.GetActiveMFAStepUpGrant(context.Background(), 42, time.Now().UTC())
	require.NoError(t, err)
	assert.Nil(t, g, "null data must decode as (nil, nil)")
}

func TestRemoteStorage_GetActiveMFAStepUpGrant_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"success":false,"error":{"code":"STORAGE_ERROR","message":"db down"}}`))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	g, err := rs.GetActiveMFAStepUpGrant(context.Background(), 42, time.Now().UTC())
	require.Error(t, err)
	assert.Nil(t, g)
}

func TestRemoteStorage_GetActiveMFAStepUpGrant_SuccessFalse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":false,"error":{"code":"STORAGE_ERROR","message":"db down"}}`))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	g, err := rs.GetActiveMFAStepUpGrant(context.Background(), 42, time.Now().UTC())
	require.Error(t, err)
	assert.Nil(t, g)
	assert.Contains(t, err.Error(), "get active MFA step-up grant failed")
}

func TestRemoteStorage_GetActiveMFAStepUpGrant_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"data":{bad json}}`))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	g, err := rs.GetActiveMFAStepUpGrant(context.Background(), 42, time.Now().UTC())
	require.Error(t, err)
	assert.Nil(t, g)
}

func TestRemoteStorage_DeleteMFAStepUpGrantsFor_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "DELETE", r.Method)
		assert.Equal(t, "/api/v1/system/mfa/stepup-grants/42", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]bool{"deleted": true}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.DeleteMFAStepUpGrantsFor(context.Background(), 42)
	require.NoError(t, err)
}

func TestRemoteStorage_DeleteMFAStepUpGrantsFor_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"success":false,"error":{"code":"STORAGE_ERROR","message":"db down"}}`))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.DeleteMFAStepUpGrantsFor(context.Background(), 42)
	require.Error(t, err)
}

func TestRemoteStorage_DeleteMFAStepUpGrantsFor_SuccessFalse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":false,"error":{"code":"NOT_FOUND","message":"not found"}}`))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.DeleteMFAStepUpGrantsFor(context.Background(), 42)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "delete MFA step-up grants failed")
}
