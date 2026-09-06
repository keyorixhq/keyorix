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

	g, err := rs.GetActiveMFAStepUpGrant(context.Background(), 42, models.MFAStepUpPurposeRestrictedSecretRead, now)
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

	g, err := rs.GetActiveMFAStepUpGrant(context.Background(), 42, models.MFAStepUpPurposeRestrictedSecretRead, time.Now().UTC())
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

	g, err := rs.GetActiveMFAStepUpGrant(context.Background(), 42, models.MFAStepUpPurposeRestrictedSecretRead, time.Now().UTC())
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

	g, err := rs.GetActiveMFAStepUpGrant(context.Background(), 42, models.MFAStepUpPurposeRestrictedSecretRead, time.Now().UTC())
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

	g, err := rs.GetActiveMFAStepUpGrant(context.Background(), 42, models.MFAStepUpPurposeRestrictedSecretRead, time.Now().UTC())
	require.Error(t, err)
	assert.Nil(t, g)
}
