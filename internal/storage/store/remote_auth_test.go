package store_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// minimalSetupToken returns a minimal *models.SetupToken for use as a request input.
func minimalSetupToken() *models.SetupToken {
	return &models.SetupToken{
		TokenHash:    "sha256hashvalue",
		Purpose:      "account_setup",
		SubjectEmail: "user@example.com",
		State:        "active",
		ExpiresAt:    time.Now().UTC().Add(time.Hour),
		CreatedBy:    1,
		CreatedAt:    time.Now().UTC(),
	}
}

// setupTokenWireBody returns a JSON-compatible map matching setupTokenWire fields.
func setupTokenWireBody() map[string]interface{} {
	return map[string]interface{}{
		"id":              float64(10),
		"token_hash":      "sha256hashvalue",
		"purpose":         "account_setup",
		"subject_user_id": nil,
		"subject_email":   "user@example.com",
		"invitation_id":   nil,
		"state":           "active",
		"expires_at":      time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano),
		"created_by":      float64(1),
		"created_at":      time.Now().UTC().Format(time.RFC3339Nano),
		"consumed_at":     nil,
	}
}

// --- GetSession ---

func TestRemoteStorage_GetSession(t *testing.T) {
	const token = "abc123token"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/sessions/abc123token", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"ID":     42,
			"UserID": 7,
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	session, err := rs.GetSession(context.Background(), token)
	require.NoError(t, err)
	assert.Equal(t, uint(42), session.ID)
	assert.Equal(t, uint(7), session.UserID)
}

func TestRemoteStorage_GetSession_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   map[string]string{"code": "NOT_FOUND", "message": "session not found"},
		})
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetSession(context.Background(), "bad-token")
	assert.Error(t, err)
}

// --- DeleteSession ---

func TestRemoteStorage_DeleteSession(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodDelete, r.Method)
		assert.Equal(t, "/api/v1/sessions/5", r.URL.Path)
		_, _ = w.Write(apiOK(nil))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.DeleteSession(context.Background(), 5)
	require.NoError(t, err)
}

func TestRemoteStorage_DeleteSession_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   map[string]string{"code": "INTERNAL", "message": "server error"},
		})
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.DeleteSession(context.Background(), 99)
	assert.Error(t, err)
}

// --- CleanupExpiredSessions ---

func TestRemoteStorage_CleanupExpiredSessions(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/sessions/cleanup", r.URL.Path)
		_, _ = w.Write(apiOK(nil))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.CleanupExpiredSessions(context.Background())
	require.NoError(t, err)
}

// --- CreateSession (unsupported stub) ---

func TestRemoteStorage_CreateSession_Unsupported(t *testing.T) {
	// No HTTP server needed — CreateSession never makes a remote call.
	rs, err := store.NewRemoteStorage(testConfig("http://localhost:19999"))
	require.NoError(t, err)

	_, err = rs.CreateSession(context.Background(), &models.Session{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not supported")
}

// --- Session stubs (errUnsupportedRemote) ---

func TestRemoteStorage_SessionStubs_ReturnError(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://localhost:19999"))
	require.NoError(t, err)
	ctx := context.Background()

	_, err = rs.GetSessionByID(ctx, 1)
	assert.Error(t, err)

	_, err = rs.GetSessionAny(ctx, "tok")
	assert.Error(t, err)

	_, _, err = rs.RotateSession(ctx, 1, nil, time.Now())
	assert.Error(t, err)

	_, err = rs.ListSessionTokenHashesByFamily(ctx, "fam")
	assert.Error(t, err)

	err = rs.DeleteSessionsByFamily(ctx, "fam")
	assert.Error(t, err)

	_, err = rs.ListSessionsByUser(ctx, 1)
	assert.Error(t, err)

	err = rs.DeleteSessionsForUserExcept(ctx, 1, 2)
	assert.Error(t, err)

	_, err = rs.ListSessionTokenHashesForUser(ctx, 1)
	assert.Error(t, err)

	err = rs.EnforceSessionLimit(ctx, 1, 5)
	assert.Error(t, err)
}

// --- TouchSession (no-op) ---

func TestRemoteStorage_TouchSession_NoError(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://localhost:19999"))
	require.NoError(t, err)

	err = rs.TouchSession(context.Background(), 1, time.Now(), time.Minute)
	require.NoError(t, err)
}

// --- PAT stubs (errUnsupportedRemote) ---

func TestRemoteStorage_PATStubs_ReturnError(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://localhost:19999"))
	require.NoError(t, err)
	ctx := context.Background()

	_, err = rs.CreatePersonalAccessToken(ctx, nil)
	assert.Error(t, err)

	_, err = rs.ListPersonalAccessTokensByUser(ctx, 1)
	assert.Error(t, err)

	_, err = rs.ListActivePersonalAccessTokens(ctx)
	assert.Error(t, err)

	_, err = rs.GetPersonalAccessTokenByID(ctx, 1)
	assert.Error(t, err)

	_, err = rs.GetPersonalAccessTokenByHash(ctx, "hash")
	assert.Error(t, err)

	err = rs.RevokePersonalAccessToken(ctx, 1)
	assert.Error(t, err)

	_, err = rs.RevokeAllPersonalAccessTokensForUser(ctx, 1)
	assert.Error(t, err)
}

// --- TouchPersonalAccessToken (no-op) ---

func TestRemoteStorage_TouchPersonalAccessToken_NoError(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://localhost:19999"))
	require.NoError(t, err)

	err = rs.TouchPersonalAccessToken(context.Background(), 1, time.Now(), time.Hour)
	require.NoError(t, err)
}

// --- Setup Tokens ---

func TestRemoteStorage_CreateSetupToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/system/setup-tokens", r.URL.Path)
		_, _ = w.Write(apiOK(setupTokenWireBody()))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	tok, err := rs.CreateSetupToken(context.Background(), minimalSetupToken())
	require.NoError(t, err)
	assert.Equal(t, "account_setup", tok.Purpose)
	assert.Equal(t, "active", tok.State)
	assert.Equal(t, "user@example.com", tok.SubjectEmail)
}

func TestRemoteStorage_CreateSetupToken_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   map[string]string{"code": "INVALID", "message": "bad request"},
		})
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.CreateSetupToken(context.Background(), minimalSetupToken())
	assert.Error(t, err)
}

func TestRemoteStorage_GetSetupTokenByHash(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/system/setup-tokens/by-hash/deadbeef", r.URL.Path)
		_, _ = w.Write(apiOK(setupTokenWireBody()))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	tok, err := rs.GetSetupTokenByHash(context.Background(), "deadbeef")
	require.NoError(t, err)
	assert.Equal(t, "account_setup", tok.Purpose)
	assert.Equal(t, "user@example.com", tok.SubjectEmail)
}

func TestRemoteStorage_GetSetupTokenByHash_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   map[string]string{"code": "NOT_FOUND", "message": "not found"},
		})
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetSetupTokenByHash(context.Background(), "missing")
	assert.Error(t, err)
}

func TestRemoteStorage_SupersedeActiveSetupTokens(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/system/setup-tokens/supersede", r.URL.Path)
		_, _ = w.Write(apiOK(nil))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.SupersedeActiveSetupTokens(context.Background(), "account_setup", "user@example.com")
	require.NoError(t, err)
}

func TestRemoteStorage_SupersedeActiveSetupTokens_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   map[string]string{"code": "INTERNAL", "message": "server error"},
		})
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.SupersedeActiveSetupTokens(context.Background(), "account_setup", "user@example.com")
	assert.Error(t, err)
}

func TestRemoteStorage_MarkSetupTokenConsumed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/system/setup-tokens/10/consume", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"consumed": true,
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	consumed, err := rs.MarkSetupTokenConsumed(context.Background(), 10, time.Now())
	require.NoError(t, err)
	assert.True(t, consumed)
}

func TestRemoteStorage_MarkSetupTokenConsumed_NotConsumed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiOK(map[string]interface{}{
			"consumed": false,
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	consumed, err := rs.MarkSetupTokenConsumed(context.Background(), 10, time.Now())
	require.NoError(t, err)
	assert.False(t, consumed)
}

func TestRemoteStorage_MarkSetupTokenConsumed_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   map[string]string{"code": "CONFLICT", "message": "already consumed"},
		})
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.MarkSetupTokenConsumed(context.Background(), 10, time.Now())
	assert.Error(t, err)
}

func TestRemoteStorage_MarkSetupTokenExpired(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/system/setup-tokens/10/expire", r.URL.Path)
		_, _ = w.Write(apiOK(nil))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.MarkSetupTokenExpired(context.Background(), 10)
	require.NoError(t, err)
}

func TestRemoteStorage_MarkSetupTokenExpired_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   map[string]string{"code": "NOT_FOUND", "message": "token not found"},
		})
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.MarkSetupTokenExpired(context.Background(), 10)
	assert.Error(t, err)
}

func TestRemoteStorage_CountSetupTokensSince(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/system/setup-tokens/count", r.URL.Path)
		assert.Equal(t, "account_setup", r.URL.Query().Get("purpose"))
		assert.Equal(t, "user@example.com", r.URL.Query().Get("subject_email"))
		_, _ = w.Write(apiOK(map[string]interface{}{
			"count": float64(3),
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	count, err := rs.CountSetupTokensSince(context.Background(), "account_setup", "user@example.com", time.Now().Add(-24*time.Hour))
	require.NoError(t, err)
	assert.Equal(t, int64(3), count)
}

func TestRemoteStorage_CountSetupTokensSince_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   map[string]string{"code": "INTERNAL", "message": "server error"},
		})
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.CountSetupTokensSince(context.Background(), "account_setup", "user@example.com", time.Now())
	assert.Error(t, err)
}
